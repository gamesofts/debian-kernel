#!/usr/bin/env bash
set -euo pipefail

log()  { echo -e "[+] $*" >&2; }
warn() { echo -e "[!] $*" >&2; }
die()  { echo -e "[x] $*" >&2; exit 1; }

require_bash() { [[ -n "${BASH_VERSION:-}" ]] || die "Run with bash, not sh. Example: sudo bash $0"; }
require_root() { [[ ${EUID:-$(id -u)} -eq 0 ]] || die "Please run as root."; }
require_amd64() { [[ "$(dpkg --print-architecture)" == "amd64" ]] || die "Only amd64 is supported."; }

mk_backup_dir() {
  local dir="/root/apt-backups/$(date +%F-%H%M%S)"
  mkdir -p "$dir"
  echo "$dir"
}

write_experimental_source() {
  cat > /etc/apt/sources.list.d/experimental.list <<'EOF'
deb https://deb.debian.org/debian experimental main contrib non-free non-free-firmware
EOF
  log "Wrote /etc/apt/sources.list.d/experimental.list"
}

write_kernel_only_experimental_pinning() {
  install -d /etc/apt/preferences.d
  cat > /etc/apt/preferences.d/99-kernel-only-experimental <<'EOF'
Package: *
Pin: release a=experimental
Pin-Priority: 1

Package: linux-image* linux-headers* linux-modules* linux-kbuild* linux-config* linux-base* linux-support*
Pin: release a=experimental
Pin-Priority: 990
EOF
  log "Wrote pinning: only kernel-related packages allowed from experimental."
}

apt_update() {
  log "apt-get update..."
  apt-get update -y
}

# Returns "<pkg>|<ver>" for the newest experimental versioned cloud kernel image:
# linux-image-<something>-cloud-amd64
find_latest_experimental_cloud_image() {
  local best_pkg="" best_ver=""

  mapfile -t pkgs < <(
    apt-cache pkgnames 2>/dev/null \
      | grep -E '^linux-image-[0-9].*-cloud-amd64$' \
      | grep -v -- '-unsigned$' \
      | sort -u
  )

  for p in "${pkgs[@]}"; do
    local v
    v="$(apt-cache madison "$p" 2>/dev/null \
        | awk -F'|' '$3 ~ /experimental/ {gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2; exit}')"
    [[ -n "$v" ]] || continue

    if [[ -z "$best_ver" ]] || dpkg --compare-versions "$v" gt "$best_ver"; then
      best_pkg="$p"
      best_ver="$v"
    fi
  done

  [[ -n "$best_pkg" && -n "$best_ver" ]] || return 1
  echo "$best_pkg|$best_ver"
}

install_latest_experimental_kernel() {
  local pkg="$1" ver="$2"
  export DEBIAN_FRONTEND=noninteractive

  log "Installing newest experimental cloud kernel: $pkg=$ver"
  apt-get install -y -t experimental "$pkg=$ver" initramfs-tools

  # Best-effort matching headers
  local kver="${pkg#linux-image-}" # e.g. 6.18-cloud-amd64 or 6.17.13+deb13-cloud-amd64
  if apt-cache show "linux-headers-$kver" >/dev/null 2>&1; then
    log "Installing matching headers: linux-headers-$kver"
    apt-get install -y -t experimental "linux-headers-$kver" || true
  else
    warn "Matching headers linux-headers-$kver not found; skipping."
  fi
}

ensure_initrd_exists() {
  local ver="$1"
  [[ -f "/boot/vmlinuz-$ver" ]] || die "Missing /boot/vmlinuz-$ver"
  if [[ ! -f "/boot/initrd.img-$ver" ]]; then
    log "initrd not found for $ver, generating..."
    update-initramfs -c -k "$ver"
  fi
  [[ -f "/boot/initrd.img-$ver" ]] || die "Missing /boot/initrd.img-$ver"
}

update_grub_if_any() {
  if command -v update-grub >/dev/null 2>&1; then
    log "Running update-grub..."
    update-grub
  elif command -v grub-mkconfig >/dev/null 2>&1 && [[ -d /boot/grub ]]; then
    log "Running grub-mkconfig..."
    grub-mkconfig -o /boot/grub/grub.cfg
  else
    warn "No grub updater found; skipping bootloader update."
  fi
}

# Purge ALL other kernels based on /boot/vmlinuz-* (not only cloud),
# keep ONLY the kernel that owns /boot/vmlinuz-$keep_ver.
purge_other_kernels_keep_one() {
  local keep_ver="$1"
  export DEBIAN_FRONTEND=noninteractive

  local keep_img="/boot/vmlinuz-$keep_ver"
  [[ -f "$keep_img" ]] || die "Keep kernel file missing: $keep_img"

  local keep_pkg
  keep_pkg="$(dpkg -S "$keep_img" 2>/dev/null | head -n1 | cut -d: -f1 || true)"
  [[ -n "$keep_pkg" ]] || die "Cannot find owning package for $keep_img"

  log "Keeping ONLY kernel image package: $keep_pkg ($keep_ver)"

  # Remove meta packages that might reinstall older kernels
  log "Purging meta packages (best-effort) to avoid pinning old kernels..."
  apt-get purge -y linux-image-cloud-amd64 linux-headers-cloud-amd64 linux-image-amd64 linux-headers-amd64 2>/dev/null || true

  # Enumerate all /boot/vmlinuz-* (real installed kernels)
  mapfile -t vmlinuz_files < <(ls -1 /boot/vmlinuz-* 2>/dev/null | sort -V || true)

  pkgs_to_purge=()
  hdrs_to_purge=()

  for f in "${vmlinuz_files[@]}"; do
    [[ "$f" == "$keep_img" ]] && continue

    # Purge owning linux-image package if exists
    owner="$(dpkg -S "$f" 2>/dev/null | head -n1 | cut -d: -f1 || true)"
    if [[ -n "$owner" && "$owner" != "$keep_pkg" ]]; then
      pkgs_to_purge+=("$owner")
    fi

    # Also try purge matching headers by version (file name after vmlinuz-)
    ver="${f#/boot/vmlinuz-}"
    hdrs_to_purge+=("linux-headers-$ver" "linux-headers-$ver-common")
  done

  # Dedupe and filter installed packages
  mapfile -t pkgs_to_purge < <(printf "%s\n" "${pkgs_to_purge[@]}" | sort -u)
  mapfile -t hdrs_to_purge < <(printf "%s\n" "${hdrs_to_purge[@]}" | sort -u)

  final_purge=()
  for p in "${pkgs_to_purge[@]}" "${hdrs_to_purge[@]}"; do
    dpkg-query -W -f='${db:Status-Status}\n' "$p" 2>/dev/null | grep -qx installed || continue
    [[ "$p" == "$keep_pkg" ]] && continue
    final_purge+=("$p")
  done
  mapfile -t final_purge < <(printf "%s\n" "${final_purge[@]}" | sort -u)

  if ((${#final_purge[@]} > 0)); then
    log "Purging old kernel packages:"
    printf "  - %s\n" "${final_purge[@]}" >&2
    apt-get purge -y "${final_purge[@]}"
  else
    log "No old kernel packages to purge (maybe only orphan boot files)."
  fi

  apt-get autoremove --purge -y

  # Remove orphan boot files that have no dpkg owner (except keep)
  for f in "${vmlinuz_files[@]}"; do
    [[ "$f" == "$keep_img" ]] && continue
    if ! dpkg -S "$f" >/dev/null 2>&1; then
      ver="${f#/boot/vmlinuz-}"
      log "Removing orphan boot files for $ver"
      rm -f "/boot/vmlinuz-$ver" "/boot/initrd.img-$ver" "/boot/System.map-$ver" "/boot/config-$ver"
    fi
  done

  update_grub_if_any
}

enable_bbr_fq() {
  log "Enabling BBR + FQ..."
  cat > /etc/sysctl.d/99-sysctl.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  cat > /etc/modules-load.d/bbr.conf <<'EOF'
tcp_bbr
EOF

  modprobe tcp_bbr 2>/dev/null || true
  sysctl --system >/dev/null

  log "Now: cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown), qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
}

main() {
  require_bash
  require_root
  require_amd64

  write_experimental_source
  write_kernel_only_experimental_pinning
  apt_update

  out="$(find_latest_experimental_cloud_image)" || die "Cannot find any versioned cloud kernel in experimental."
  IFS='|' read -r pkg ver <<<"$out"
  log "Selected newest experimental cloud kernel: $pkg ($ver)"

  install_latest_experimental_kernel "$pkg" "$ver"

  keep_ver="${pkg#linux-image-}"
  [[ -f "/boot/vmlinuz-$keep_ver" ]] || keep_ver="$(ls -1 /boot/vmlinuz-*-cloud-amd64 2>/dev/null | sed 's#.*/vmlinuz-##' | sort -V | tail -n 1)"
  log "Keeping kernel version: $keep_ver"

  ensure_initrd_exists "$keep_ver"

  # Per your requirement: once files exist, purge immediately; keep only one kernel
  purge_other_kernels_keep_one "$keep_ver"

  enable_bbr_fq

  warn "Current running kernel: $(uname -r)"
  warn "Reboot ASAP to validate you can boot with the kept kernel (no fallback kept):"
  echo "reboot"
}

main "$@"
