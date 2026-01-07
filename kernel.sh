#!/usr/bin/env bash
set -euo pipefail

log()  { echo -e "[+] $*" >&2; }
warn() { echo -e "[!] $*" >&2; }
die()  { echo -e "[x] $*" >&2; exit 1; }

[[ -n "${BASH_VERSION:-}" ]] || die "Run with bash, e.g. sudo bash $0"
[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"
[[ "$(dpkg --print-architecture)" == "amd64" ]] || die "Only amd64 supported"

# --- OS check (Debian >=12) ---
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == "debian" ]] || die "Only Debian supported"
dpkg --compare-versions "${VERSION_ID:-0}" ge "12" || die "Only Debian >= 12 supported (VERSION_ID=${VERSION_ID:-})"
CODENAME="${VERSION_CODENAME:-}"

backup_dir="/root/apt-backups/$(date +%F-%H%M%S)"
mkdir -p "$backup_dir"

# move invalid *.bak.* files out of sources.list.d to stop "invalid filename extension" warnings
shopt -s nullglob
for f in /etc/apt/sources.list.d/*.bak.*; do
  mv -f "$f" "${backup_dir}/"
  log "Moved invalid ext file out of sources.list.d: $f"
done
shopt -u nullglob

has_suite_in_sources() {
  local suite="$1"
  grep -RqsE "^[[:space:]]*deb[[:space:]].*[[:space:]]${suite}([[:space:]]|/)" \
    /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null
}

ensure_suite_source_exists() {
  local suite="$1" file="$2" line="$3"
  if has_suite_in_sources "$suite"; then
    log "$suite source already exists; not modifying existing sources."
    return 0
  fi
  printf "%s\n" "$line" > "$file"
  log "Wrote $file"
}

# --- add experimental + sid (kernel-only pinned) ---
ensure_suite_source_exists "experimental" "/etc/apt/sources.list.d/experimental.list" \
  "deb https://deb.debian.org/debian experimental main contrib non-free non-free-firmware"
ensure_suite_source_exists "sid" "/etc/apt/sources.list.d/sid.list" \
  "deb https://deb.debian.org/debian sid main contrib non-free non-free-firmware"

install -d /etc/apt/preferences.d
cat > /etc/apt/preferences.d/99-kernel-only-exp-sid <<'EOF'
# Block experimental/sid by default
Package: *
Pin: release a=experimental
Pin-Priority: 1

Package: *
Pin: release a=sid
Pin-Priority: 1

# Allow ONLY kernel-related packages from experimental/sid
Package: linux-image* linux-headers* linux-modules* linux-kbuild* linux-config* linux-base* linux-support* linux-doc*
Pin: release a=experimental
Pin-Priority: 990

Package: linux-image* linux-headers* linux-modules* linux-kbuild* linux-config* linux-base* linux-support* linux-doc*
Pin: release a=sid
Pin-Priority: 950
EOF
log "Pinned: only kernel-related packages allowed from experimental/sid."

log "apt-get update..."
apt-get update -y

# Hard refresh lists once (helps when lists are partial)
log "Refreshing APT lists once (purge /var/lib/apt/lists/* then update)..."
rm -rf /var/lib/apt/lists/*
mkdir -p /var/lib/apt/lists/partial
apt-get update -y

# --- helpers to select newest installable cloud kernel ---
extract_suite_from_madison_line() {
  # line: pkg | ver | url suite/component arch Packages
  awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/, "", $3); print $3}' \
    | awk '{print $2}' \
    | awk -F'/' '{print $1}'
}
get_ver_in_suite() {
  local pkg="$1" suite="$2"
  apt-cache madison "$pkg" 2>/dev/null \
    | while IFS= read -r line; do
        [[ -n "$line" ]] || continue
        s="$(printf "%s\n" "$line" | extract_suite_from_madison_line)"
        [[ "$s" == "$suite" ]] || continue
        v="$(printf "%s\n" "$line" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}')"
        [[ -n "$v" ]] && { echo "$v"; break; }
      done
}

candidate_installable() {
  local suite="$1" pkg="$2" ver="$3"
  # dry-run must be solvable
  apt-get -s -t "$suite" install "$pkg=$ver" >/dev/null 2>&1
}

select_newest_installable_cloud_kernel() {
  local suites=("experimental" "sid" "${CODENAME}-backports" "${CODENAME}" "${CODENAME}-security")

  mapfile -t pkgnames < <(
    apt-cache pkgnames 2>/dev/null \
      | grep -E '^linux-image-[0-9].*-cloud-amd64$' \
      | grep -v -- '-unsigned$' \
      | grep -v -- '-dbg$' \
      | sort -u
  )

  local best_suite="" best_pkg="" best_ver=""
  for pkg in "${pkgnames[@]}"; do
    for suite in "${suites[@]}"; do
      ver="$(get_ver_in_suite "$pkg" "$suite" || true)"
      [[ -n "$ver" ]] || continue

      # If experimental is inconsistent, dry-run will fail -> auto skip
      if ! candidate_installable "$suite" "$pkg" "$ver"; then
        continue
      fi

      if [[ -z "$best_ver" ]] || dpkg --compare-versions "$ver" gt "$best_ver"; then
        best_ver="$ver"; best_pkg="$pkg"; best_suite="$suite"
      fi
    done
  done

  [[ -n "$best_pkg" ]] || return 1
  echo "$best_suite|$best_pkg|$best_ver"
}

sel="$(select_newest_installable_cloud_kernel || true)"
if [[ -z "${sel:-}" ]]; then
  warn "No installable cloud kernel found."
  warn "Tip: this often happens when experimental has broken dependencies."
  die "Abort."
fi

IFS='|' read -r suite pkg ver <<<"$sel"
log "Selected newest installable cloud kernel: $pkg ($ver) from $suite"

export DEBIAN_FRONTEND=noninteractive
log "Installing: $pkg=$ver"
apt-get install -y -t "$suite" "$pkg=$ver" initramfs-tools

keep_ver="${pkg#linux-image-}"
log "Kernel version to keep: $keep_ver"

[[ -f "/boot/vmlinuz-$keep_ver" ]] || die "Missing /boot/vmlinuz-$keep_ver"
if [[ ! -f "/boot/initrd.img-$keep_ver" ]]; then
  log "initrd not found for $keep_ver, generating..."
  update-initramfs -c -k "$keep_ver"
fi
[[ -f "/boot/initrd.img-$keep_ver" ]] || die "Missing /boot/initrd.img-$keep_ver"

# --- purge all other kernels (keep only ONE) ---
keep_img="/boot/vmlinuz-$keep_ver"
keep_pkg="$(dpkg -S "$keep_img" 2>/dev/null | head -n1 | cut -d: -f1 || true)"
[[ -n "$keep_pkg" ]] || die "Cannot find owning package for $keep_img"
apt-mark manual "$keep_pkg" >/dev/null 2>&1 || true
log "Keeping ONLY kernel image package: $keep_pkg ($keep_ver)"

if [[ "$(uname -r)" != "$keep_ver" ]]; then
  warn "Running kernel ($(uname -r)) != kept kernel ($keep_ver). You asked to purge immediately; reboot ASAP."
fi

# remove metas if present
apt-get purge -y linux-image-amd64 linux-headers-amd64 linux-image-cloud-amd64 linux-headers-cloud-amd64 2>/dev/null || true

mapfile -t vmlinuz_files < <(ls -1 /boot/vmlinuz-* 2>/dev/null | sort -V || true)

pkgs_to_purge=()
extra_to_purge=()

for f in "${vmlinuz_files[@]}"; do
  [[ "$f" == "$keep_img" ]] && continue
  ver2="${f#/boot/vmlinuz-}"

  owner="$(dpkg -S "$f" 2>/dev/null | head -n1 | cut -d: -f1 || true)"
  [[ -n "$owner" ]] && pkgs_to_purge+=("$owner")

  extra_to_purge+=(
    "linux-image-$ver2"
    "linux-modules-$ver2"
    "linux-modules-extra-$ver2"
    "linux-headers-$ver2"
    "linux-headers-$ver2-common"
  )
done

mapfile -t pkgs_to_purge  < <(printf "%s\n" "${pkgs_to_purge[@]}"  | sort -u)
mapfile -t extra_to_purge < <(printf "%s\n" "${extra_to_purge[@]}" | sort -u)

final_purge=()
for p in "${pkgs_to_purge[@]}" "${extra_to_purge[@]}"; do
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
  log "No old kernel packages to purge."
fi

apt-get autoremove --purge -y

# remove orphan /boot files (e.g. self-built kernel 6.10.10)
for f in "${vmlinuz_files[@]}"; do
  [[ "$f" == "$keep_img" ]] && continue
  if ! dpkg -S "$f" >/dev/null 2>&1; then
    ver3="${f#/boot/vmlinuz-}"
    log "Removing orphan boot files for $ver3"
    rm -f "/boot/vmlinuz-$ver3" "/boot/initrd.img-$ver3" "/boot/System.map-$ver3" "/boot/config-$ver3"
  fi
done

# update grub if exists
if command -v update-grub >/dev/null 2>&1; then
  log "Running update-grub..."
  update-grub
elif command -v grub-mkconfig >/dev/null 2>&1 && [[ -d /boot/grub ]]; then
  log "Running grub-mkconfig..."
  grub-mkconfig -o /boot/grub/grub.cfg
else
  warn "No grub updater found; skipping."
fi

# enable BBR + FQ
log "Enabling BBR + FQ..."
cat > /etc/sysctl.d/99-bbr-fq.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
cat > /etc/modules-load.d/bbr.conf <<'EOF'
tcp_bbr
EOF
modprobe tcp_bbr 2>/dev/null || true
sysctl --system >/dev/null

# clean up
apt-get autoremove --purge -y
apt-get clean
rm -rf /var/lib/apt/lists/*
mkdir -p /var/lib/apt/lists/partial

log "Now: cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown), qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"

warn "Current running kernel: $(uname -r)"
warn "Only one kernel is kept on disk now: /boot/vmlinuz-$keep_ver"
