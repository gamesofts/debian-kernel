#!/usr/bin/env bash
set -euo pipefail

# Debian >= 12, amd64 only
# Goal:
#   1) Upgrade to newest *installable* cloud kernel (prefer experimental, then sid, then backports/main/security)
#   2) If already newest, skip install
#   3) After kernel files exist, purge ALL other kernels (keep only one)
#   4) Enable BBR + FQ
#   5) Clean APT caches/lists to avoid disk growth

log()  { echo -e "[+] $*" >&2; }
warn() { echo -e "[!] $*" >&2; }
die()  { echo -e "[x] $*" >&2; exit 1; }

PIN_FILE="/etc/apt/preferences.d/99-kernel-only-exp-sid"
PIN_BAK=""
PIN_EXISTED=0
created_source_files=()

cleanup_apt_temp_state() {
  local f

  for f in "${created_source_files[@]:-}"; do
    [[ -n "${f:-}" && -f "$f" ]] || continue
    rm -f "$f" || true
    log "Removed temporary source file: $f"
  done

  if [[ "$PIN_EXISTED" -eq 1 ]]; then
    if [[ -n "$PIN_BAK" && -f "$PIN_BAK" ]]; then
      cp -f "$PIN_BAK" "$PIN_FILE" || true
      rm -f "$PIN_BAK" || true
      log "Restored original pin file: $PIN_FILE"
    fi
  else
    rm -f "$PIN_FILE" || true
    [[ -n "$PIN_BAK" && -f "$PIN_BAK" ]] && rm -f "$PIN_BAK" || true
    log "Removed temporary pin file: $PIN_FILE"
  fi
}

trap cleanup_apt_temp_state EXIT

# ----------------- prechecks -----------------
[[ -n "${BASH_VERSION:-}" ]] || die "Run with bash, e.g. sudo bash $0"
[[ ${EUID:-$(id -u)} -eq 0 ]] || die "Run as root"
[[ "$(dpkg --print-architecture)" == "amd64" ]] || die "Only amd64 supported"

# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == "debian" ]] || die "Only Debian supported"
dpkg --compare-versions "${VERSION_ID:-0}" ge "12" || die "Only Debian >= 12 supported (VERSION_ID=${VERSION_ID:-})"
CODENAME="${VERSION_CODENAME:-}"
[[ -n "$CODENAME" ]] || die "Cannot detect VERSION_CODENAME from /etc/os-release"

# ----------------- apt sources hygiene -----------------
# Remove invalid *.bak.* files in sources.list.d to avoid warnings
shopt -s nullglob
for f in /etc/apt/sources.list.d/*.bak.*; do
  rm -f "$f"
  log "Removed invalid ext file: $f"
done
shopt -u nullglob

has_suite_in_sources() {
  # Detect suite both in classic .list format and Deb822 .sources format
  local suite="$1"
  grep -RqsE "^[[:space:]]*deb[[:space:]].*[[:space:]]${suite}([[:space:]]|/)" \
    /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null && return 0

  grep -RqsE "^[[:space:]]*Suites:[[:space:]].*\b${suite}\b" \
    /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null && return 0

  return 1
}

ensure_suite_source_exists() {
  local suite="$1" file="$2" line="$3"
  if has_suite_in_sources "$suite"; then
    log "$suite source already exists; not modifying existing sources."
    return 0
  fi
  printf "%s\n" "$line" > "$file"
  created_source_files+=("$file")
  log "Wrote $file"
}

# Add experimental & sid sources ONLY if absent
ensure_suite_source_exists "experimental" "/etc/apt/sources.list.d/experimental.list" \
  "deb https://deb.debian.org/debian experimental main contrib non-free non-free-firmware"
ensure_suite_source_exists "sid" "/etc/apt/sources.list.d/sid.list" \
  "deb https://deb.debian.org/debian sid main contrib non-free non-free-firmware"

# Pin: only kernel-related packages are allowed from experimental/sid
install -d /etc/apt/preferences.d
if [[ -f "$PIN_FILE" ]]; then
  PIN_EXISTED=1
  PIN_BAK="$(mktemp /tmp/99-kernel-only-exp-sid.XXXXXX)"
  cp -f "$PIN_FILE" "$PIN_BAK"
fi
cat > "$PIN_FILE" <<'EOF'
Package: *
Pin: release a=experimental
Pin-Priority: 1

Package: *
Pin: release a=sid
Pin-Priority: 1

Package: linux-image* linux-headers* linux-modules* linux-kbuild* linux-config* linux-base* linux-support* linux-doc*
Pin: release a=experimental
Pin-Priority: 990

Package: linux-image* linux-headers* linux-modules* linux-kbuild* linux-config* linux-base* linux-support* linux-doc*
Pin: release a=sid
Pin-Priority: 950
EOF
log "Pinned: only kernel-related packages allowed from experimental/sid."

log "apt-get update..."
apt-get -o Acquire::PDiffs=false update

# ----------------- candidate selection -----------------
extract_suite_from_madison_line() {
  # line: pkg | ver | url suite/component arch Packages
  awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/, "", $3); print $3}' \
    | awk '{print $2}' \
    | awk -F'/' '{print $1}'
}

normalize_suite() {
  local suite="$1"
  [[ "$suite" == "unstable" ]] && suite="sid"
  echo "$suite"
}

is_allowed_suite() {
  local suite="$1"
  [[ "$suite" == "experimental" || "$suite" == "sid" || "$suite" == "${CODENAME}-backports" || "$suite" == "${CODENAME}-security" || "$suite" == "${CODENAME}-updates" || "$suite" == "${CODENAME}" ]]
}

suite_priority() {
  local suite="$1"
  case "$suite" in
    experimental) echo 0 ;;
    sid) echo 1 ;;
    "${CODENAME}-backports") echo 2 ;;
    "${CODENAME}-security") echo 3 ;;
    "${CODENAME}-updates") echo 4 ;;
    "${CODENAME}") echo 5 ;;
    *) echo 99 ;;
  esac
}

candidate_is_better() {
  local new_ver="$1" new_pri="$2" cur_ver="$3" cur_pri="$4"
  if [[ -z "$cur_ver" ]]; then
    return 0
  fi
  if dpkg --compare-versions "$new_ver" gt "$cur_ver"; then
    return 0
  fi
  if dpkg --compare-versions "$new_ver" eq "$cur_ver" && ((new_pri < cur_pri)); then
    return 0
  fi
  return 1
}

candidate_installable() {
  local suite="$1" pkg="$2" ver="$3"
  # Dry-run must be solvable; rejects broken experimental states
  apt-get -s -t "$suite" install --no-install-recommends "$pkg=$ver" initramfs-tools >/dev/null 2>&1
}

select_newest_installable_cloud_kernel() {
  local pkg line raw_suite suite ver pri
  local i
  local best_idx best_suite best_pkg best_ver best_pri
  mapfile -t pkgnames < <(
    apt-cache pkgnames 2>/dev/null \
      | grep -E '^linux-image-[0-9].*-cloud-amd64$' \
      | grep -v -- '-unsigned$' \
      | grep -v -- '-dbg$' \
      | sort -u
  )

  local candidates=()
  for pkg in "${pkgnames[@]}"; do
    while IFS= read -r line; do
      [[ -n "$line" ]] || continue
      raw_suite="$(printf "%s\n" "$line" | extract_suite_from_madison_line)"
      suite="$(normalize_suite "$raw_suite")"
      is_allowed_suite "$suite" || continue
      ver="$(printf "%s\n" "$line" | awk -F'|' '{gsub(/^[ \t]+|[ \t]+$/, "", $2); print $2}')"
      [[ -n "$ver" ]] || continue
      pri="$(suite_priority "$suite")"
      candidates+=("$suite|$pkg|$ver|$pri")
    done < <(apt-cache madison "$pkg" 2>/dev/null)
  done

  ((${#candidates[@]} > 0)) || return 1
  mapfile -t candidates < <(printf "%s\n" "${candidates[@]}" | sort -u)

  while ((${#candidates[@]} > 0)); do
    best_idx=-1
    best_suite=""
    best_pkg=""
    best_ver=""
    best_pri=999

    for i in "${!candidates[@]}"; do
      IFS='|' read -r suite pkg ver pri <<<"${candidates[$i]}"
      if candidate_is_better "$ver" "$pri" "$best_ver" "$best_pri"; then
        best_idx="$i"
        best_suite="$suite"
        best_pkg="$pkg"
        best_ver="$ver"
        best_pri="$pri"
      fi
    done

    [[ "$best_idx" -ge 0 ]] || break
    if candidate_installable "$best_suite" "$best_pkg" "$best_ver"; then
      echo "$best_suite|$best_pkg|$best_ver"
      return 0
    fi

    unset 'candidates[best_idx]'
    candidates=("${candidates[@]}")
  done

  return 1
}

# ----------------- early skip if already latest -----------------
is_pkg_installed_exact() {
  local pkg="$1" want_ver="$2"
  local status installed_ver
  status="$(dpkg-query -W -f='${db:Status-Status}\n' "$pkg" 2>/dev/null || true)"
  [[ "$status" == "installed" ]] || return 1
  installed_ver="$(dpkg-query -W -f='${Version}\n' "$pkg" 2>/dev/null || true)"
  [[ "$installed_ver" == "$want_ver" ]]
}

kernel_files_exist() {
  local kver="$1"
  [[ -f "/boot/vmlinuz-$kver" && -f "/boot/initrd.img-$kver" ]]
}

ensure_boot_space_for_upgrade() {
  local required_mb=350
  local required_kb=$((required_mb * 1024))
  local boot_avail_kb root_avail_kb

  boot_avail_kb="$(df -Pk /boot 2>/dev/null | awk 'NR==2{print $4}' || true)"
  if [[ -n "${boot_avail_kb:-}" && "$boot_avail_kb" =~ ^[0-9]+$ ]]; then
    ((boot_avail_kb >= required_kb)) || die "/boot free space too low: ${boot_avail_kb}KB (< ${required_kb}KB)."
    return 0
  fi

  root_avail_kb="$(df -Pk / 2>/dev/null | awk 'NR==2{print $4}' || true)"
  if [[ -n "${root_avail_kb:-}" && "$root_avail_kb" =~ ^[0-9]+$ ]]; then
    ((root_avail_kb >= required_kb)) || die "/ free space too low: ${root_avail_kb}KB (< ${required_kb}KB)."
    return 0
  fi

  die "Unable to detect available disk space for /boot or /."
}

confirm_upgrade() {
  local suite="$1" pkg="$2" ver="$3"
  if [[ -t 0 && -t 1 ]]; then
    read -r -p "Upgrade now? [y/N] " ans
    if [[ ! "$ans" =~ ^[Yy]$ ]]; then
      log "Upgrade canceled by user."
      exit 0
    fi
  else
    warn "No interactive TTY detected; defaulting to upgrade: $pkg ($ver) from $suite"
  fi
}

ensure_initrd_exists() {
  local kver="$1"
  [[ -f "/boot/vmlinuz-$kver" ]] || die "Missing /boot/vmlinuz-$kver"
  if [[ ! -f "/boot/initrd.img-$kver" ]]; then
    log "initrd not found for $kver, generating..."
    update-initramfs -c -k "$kver"
  fi
  [[ -f "/boot/initrd.img-$kver" ]] || die "Missing /boot/initrd.img-$kver"
}

# ----------------- install -----------------
install_selected_kernel() {
  local suite="$1" pkg="$2" ver="$3"
  export DEBIAN_FRONTEND=noninteractive

  log "Installing: $pkg=$ver from suite: $suite"
  # Keep it lean: do NOT install headers by default (saves disk).
  apt-get install -y -t "$suite" --no-install-recommends "$pkg=$ver" initramfs-tools
}

# ----------------- purge old kernels, keep only one -----------------
update_grub_if_any() {
  if command -v update-grub >/dev/null 2>&1; then
    log "Running update-grub..."
    update-grub
  elif command -v grub-mkconfig >/dev/null 2>&1 && [[ -d /boot/grub ]]; then
    log "Running grub-mkconfig..."
    grub-mkconfig -o /boot/grub/grub.cfg
  else
    warn "No grub updater found; skipping."
  fi
}

purge_other_kernels_keep_one() {
  local keep_ver="$1"
  export DEBIAN_FRONTEND=noninteractive

  local keep_img="/boot/vmlinuz-$keep_ver"
  [[ -f "$keep_img" ]] || die "Keep kernel file missing: $keep_img"

  local keep_pkg
  keep_pkg="$(dpkg -S "$keep_img" 2>/dev/null | head -n1 | cut -d: -f1 || true)"
  [[ -n "$keep_pkg" ]] || die "Cannot find owning package for $keep_img"

  apt-mark manual "$keep_pkg" >/dev/null 2>&1 || true
  log "Keeping ONLY kernel image package: $keep_pkg ($keep_ver)"

  if [[ "$(uname -r)" != "$keep_ver" ]]; then
    warn "Running kernel ($(uname -r)) != kept kernel ($keep_ver). You required immediate purge; reboot ASAP."
  fi

  # Remove metas that might reinstall other kernels (best-effort)
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

  # Remove orphan /boot files (e.g. self-built kernels)
  for f in "${vmlinuz_files[@]}"; do
    [[ "$f" == "$keep_img" ]] && continue
    if ! dpkg -S "$f" >/dev/null 2>&1; then
      ver3="${f#/boot/vmlinuz-}"
      log "Removing orphan boot files for $ver3"
      rm -f "/boot/vmlinuz-$ver3" "/boot/initrd.img-$ver3" "/boot/System.map-$ver3" "/boot/config-$ver3"
    fi
  done

  update_grub_if_any
}

# ----------------- enable bbr + fq -----------------
enable_bbr_fq() {
  log "Enabling BBR + FQ..."
  cat > /etc/sysctl.d/99-sysctl.conf <<'EOF'
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 8192
net.core.netdev_max_backlog = 16384
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_notsent_lowat = 131072
EOF
  cat > /etc/modules-load.d/bbr.conf <<'EOF'
tcp_bbr
EOF

  modprobe tcp_bbr 2>/dev/null || true
  sysctl --system >/dev/null || true

  log "Now: cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo unknown), qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo unknown)"
}

# ----------------- post cleanup (disk) -----------------
post_cleanup_disk() {
  apt-get clean
  rm -rf /var/lib/apt/lists/*
  mkdir -p /var/lib/apt/lists/partial
}

# ----------------- main -----------------
sel="$(select_newest_installable_cloud_kernel || true)"
[[ -n "${sel:-}" ]] || die "No installable cloud kernel found in experimental/sid/backports/main/security."

IFS='|' read -r suite pkg ver <<<"$sel"
current_running="$(uname -r)"
current_pkg_ver="$(dpkg-query -W -f='${Version}\n' "$pkg" 2>/dev/null || true)"
[[ -n "$current_pkg_ver" ]] || current_pkg_ver="not installed"
log "Upgrade candidate: $pkg ($ver) from $suite"
log "Current running kernel: $current_running"

keep_ver="${pkg#linux-image-}"

if is_pkg_installed_exact "$pkg" "$ver" && kernel_files_exist "$keep_ver"; then
  log "Already latest installed; skipping install."
else
  ensure_boot_space_for_upgrade
  confirm_upgrade "$suite" "$pkg" "$ver"
  install_selected_kernel "$suite" "$pkg" "$ver"
fi

# Ensure boot files exist (generate initrd if needed)
ensure_initrd_exists "$keep_ver"

# Keep only one kernel immediately (as you requested)
purge_other_kernels_keep_one "$keep_ver"

# Enable BBR + FQ
enable_bbr_fq

# Cleanup disk growth from APT caches/lists
post_cleanup_disk

warn "Current running kernel: $(uname -r)"
warn "Kept kernel on disk: $keep_ver"
warn "Reboot ASAP (you keep only ONE kernel, no fallback)"
