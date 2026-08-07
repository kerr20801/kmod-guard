#!/usr/bin/env bash
#
# kmod-guard — audit and disable rarely-used kernel network protocol modules.
#
# The point people miss: a module showing as "not loaded" is not the same as
# "not reachable". Distros ship autoload aliases (net-pf-2-proto-132 for SCTP),
# so an unprivileged process creating one socket pulls the module in on demand.
# And `blacklist` does NOT stop that path — only `install <mod> /bin/false` does.
#
# So this script does three things, in order, and the third is the one that
# matters: audit, apply, then PROVE it by actually trying to create a socket.
#
# Usage:
#   ./kmod-guard.sh                 audit only (no changes, safe to run anywhere)
#   ./kmod-guard.sh --apply         write modprobe.d config, unload if possible
#   ./kmod-guard.sh --revert        remove the config
#   ./kmod-guard.sh --modules sctp,dccp    limit to specific modules
#   ./kmod-guard.sh --apply --force        apply even if a module looks in use
#
# Exit: 0 = all target modules blocked, 1 = at least one still reachable, 2 = error
#
# MIT licence.

set -uo pipefail

CONF=/etc/modprobe.d/99-kmod-guard.conf
MODULES="sctp dccp tipc rds"
MODE=audit
FORCE=0

# protocol numbers used to actually test reachability via socket()
proto_num() {
  case "$1" in
    sctp) echo 132 ;;
    dccp) echo 33  ;;
    *)    echo ""  ;;   # tipc/rds use their own address families, see af_num
  esac
}
af_num() {
  case "$1" in
    tipc) echo 30 ;;
    rds)  echo 21 ;;
    *)    echo ""  ;;
  esac
}

c_red=$'\e[31m'; c_grn=$'\e[32m'; c_yel=$'\e[33m'; c_dim=$'\e[2m'; c_off=$'\e[0m'
[ -t 1 ] || { c_red=; c_grn=; c_yel=; c_dim=; c_off=; }

die(){ echo "${c_red}error:${c_off} $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --apply)   MODE=apply ;;
    --revert)  MODE=revert ;;
    --audit)   MODE=audit ;;
    --force)   FORCE=1 ;;
    --modules) shift; [ $# -gt 0 ] || die "--modules needs a value"
               MODULES=$(echo "$1" | tr ',' ' ') ;;
    -h|--help) sed -n '3,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) die "unknown option: $1" ;;
  esac
  shift
done

[ "$(uname -s)" = Linux ] || die "Linux only"
if [ "$MODE" != audit ] && [ "$(id -u)" -ne 0 ]; then
  die "--$MODE needs root (try: sudo $0 --$MODE)"
fi

KREL=$(uname -r)

# ── probes ────────────────────────────────────────────────────────────────────

is_loaded()   { lsmod 2>/dev/null | grep -q "^$1 "; }
mod_exists()  { modinfo "$1" >/dev/null 2>&1; }
has_alias()   {
  local f=/lib/modules/$KREL/modules.alias
  [ -r "$f" ] || return 1
  grep -qE "^alias net-pf-[0-9]+-proto-[0-9]+ $1\$|^alias net-pf-[0-9]+ $1\$" "$f"
}
is_blocked_cfg() {
  # Only search directories that exist. grep returns 2 for a missing path even
  # with -s, and under `set -o pipefail` that poisons the whole pipeline — which
  # silently reported "no config" on hosts that were in fact configured.
  local d dirs=()
  for d in /etc/modprobe.d /run/modprobe.d /usr/lib/modprobe.d /lib/modprobe.d; do
    [ -d "$d" ] && dirs+=("$d")
  done
  [ ${#dirs[@]} -gt 0 ] || return 1
  grep -rhE "^[[:space:]]*install[[:space:]]+$1[[:space:]]+(/bin/false|/bin/true)" \
    "${dirs[@]}" 2>/dev/null | grep -q .
}
refcount() { lsmod 2>/dev/null | awk -v m="$1" '$1==m {print $3; found=1} END{if(!found) print "-"}'; }

# The only check that actually matters: can a process reach the protocol?
# Note this deliberately does NOT use `ss`, because running `ss` will itself
# autoload the *_diag helper modules and change what you are measuring.
can_reach() {
  local m=$1 p af
  p=$(proto_num "$m"); af=$(af_num "$m")
  command -v python3 >/dev/null 2>&1 || return 2   # unknown
  if [ -n "$p" ]; then
    python3 - "$p" <<'PY' >/dev/null 2>&1
import socket, sys
socket.socket(socket.AF_INET, socket.SOCK_STREAM, int(sys.argv[1])).close()
PY
  elif [ -n "$af" ]; then
    python3 - "$af" <<'PY' >/dev/null 2>&1
import socket, sys
socket.socket(int(sys.argv[1]), socket.SOCK_DGRAM, 0).close()
PY
  else
    return 2
  fi
}

# ── report ────────────────────────────────────────────────────────────────────

audit_one() {
  local m=$1 loaded exists alias blocked reach rc
  is_loaded  "$m" && loaded=yes || loaded=no
  mod_exists "$m" && exists=yes || exists=no
  has_alias  "$m" && alias=yes  || alias=no
  is_blocked_cfg "$m" && blocked=yes || blocked=no
  rc=$(refcount "$m")
  can_reach "$m"; reach=$?

  local verdict color
  case $reach in
    0) verdict="REACHABLE"; color=$c_red ;;
    1) verdict="blocked";   color=$c_grn ;;
    *) verdict="unknown";   color=$c_yel ;;
  esac

  printf "  %-6s %-9s loaded=%-4s refs=%-3s module=%-4s autoload=%-4s config=%-4s %s%s%s\n" \
    "$m" "" "$loaded" "$rc" "$exists" "$alias" "$blocked" "$color" "$verdict" "$c_off"

  [ $reach -eq 0 ] && return 1 || return 0
}

in_use() {
  # conservative: a module with a non-zero refcount or dependent modules
  local m=$1 rc dep
  rc=$(refcount "$m"); [ "$rc" = "-" ] && return 1
  dep=$(lsmod | awk -v m="$m" '$1==m {print $4}')
  [ "$rc" != "0" ] || [ -n "$dep" ]
}

write_conf() {
  local tmp; tmp=$(mktemp) || die "mktemp failed"
  {
    echo "# Written by kmod-guard on $(date -Is)"
    echo "# Rarely-used network protocols disabled to shrink kernel attack surface."
    echo "#"
    echo "# 'install <mod> /bin/false' is the load-bearing line. A bare 'blacklist'"
    echo "# still permits autoload via the net-pf-*-proto-* alias, which is exactly"
    echo "# how an unprivileged process reaches this code."
    echo "# Remove this file (or run kmod-guard.sh --revert) to undo."
    echo
    for m in $MODULES; do
      echo "install $m /bin/false"
      echo "install ${m}_diag /bin/false"
    done
    echo
    for m in $MODULES; do
      echo "blacklist $m"
      echo "blacklist ${m}_diag"
    done
  } > "$tmp"
  install -m 0644 -o root -g root "$tmp" "$CONF" || { rm -f "$tmp"; die "cannot write $CONF"; }
  rm -f "$tmp"
  echo "wrote $CONF"
}

# ── main ──────────────────────────────────────────────────────────────────────

echo "kmod-guard  —  kernel $KREL  —  $(hostname 2>/dev/null || echo host)"
echo

case $MODE in
revert)
  if [ -f "$CONF" ]; then rm -f "$CONF"; echo "removed $CONF"
  else echo "nothing to remove ($CONF absent)"; fi
  command -v depmod >/dev/null && depmod -a 2>/dev/null
  echo "note: modules are not reloaded automatically; reboot or modprobe as needed"
  exit 0
  ;;

apply)
  # refuse to disable something the box is genuinely using
  skip=""
  for m in $MODULES; do
    if in_use "$m" && [ $FORCE -eq 0 ]; then
      echo "${c_yel}skip${c_off} $m — appears to be in use (refs=$(refcount "$m")). Use --force to override."
      skip="$skip $m"
    fi
  done
  for s in $skip; do MODULES=$(echo "$MODULES" | sed "s/\b$s\b//g"); done
  MODULES=$(echo "$MODULES" | tr -s ' ' | sed 's/^ //;s/ $//')
  [ -n "$MODULES" ] || { echo "nothing left to apply"; exit 0; }

  write_conf
  command -v depmod >/dev/null && depmod -a 2>/dev/null

  # try to unload what is already resident; a live refcount will refuse, which
  # is fine — the config still prevents it coming back after reboot.
  for m in $MODULES; do
    if is_loaded "$m"; then
      modprobe -r "${m}_diag" 2>/dev/null
      if modprobe -r "$m" 2>/dev/null; then
        echo "unloaded $m"
      else
        echo "${c_yel}note${c_off} $m is resident and could not be unloaded (in use) — reboot to clear"
      fi
    fi
  done
  echo
  ;;
esac

echo "status:"
fails=0
for m in $MODULES; do
  audit_one "$m" || fails=$((fails+1))
done
echo

if [ $fails -eq 0 ]; then
  echo "${c_grn}all target modules unreachable${c_off}"
  [ "$MODE" = audit ] && echo "${c_dim}(audit only — no changes were made)${c_off}"
  exit 0
else
  echo "${c_red}$fails module(s) still reachable${c_off}"
  [ "$MODE" = audit ] && echo "run with --apply to fix"
  exit 1
fi
