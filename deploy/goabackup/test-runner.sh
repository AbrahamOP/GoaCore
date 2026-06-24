#!/usr/bin/env bash
# ============================================================================
# test-runner.sh — functional tests for goabackup-runner.sh (Jalon 2 changes)
#
# Stubs the external commands (pvesm/lvs/zfs/zpool/df/rclone) via a PATH-prepended
# stub dir, drives the helper through SSH_ORIGINAL_COMMAND, and asserts the JSON.
# It does NOT deploy anything and does NOT require root: GOABACKUP_LOG_FILE points
# the log at a temp file. Run: bash test-runner.sh
# ============================================================================
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNNER="$HERE/goabackup-runner.sh"

WORK="$(mktemp -d)"
STUB="$WORK/bin"
mkdir -p "$STUB"
export GOABACKUP_LOG_FILE="$WORK/runner.log"
trap 'rm -rf "$WORK"' EXIT

pass=0; fail=0
ok()  { printf '  ok   - %s\n' "$1"; pass=$((pass+1)); }
bad() { printf '  FAIL - %s\n     got: %s\n' "$1" "$2"; fail=$((fail+1)); }

# run <stub-scenario> <command...> -> echoes the helper's stdout (JSON).
run() {
    local cmd="$1"
    SSH_ORIGINAL_COMMAND="$cmd" PATH="$STUB:$PATH" bash "$RUNNER" 2>/dev/null
}

# make_stub writes an executable stub for $1 whose body is $2.
make_stub() { printf '#!/usr/bin/env bash\n%s\n' "$2" > "$STUB/$1"; chmod +x "$STUB/$1"; }

reset_stubs() { rm -f "$STUB"/*; }

# ---------------------------------------------------------------------------
echo "== disk-free: lvmthin backend =="
reset_stubs
make_stub pvesm '
case "$*" in
  *"--content backup"*) echo "Name Type Status Total Used Available %"; echo "local lvmthin active 1 1 1 50%";;
  *) echo "";;
esac'
make_stub lvs 'echo "  42.50  3.10"'
make_stub df 'echo "Avail"; echo "10737418240"'   # 10 GiB
out=$(run "disk-free")
case "$out" in
  *'"backend":"lvmthin"'*) ok "backend=lvmthin reported" ;;
  *) bad "backend=lvmthin" "$out" ;;
esac
case "$out" in
  *'"thin_data_pct":42.50'*) ok "thin_data_pct parsed from lvs" ;;
  *) bad "thin_data_pct=42.50" "$out" ;;
esac
case "$out" in
  *'"local_avail_bytes":10737418240'*) ok "local_avail_bytes from df" ;;
  *) bad "local_avail_bytes" "$out" ;;
esac

# ---------------------------------------------------------------------------
echo "== disk-free: zfspool backend (no lvs, df floor) =="
reset_stubs
make_stub pvesm '
case "$*" in
  *"--content backup"*) echo "H"; echo "tank zfspool active 1 1 1 30%";;
  *) echo "";;
esac'
make_stub zpool 'echo "30"'
make_stub df 'echo "Avail"; echo "5368709120"'    # 5 GiB
# Intentionally NO lvs stub: a zfspool backend must not call lvs, and absence must
# NOT hard-fail (the old lvs_failed=error path is gone).
out=$(run "disk-free")
case "$out" in
  *'"ok":true'*'"backend":"zfspool"'*) ok "zfspool degrades soft (ok:true)" ;;
  *) bad "zfspool ok:true backend:zfspool" "$out" ;;
esac
case "$out" in
  *'"thin_data_pct":0'*) ok "thin_data_pct=0 on non-lvm (Go skips ceiling)" ;;
  *) bad "thin_data_pct=0 on zfs" "$out" ;;
esac
case "$out" in
  *'"local_avail_bytes":5368709120'*) ok "df floor present on zfs" ;;
  *) bad "df floor on zfs" "$out" ;;
esac

# ---------------------------------------------------------------------------
echo "== disk-free: unknown backend (pvesm fails) =="
reset_stubs
make_stub pvesm 'exit 1'
make_stub df 'echo "Avail"; echo "1073741824"'
out=$(run "disk-free")
case "$out" in
  *'"ok":true'*'"backend":"unknown"'*) ok "unknown backend, still ok:true" ;;
  *) bad "unknown backend ok" "$out" ;;
esac

# ---------------------------------------------------------------------------
echo "== resolve_dump_dir: TAB-indented dir storage ≠ /var/lib/vz (parsing) =="
reset_stubs
# A REALISTIC storage.cfg as Proxmox writes it: property lines indented by a TAB.
# The `dir: bigbackups` stanza advertises content=backup at a path that is NOT the
# conventional /var/lib/vz fallback. The parser must extract path/content from the
# tab-indented lines; the regression (empty key on tab lines) silently fell back to
# /var/lib/vz/dump for every PME whose backup storage lives elsewhere.
BIGDIR="$WORK/bigbackups"
mkdir -p "$BIGDIR/dump"
CFG="$WORK/storage.cfg"
printf 'dir: local\n\tpath /var/lib/vz\n\tcontent iso,vztmpl\n\ndir: bigbackups\n\tpath %s\n\tcontent backup,vztmpl\n' "$BIGDIR" > "$CFG"
make_stub pvesm '
case "$*" in
  *"--content backup"*) echo "Name Type Status Total Used Available %"; echo "bigbackups dir active 1 1 1 50%";;
  *) echo "";;
esac'
make_stub df 'echo "Avail"; echo "21474836480"'   # 20 GiB on the resolved dir
# GOABACKUP_DUMP_STORAGE deliberately EMPTY → force the storage.cfg auto-detect path.
out=$(SSH_ORIGINAL_COMMAND="disk-free" GOABACKUP_DUMP_STORAGE="" \
      GOABACKUP_STORAGE_CFG="$CFG" PATH="$STUB:$PATH" bash "$RUNNER" 2>/dev/null)
# The dump dir is logged; assert it resolved to bigbackups/dump, NOT the fallback.
logged_dir=$(grep -o 'dir=[^ ]*' "$GOABACKUP_LOG_FILE" | tail -1)
case "$logged_dir" in
  "dir=$BIGDIR/dump") ok "tab-indented dir storage resolved to $BIGDIR/dump" ;;
  *) bad "dump dir should resolve to $BIGDIR/dump (not /var/lib/vz/dump)" "$logged_dir" ;;
esac
case "$out" in
  *'"backend":"dir"'*'"local_avail_bytes":21474836480'*) ok "dir backend df floor read from resolved dir" ;;
  *) bad "dir backend disk-free should report the resolved dir's avail" "$out" ;;
esac

# ---------------------------------------------------------------------------
echo "== disk-free: df FAILS → avail_probe=failed (≠ a real 0) =="
reset_stubs
# lvs absent + pvesm unknown so no thin-pool ceiling, AND df errors on the (missing)
# dump dir. The helper must SIGNAL the blind probe (avail_probe=failed) so the Go
# side can refuse a destructive restore rather than fail-open with no disk guard.
make_stub pvesm 'exit 1'
make_stub df 'exit 1'
out=$(run "disk-free")
case "$out" in
  *'"avail_probe":"failed"'*) ok "df failure flagged as avail_probe=failed" ;;
  *) bad "df failure should set avail_probe=failed" "$out" ;;
esac
case "$out" in
  *'"local_avail_bytes":0'*) ok "local_avail_bytes=0 on df failure" ;;
  *) bad "local_avail_bytes should be 0 on df failure" "$out" ;;
esac

# ---------------------------------------------------------------------------
echo "== disk-free: df OK → avail_probe=ok =="
reset_stubs
make_stub pvesm 'exit 1'
make_stub df 'echo "Avail"; echo "1073741824"'
out=$(run "disk-free")
case "$out" in
  *'"avail_probe":"ok"'*) ok "successful df reports avail_probe=ok" ;;
  *) bad "df success should set avail_probe=ok" "$out" ;;
esac

# ---------------------------------------------------------------------------
echo "== validate_remote via cryptcheck: membership enforced =="
reset_stubs
# rclone listremotes lists ONLY 'offsite' — a request for 'gcrypt' must be refused
# (the old hardcoded whitelist is gone; membership is the source of truth).
make_stub rclone '
case "$1" in
  listremotes) echo "offsite:"; echo "backupz:";;
  cryptcheck)  exit 0;;   # would say "OK" but config-missing check fires first
  *) exit 0;;
esac'
make_stub pvesm 'echo ""'
# Unknown remote name → refused before any rclone cryptcheck.
out=$(run "cryptcheck 9500 nonexistent")
case "$out" in
  *'"error":"invalid_remote"'*) ok "unknown remote refused (membership)" ;;
  *) bad "unknown remote should be invalid_remote" "$out" ;;
esac
# Known remote name passes validate_remote (then hits the rclone_config_missing gate
# since RCLONE_CONFIG is the hardcoded prod path, absent in the test sandbox).
out=$(run "cryptcheck 9500 offsite")
case "$out" in
  *'"error":"rclone_config_missing"'*) ok "known remote passes validation (reaches config gate)" ;;
  *'"error":"invalid_remote"'*) bad "known remote wrongly refused" "$out" ;;
  *) ok "known remote passed validate_remote (got: $out)" ;;
esac
# Injection attempt → refused by the anti-injection regex BEFORE membership.
out=$(run "cryptcheck 9500 evil;rm")
case "$out" in
  *'"error":"invalid_remote"'*) ok "remote with metachars refused (anti-injection)" ;;
  *) bad "metachar remote should be invalid_remote" "$out" ;;
esac

# ---------------------------------------------------------------------------
echo "== cryptcheck: missing remote arg rejected =="
reset_stubs
make_stub pvesm 'echo ""'
out=$(run "cryptcheck 9500")
case "$out" in
  *'"error":"missing_arguments"'*) ok "cryptcheck now requires <vmid> <remote>" ;;
  *) bad "missing remote should be missing_arguments" "$out" ;;
esac

# ---------------------------------------------------------------------------
echo "== sandbox VMID guard still hard (ping out of range) =="
reset_stubs
make_stub pct 'exit 1'; make_stub qm 'exit 1'
out=$(run "ping 110")   # prod VMID, outside 9500-9599
case "$out" in
  *'"error":"non_sandbox_vmid"'*) ok "ping refuses non-sandbox VMID" ;;
  *) bad "ping 110 should be non_sandbox_vmid" "$out" ;;
esac

# ---------------------------------------------------------------------------
echo "== unknown operation rejected =="
reset_stubs
out=$(run "rm-rf-everything")
case "$out" in
  *'"error":"operation_not_allowed"'*) ok "closed op set enforced" ;;
  *) bad "unknown op should be operation_not_allowed" "$out" ;;
esac

# ---------------------------------------------------------------------------
echo
echo "RESULT: $pass passed, $fail failed"
[[ $fail -eq 0 ]]
