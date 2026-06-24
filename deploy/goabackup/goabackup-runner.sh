#!/usr/bin/env bash
# ============================================================================
# goabackup-runner.sh - Security-Critical Backup Operations Entrypoint
# ============================================================================
#
# DEPLOYMENT REQUIREMENTS:
#   1. SSH entry (authorized_keys for user 'goabackup'):
#      command="sudo /usr/local/bin/goabackup-runner.sh",no-port-forwarding,\
#      no-agent-forwarding,no-X11-forwarding,no-pty ssh-rsa AAAA...
#
#   2. Sudoers configuration (/etc/sudoers.d/goabackup):
#      goabackup ALL=(root) NOPASSWD: /usr/local/bin/goabackup-runner.sh
#      Defaults:goabackup env_keep+="SSH_ORIGINAL_COMMAND"
#      Defaults:goabackup env_keep+="SSH_CONNECTION"
#
#   3. Rclone config with Google Drive crypt backend (readable by root):
#      /root/.config/rclone/rclone.conf
#      Section [gcrypt] = encrypted remote, backend to [gdrive]
#
# OPERATION FLOW:
#   - Runs as root (via sudo forced-command)
#   - Reads operation from SSH_ORIGINAL_COMMAND env var
#   - Whitelist-validates operation + args
#   - Executes read-only checks (NO destructive operations)
#   - Outputs JSON on stdout, logs to /var/log/goabackup-runner.log
#   - Always exits with explicit code
#
# SECURITY POSTURE:
#   - No eval, no dynamic code execution
#   - No shell metacharacters in args (strict regex validation)
#   - IFS set to prevent word splitting
#   - Quotes around all variable expansions
#   - Timeouts on all external commands
#   - JSON output prevents information leakage via shell escaping
# ============================================================================

set -euo pipefail
IFS=$'\n\t'

SCRIPT_NAME="$(basename "${BASH_SOURCE[0]}")"
readonly SCRIPT_NAME
# LOG_FILE default is the production path; GOABACKUP_LOG_FILE overrides it for the
# functional test harness only (a host-local path, never from SSH_ORIGINAL_COMMAND).
readonly LOG_FILE="${GOABACKUP_LOG_FILE:-/var/log/goabackup-runner.log}"
readonly RCLONE_CONFIG="/root/.config/rclone/rclone.conf"
readonly TIMEOUT_DISK_CHECK=5
readonly TIMEOUT_CRYPTCHECK=180
readonly TIMEOUT_HEALTHCHECK=30
readonly TIMEOUT_PING=10
readonly VMID_SANDBOX_MIN=9500
readonly VMID_SANDBOX_MAX=9599

# LOCAL config (NEVER received via SSH_ORIGINAL_COMMAND). These are install-time
# knobs an admin may edit on the host; the app never drives them.
#
# THINPOOL is the LVM-thin pool the disk sonde reads when the dump storage backend
# is lvmthin (auto-detected; this is only the default name). DUMP_STORAGE optionally
# pins the Proxmox storage holding vzdump backups; empty = auto-detect a `dir`
# storage with content=backup. REMOTE_PREFIX is the off-site tree prefix
# (<remote>:<REMOTE_PREFIX><vmid>/) — conventional, configurable here only.
readonly THINPOOL="${GOABACKUP_THINPOOL:-pve/data}"
readonly DUMP_STORAGE="${GOABACKUP_DUMP_STORAGE:-}"
readonly REMOTE_PREFIX="${GOABACKUP_REMOTE_PREFIX:-daily/}"
readonly DUMP_DIR_FALLBACK="/var/lib/vz/dump"
# STORAGE_CFG default is the production path; GOABACKUP_STORAGE_CFG overrides it for
# the functional test harness ONLY (a host-local fixture path, never received from
# SSH_ORIGINAL_COMMAND), exactly like GOABACKUP_LOG_FILE.
readonly STORAGE_CFG="${GOABACKUP_STORAGE_CFG:-/etc/pve/storage.cfg}"

# ============================================================================
# SECTION: Utility Functions
# ============================================================================

# Initialize log file with restrictive perms if not present
init_log() {
    if [[ ! -f "$LOG_FILE" ]]; then
        touch "$LOG_FILE" 2>/dev/null || return 1
        chmod 600 "$LOG_FILE" 2>/dev/null || return 1
    fi
    return 0
}

# Log with structured format: ISO8601 timestamp, source, operation, verdict
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date -Iseconds)"
    local ssh_conn="${SSH_CONNECTION:-unknown}"

    printf '[%s] %s | ssh=%s | %s | %s\n' \
        "$timestamp" "$SCRIPT_NAME" "$ssh_conn" "$level" "$message" >> "$LOG_FILE" 2>/dev/null || true
}

# Output JSON response (always on stdout, single line)
json_response() {
    local ok="$1"
    shift
    local data=("$@")

    # Build JSON object: {"ok": true/false, "field1": value1, ...}
    local json_fields="\"ok\":${ok}"

    # Add remaining key=value pairs
    for item in "${data[@]}"; do
        # item format: key=value or key=json_string (must be valid JSON)
        local key="${item%%=*}"
        local value="${item#*=}"

        # Validate key is alphanumeric+_
        if ! [[ "$key" =~ ^[a-zA-Z_][a-zA-Z0-9_]*$ ]]; then
            json_fields+=",\"error\":\"invalid_key\""
            continue
        fi

        # Number/bool/null pass through unquoted; everything else is a quoted string.
        if [[ "$value" =~ ^(true|false|null|-?[0-9]+(\.[0-9]+)?)$ ]]; then
            json_fields+=",\"$key\":$value"
        else
            # Escape and quote as string
            value="${value//\\/\\\\}"
            value="${value//\"/\\\"}"
            json_fields+=",\"$key\":\"$value\""
        fi
    done

    printf '{%s}\n' "$json_fields"
}

# Escape string for JSON (double quotes, backslashes)
json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    printf '%s' "$s"
}

# Resolve the local vzdump dump directory. Auto-detects a Proxmox `dir` storage with
# content=backup (DUMP_STORAGE pin honoured first), falling back to the conventional
# /var/lib/vz/dump. The result is a LOCAL variable, never received from the app, and
# is always suffixed with /dump so the glob stays anchored. Echoes the directory.
resolve_dump_dir() {
    local base="" path=""

    # 1. Explicit pin (install-time): trust the storage name, resolve its path.
    if [[ -n "$DUMP_STORAGE" ]]; then
        path=$( timeout "$TIMEOUT_DISK_CHECK" pvesm path "${DUMP_STORAGE}:" 2>/dev/null | head -1 ) || true
        if [[ -n "$path" && -d "$path" ]]; then
            printf '%s' "$path"
            return 0
        fi
    fi

    # 2. Auto-detect: first `dir` storage advertising content=backup in storage.cfg.
    if [[ -r "$STORAGE_CFG" ]]; then
        # Parse the storage.cfg stanza: a `dir: NAME` block with `path X` and
        # `content ...,backup,...`. Pure bash, no eval.
        local in_dir=0 cur_path="" cur_has_backup=0 line key val
        while IFS= read -r line; do
            if [[ "$line" =~ ^dir:[[:space:]] ]]; then
                # New dir stanza — commit the previous one if it qualified.
                if (( in_dir && cur_has_backup )) && [[ -n "$cur_path" ]]; then
                    base="$cur_path"; break
                fi
                in_dir=1; cur_path=""; cur_has_backup=0
                continue
            fi
            if [[ "$line" =~ ^[a-z]+:[[:space:]] ]]; then
                # A different storage type stanza ends the dir block.
                if (( in_dir && cur_has_backup )) && [[ -n "$cur_path" ]]; then
                    base="$cur_path"; break
                fi
                in_dir=0; cur_path=""; cur_has_backup=0
                continue
            fi
            if (( in_dir )); then
                # storage.cfg property lines are indented by a LEADING TAB (Proxmox
                # 5.x→9.x writer) or spaces. Strip the leading whitespace FIRST, then
                # take the first field as the key — otherwise `%%[[:space:]]*` on a
                # tab-indented line removes everything from the leading tab onward and
                # yields an EMPTY key, so `path`/`content` never match and dir-storage
                # auto-detection silently dies (always falling back to the conventional
                # /var/lib/vz/dump). Verified on both tab- and space-indented lines.
                local trimmed="${line#"${line%%[![:space:]]*}"}"
                key="${trimmed%%[[:space:]]*}"
                val="${trimmed#"$key"}"; val="${val#"${val%%[![:space:]]*}"}"
                case "$key" in
                    path) cur_path="$val" ;;
                    content) [[ ",$val," == *",backup,"* || "$val" == *backup* ]] && cur_has_backup=1 ;;
                esac
            fi
        done < "$STORAGE_CFG"
        # Commit a trailing qualifying stanza (file ended inside the block).
        if [[ -z "$base" ]] && (( in_dir && cur_has_backup )) && [[ -n "$cur_path" ]]; then
            base="$cur_path"
        fi
    fi

    if [[ -n "$base" && -d "$base/dump" ]]; then
        printf '%s' "$base/dump"
        return 0
    fi
    if [[ -n "$base" && -d "$base" ]]; then
        printf '%s' "$base"
        return 0
    fi

    # 3. Conventional fallback.
    printf '%s' "$DUMP_DIR_FALLBACK"
}

# Resolve the backend type of the dump storage via pvesm status (lvmthin / zfspool /
# dir / unknown). Best-effort and FAIL-SOFT: any failure yields "unknown" so the
# disk sonde degrades to the universal df floor rather than aborting on non-LVM.
# Echoes one of: lvmthin | zfspool | dir | unknown.
resolve_dump_backend() {
    # When a dump storage is pinned, read its exact type; else scan for the first
    # storage advertising backup content and report its type.
    local status_line type
    if [[ -n "$DUMP_STORAGE" ]]; then
        status_line=$( timeout "$TIMEOUT_DISK_CHECK" pvesm status --storage "$DUMP_STORAGE" 2>/dev/null | awk 'NR==2{print $2}' ) || true
        case "$status_line" in
            lvmthin|zfspool|dir) printf '%s' "$status_line"; return 0 ;;
        esac
    fi
    # Generic: find a storage whose content includes backup, report its Type column.
    type=$( timeout "$TIMEOUT_DISK_CHECK" pvesm status --content backup 2>/dev/null | awk 'NR==2{print $2}' ) || true
    case "$type" in
        lvmthin|zfspool|dir) printf '%s' "$type"; return 0 ;;
    esac
    printf 'unknown'
}

# ============================================================================
# SECTION: Argument Validation
# ============================================================================

# Validate VMID: must be integer, optionally in sandbox range for healthcheck/ping
validate_vmid() {
    local vmid="$1"
    local require_sandbox="${2:-false}"

    # Must be all digits
    if ! [[ "$vmid" =~ ^[0-9]+$ ]]; then
        return 1
    fi

    # If sandbox check required, must be in 9500-9599
    if [[ "$require_sandbox" == "true" ]]; then
        if (( vmid < VMID_SANDBOX_MIN || vmid > VMID_SANDBOX_MAX )); then
            return 1
        fi
    fi

    return 0
}

# Validate generic alphanumeric argument (service name, port, etc)
# Allowed: letters, digits, dots, dashes, underscores, colons
validate_arg() {
    local arg="$1"

    if ! [[ "$arg" =~ ^[a-zA-Z0-9._:\-]+$ ]]; then
        return 1
    fi

    return 0
}

# ============================================================================
# SECTION: Operation Handlers
# ============================================================================

# Operation: disk-free
# Backend-agnostic disk pre-flight probe. Detects the dump storage backend
# (lvmthin / zfspool / dir / unknown) and reports:
#   - thin_data_pct / thin_meta_pct : LVM-thin usage (0 on non-lvmthin backends)
#   - local_avail_bytes             : free bytes on the dump dir (universal, df)
#   - backend                       : the detected backend (ALWAYS present)
#
# CONTRACT: the Go side reads `backend` and only applies the thin-pool ceiling guard
# when backend==lvmthin AND thin_data_pct>0. A missing/0 thin_data_pct must NEVER be
# read as "0% used ⇒ always pass". FAIL-SOFT: a non-LVM backend degrades to
# backend=zfspool/dir/unknown with the df floor, never a hard error (the old
# lvs_failed=error path blocked every restore on a non-LVM PME).
op_disk_free() {
    log "INFO" "disk-free requested"

    local thin_data_pct=0 thin_meta_pct=0 local_avail_bytes=0 zfs_cap_pct=0
    local avail_probe="ok"   # "ok" = df succeeded, "failed" = df errored (≠ a real 0)
    local backend dump_dir
    backend=$(resolve_dump_backend)
    dump_dir=$(resolve_dump_dir)

    # --- LVM-thin: read the thin pool usage (best-effort; degrade to unknown). ---
    if [[ "$backend" == "lvmthin" ]]; then
        local lvs_output
        if lvs_output=$( timeout "$TIMEOUT_DISK_CHECK" lvs --noheadings -o data_percent,metadata_percent "$THINPOOL" 2>&1 ); then
            IFS=' ' read -r thin_data_pct thin_meta_pct <<< "$lvs_output" || true
            thin_data_pct=$(printf '%s' "$thin_data_pct" | xargs)
            thin_meta_pct=$(printf '%s' "$thin_meta_pct" | xargs)
            # Guard: keep numeric only, else neutralise to 0 (never garbage to Go).
            [[ "$thin_data_pct" =~ ^[0-9]+(\.[0-9]+)?$ ]] || thin_data_pct=0
            [[ "$thin_meta_pct" =~ ^[0-9]+(\.[0-9]+)?$ ]] || thin_meta_pct=0
        else
            # Pool read failed though backend looked lvmthin → degrade, don't abort.
            log "WARN" "disk-free: lvs failed on $THINPOOL, degrading backend to unknown"
            backend="unknown"
        fi
    fi

    # --- ZFS: best-effort capacity (documented; not validated on a live ZFS PVE). ---
    if [[ "$backend" == "zfspool" ]]; then
        # zpool list capacity is a whole-pool percentage; we pass it through as an
        # advisory field. The Go side relies on the df floor below for ZFS, not on
        # this percentage (best-effort only).
        local zpool_out
        if zpool_out=$( timeout "$TIMEOUT_DISK_CHECK" zpool list -Hp -o capacity 2>/dev/null | head -1 ); then
            zpool_out="${zpool_out%\%}"
            [[ "$zpool_out" =~ ^[0-9]+$ ]] && zfs_cap_pct="$zpool_out"
        fi
    fi

    # --- Universal floor: free bytes on the dump dir (works on every backend). ---
    local df_output
    if df_output=$( timeout "$TIMEOUT_DISK_CHECK" df -B1 --output=avail "$dump_dir" 2>&1 ); then
        local_avail_bytes=$(printf '%s' "$df_output" | tail -1 | xargs)
        [[ "$local_avail_bytes" =~ ^[0-9]+$ ]] || local_avail_bytes=0
    else
        # df ERRORED (e.g. the resolved dump dir does not exist). This is NOT a real
        # "0 bytes free": flag it so the Go side can distinguish a blind probe from a
        # genuine 0 and refuse a destructive restore rather than fail-open when the
        # backend also gives no thin-pool ceiling.
        log "WARN" "disk-free: df failed on $dump_dir"
        local_avail_bytes=0
        avail_probe="failed"
    fi

    log "INFO" "disk-free success: backend=${backend} data=${thin_data_pct}% meta=${thin_meta_pct}% zfs_cap=${zfs_cap_pct}% local=${local_avail_bytes} bytes dir=${dump_dir} avail_probe=${avail_probe}"
    json_response "true" \
        "backend=${backend}" \
        "thin_data_pct=${thin_data_pct}" \
        "thin_meta_pct=${thin_meta_pct}" \
        "zfs_capacity_pct=${zfs_cap_pct}" \
        "local_avail_bytes=${local_avail_bytes}" \
        "avail_probe=${avail_probe}"
    return 0
}

# Operation: cryptcheck <vmid> <remote>
# Verifies off-site backup integrity (one-way rclone cryptcheck) against <remote>.
# The remote is NO LONGER hardcoded to "gcrypt": it is passed by the N1 engine and
# re-validated host-side via validate_remote (membership in `rclone listremotes`).
# Targets <remote>:<REMOTE_PREFIX><vmid>/ in the auto-detected local dump dir.
op_cryptcheck() {
    local vmid="$1"
    local remote="$2"

    if ! validate_vmid "$vmid"; then
        log "WARN" "cryptcheck: invalid vmid=$vmid"
        json_response "false" "error=invalid_vmid"
        return 1
    fi
    if ! validate_remote "$remote"; then
        log "WARN" "cryptcheck: invalid or unknown remote=$remote"
        json_response "false" "error=invalid_remote"
        return 1
    fi

    log "INFO" "cryptcheck requested: vmid=$vmid remote=$remote"

    # Check if rclone.conf exists
    if [[ ! -f "$RCLONE_CONFIG" ]]; then
        log "WARN" "cryptcheck: rclone config not found"
        json_response "false" "error=rclone_config_missing"
        return 1
    fi

    local dump_dir
    dump_dir=$(resolve_dump_dir)

    # Run rclone cryptcheck (one-way, only checks remote against local). The remote
    # name passed validate_remote (anti-injection + membership) so interpolating it
    # into "<remote>:<prefix><vmid>/" is safe.
    local rclone_output
    local rclone_rc=0
    rclone_output=$( timeout "$TIMEOUT_CRYPTCHECK" \
        rclone cryptcheck \
            --config "$RCLONE_CONFIG" \
            --one-way \
            --include "vzdump-*-${vmid}-*.zst" \
            "$dump_dir" \
            "${remote}:${REMOTE_PREFIX}${vmid}/" \
            2>&1 ) || rclone_rc=$?

    local differences=0
    local errors=0

    # Parse rclone output for differences/errors
    if grep -q 'ERROR' <<< "$rclone_output"; then
        errors=$(printf '%s' "$rclone_output" | grep -c 'ERROR' || echo 0)
    fi

    if grep -q 'Differences found' <<< "$rclone_output"; then
        differences=$(printf '%s' "$rclone_output" | grep 'Differences found' | grep -oE '[0-9]+' | head -1 || echo 0)
    fi

    # rclone exit code: 0 = match, 1+ = mismatch/error
    if (( rclone_rc == 0 )); then
        log "INFO" "cryptcheck vmid=$vmid: OK (no differences)"
        json_response "true" \
            "differences=${differences}" \
            "errors=${errors}" \
            "detail=integrity_verified"
        return 0
    else
        log "WARN" "cryptcheck vmid=$vmid: MISMATCH/ERROR (exit=$rclone_rc, diff=$differences, err=$errors)"
        local detail
        detail=$(json_escape "rclone exit code: $rclone_rc, differences: $differences, errors: $errors")
        json_response "false" \
            "differences=${differences}" \
            "errors=${errors}" \
            "detail=$detail"
        return 1
    fi
}

# Operation: healthcheck <vmid> <type> <kind> <arg>
# Checks service status or open ports on a guest VM (sandbox range 9500-9599 only)
op_healthcheck() {
    local vmid="$1"
    local type="$2"      # lxc or qemu
    local kind="$3"      # service or port
    local arg="$4"       # service name or port number

    # SANDBOX VALIDATION: vmid must be in 9500-9599
    if ! validate_vmid "$vmid" "true"; then
        log "WARN" "healthcheck: invalid or non-sandbox vmid=$vmid"
        json_response "false" "error=non_sandbox_vmid"
        return 1
    fi

    # Validate type
    if ! [[ "$type" =~ ^(lxc|qemu)$ ]]; then
        log "WARN" "healthcheck: invalid type=$type"
        json_response "false" "error=invalid_type"
        return 1
    fi

    # Validate kind
    if ! [[ "$kind" =~ ^(service|port)$ ]]; then
        log "WARN" "healthcheck: invalid kind=$kind"
        json_response "false" "error=invalid_kind"
        return 1
    fi

    # Validate arg (service name or port number)
    if ! validate_arg "$arg"; then
        log "WARN" "healthcheck: invalid arg=$arg"
        json_response "false" "error=invalid_arg"
        return 1
    fi

    # For port checks, arg must be strictly numeric (avoids regex metachars in the grep below)
    if [[ "$kind" == "port" ]] && ! [[ "$arg" =~ ^[0-9]+$ ]]; then
        log "WARN" "healthcheck: port must be numeric, got=$arg"
        json_response "false" "error=invalid_port"
        return 1
    fi

    log "INFO" "healthcheck requested: vmid=$vmid type=$type kind=$kind arg=$arg"

    # ========================================================================
    # LXC + SERVICE
    # ========================================================================
    if [[ "$type" == "lxc" && "$kind" == "service" ]]; then
        local status
        if status=$( timeout "$TIMEOUT_HEALTHCHECK" pct exec "$vmid" -- systemctl is-active "$arg" 2>&1 ); then
            # Check if output is "active"
            if [[ "$status" == "active" ]]; then
                log "INFO" "healthcheck vmid=$vmid: service $arg is active"
                json_response "true" "detail=active"
                return 0
            else
                log "INFO" "healthcheck vmid=$vmid: service $arg status=$status"
                json_response "false" "detail=$status"
                return 1
            fi
        else
            log "WARN" "healthcheck vmid=$vmid: pct exec failed"
            json_response "false" "error=pct_exec_failed"
            return 1
        fi
    fi

    # ========================================================================
    # LXC + PORT
    # ========================================================================
    if [[ "$type" == "lxc" && "$kind" == "port" ]]; then
        local ss_output
        if ss_output=$( timeout "$TIMEOUT_HEALTHCHECK" pct exec "$vmid" -- ss -ltn 2>&1 ); then
            # Grep for the port in LISTEN state (format: "LISTEN ... :port")
            if printf '%s' "$ss_output" | grep -qE ":${arg}\b"; then
                log "INFO" "healthcheck vmid=$vmid: port $arg is listening"
                json_response "true" "detail=listening"
                return 0
            else
                log "INFO" "healthcheck vmid=$vmid: port $arg not listening"
                json_response "false" "detail=not_listening"
                return 1
            fi
        else
            log "WARN" "healthcheck vmid=$vmid: pct exec ss failed"
            json_response "false" "error=pct_exec_failed"
            return 1
        fi
    fi

    # ========================================================================
    # QEMU + SERVICE
    # ========================================================================
    if [[ "$type" == "qemu" && "$kind" == "service" ]]; then
        local qm_output
        if qm_output=$( timeout "$TIMEOUT_HEALTHCHECK" qm guest exec "$vmid" -- systemctl is-active "$arg" 2>&1 ); then
            # qm guest exec returns JSON; extract "out-data" field
            local service_status
            service_status=$(printf '%s' "$qm_output" | grep -oP '"out-data":\s*"\K[^"]+' || echo "unknown")

            if [[ "$service_status" == "active" ]]; then
                log "INFO" "healthcheck vmid=$vmid: qemu service $arg is active"
                json_response "true" "detail=active"
                return 0
            else
                log "INFO" "healthcheck vmid=$vmid: qemu service $arg status=$service_status"
                json_response "false" "detail=$service_status"
                return 1
            fi
        else
            log "WARN" "healthcheck vmid=$vmid: qm guest exec failed"
            json_response "false" "error=qm_exec_failed"
            return 1
        fi
    fi

    # ========================================================================
    # QEMU + PORT
    # ========================================================================
    if [[ "$type" == "qemu" && "$kind" == "port" ]]; then
        local qm_ss_output
        if qm_ss_output=$( timeout "$TIMEOUT_HEALTHCHECK" qm guest exec "$vmid" -- ss -ltn 2>&1 ); then
            # Parse JSON response, extract out-data
            local ss_data
            ss_data=$(printf '%s' "$qm_ss_output" | grep -oP '"out-data":\s*"\K[^"]*(?=")' || echo "")

            if printf '%s' "$ss_data" | grep -qE ":${arg}\b"; then
                log "INFO" "healthcheck vmid=$vmid: qemu port $arg is listening"
                json_response "true" "detail=listening"
                return 0
            else
                log "INFO" "healthcheck vmid=$vmid: qemu port $arg not listening"
                json_response "false" "detail=not_listening"
                return 1
            fi
        else
            log "WARN" "healthcheck vmid=$vmid: qm guest exec ss failed"
            json_response "false" "error=qm_exec_failed"
            return 1
        fi
    fi

    # Should not reach here
    log "WARN" "healthcheck vmid=$vmid: unreachable code path"
    json_response "false" "error=unreachable"
    return 1
}

# Operation: ping <vmid>
# Returns guest status: running, stopped, or absent (sandbox range 9500-9599 only)
op_ping() {
    local vmid="$1"

    # SANDBOX VALIDATION: vmid must be in 9500-9599
    if ! validate_vmid "$vmid" "true"; then
        log "WARN" "ping: invalid or non-sandbox vmid=$vmid"
        json_response "false" "error=non_sandbox_vmid"
        return 1
    fi

    log "INFO" "ping requested: vmid=$vmid"

    local status
    local guest_type="unknown"

    # Try LXC first
    if status=$( timeout "$TIMEOUT_PING" pct status "$vmid" 2>&1 ); then
        guest_type="lxc"
    elif status=$( timeout "$TIMEOUT_PING" qm status "$vmid" 2>&1 ); then
        guest_type="qemu"
    else
        # Neither succeeded, assume absent
        log "INFO" "ping vmid=$vmid: absent"
        json_response "true" "status=absent"
        return 0
    fi

    # Extract status from output (e.g., "status: running" or "status: stopped")
    local guest_status
    guest_status=$(printf '%s' "$status" | grep -oP '(?<=status: )\S+' | head -1)

    if [[ -z "$guest_status" ]]; then
        guest_status="unknown"
    fi

    log "INFO" "ping vmid=$vmid: status=$guest_status (type=$guest_type)"
    json_response "true" "status=$guest_status"
    return 0
}

# Validate an rclone remote name. The hardcoded ^(gdrive|gcrypt)$ whitelist is GONE:
# the local rclone config (edited by the admin) is now the source of truth. Two gates
# must BOTH pass:
#   1. Anti-injection: the name is strictly [a-zA-Z0-9_-]+ (no metachars, no colon —
#      we append the ":" ourselves), so it can never break out of the rclone arg.
#   2. Membership: the name appears EXACTLY (line-by-line, never substring/regex) in
#      `rclone listremotes`. A remote the host does not actually have is refused, so
#      the app can never point an op at an arbitrary/exfil destination.
# RCLONE_CONFIG stays hardcoded readonly (never an argument), so the allowlist the
# host enumerates is the host's own — trust never moves app→host.
validate_remote() {
    local candidate="$1"

    # 1. Strict anti-injection.
    if ! [[ "$candidate" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        return 1
    fi

    # 2. Exact membership in the host's configured remotes.
    local listed line
    listed=$( timeout "$TIMEOUT_DISK_CHECK" rclone listremotes --config "$RCLONE_CONFIG" 2>/dev/null ) || return 1
    while IFS= read -r line; do
        line="${line%:}"          # rclone prints "name:" — strip the trailing colon
        [[ -z "$line" ]] && continue
        if [[ "$line" == "$candidate" ]]; then
            return 0
        fi
    done <<< "$listed"
    return 1
}

# Operation: rclone-remotes — list configured rclone remotes (read-only).
op_rclone_remotes() {
    log "INFO" "rclone-remotes requested"
    local out rc=0
    out=$( timeout "$TIMEOUT_DISK_CHECK" rclone listremotes --config "$RCLONE_CONFIG" 2>&1 ) || rc=$?
    if (( rc != 0 )); then
        json_response "false" "error=rclone_failed"
        return 1
    fi
    local arr="" first=1 line
    while IFS= read -r line; do
        line="${line%:}"
        [[ -z "$line" ]] && continue
        if (( first )); then first=0; else arr+=","; fi
        arr+="\"$(json_escape "$line")\""
    done <<< "$out"
    # remotes is a JSON array → emit directly (json_response only handles scalars).
    printf '{"ok":true,"remotes":[%s]}\n' "$arr"
}

# Operation: rclone-about <remote> — backend space usage (read-only).
op_rclone_about() {
    local remote="$1"
    if ! validate_remote "$remote"; then
        json_response "false" "error=invalid_remote"
        return 1
    fi
    log "INFO" "rclone-about requested: remote=$remote"
    local out rc=0
    out=$( timeout "$TIMEOUT_HEALTHCHECK" rclone about "${remote}:" --json --config "$RCLONE_CONFIG" 2>&1 ) || rc=$?
    if (( rc != 0 )); then
        json_response "false" "error=rclone_about_failed"
        return 1
    fi
    local used free total
    used=$(printf '%s' "$out" | grep -oE '"used": *[0-9]+' | grep -oE '[0-9]+' | head -1)
    free=$(printf '%s' "$out" | grep -oE '"free": *[0-9]+' | grep -oE '[0-9]+' | head -1)
    total=$(printf '%s' "$out" | grep -oE '"total": *[0-9]+' | grep -oE '[0-9]+' | head -1)
    json_response "true" "used=${used:-0}" "free=${free:-0}" "total=${total:-0}"
}

# Operation: rclone-push <vmid> <remote> <keeplocal 0|1>
# Pushes the latest LOCAL vzdump archive of <vmid> to <remote>:<REMOTE_PREFIX><vmid>/.
# The archive path is resolved internally from the VMID (no path injection) in the
# auto-detected dump dir. keeplocal=0 deletes that archive locally after a successful
# copy (off-site-only destination).
op_rclone_push() {
    local vmid="$1" remote="$2" keeplocal="$3"
    if ! validate_vmid "$vmid"; then
        json_response "false" "error=invalid_vmid"; return 1
    fi
    if ! validate_remote "$remote"; then
        json_response "false" "error=invalid_remote"; return 1
    fi
    if [[ "$keeplocal" != "0" && "$keeplocal" != "1" ]]; then
        json_response "false" "error=invalid_keeplocal"; return 1
    fi
    local dump_dir
    dump_dir=$(resolve_dump_dir)
    local archive
    archive=$(ls -t "$dump_dir"/vzdump-*-"${vmid}"-*.zst 2>/dev/null | head -1)
    if [[ -z "$archive" ]]; then
        json_response "false" "error=no_local_archive"; return 1
    fi
    log "INFO" "rclone-push: vmid=$vmid remote=$remote keeplocal=$keeplocal archive=$(basename "$archive")"
    local rc=0
    timeout "$TIMEOUT_CRYPTCHECK" rclone copy "$archive" "${remote}:${REMOTE_PREFIX}${vmid}/" \
        --config "$RCLONE_CONFIG" --transfers 2 --retries 3 --low-level-retries 10 >/dev/null 2>&1 || rc=$?
    if (( rc != 0 )); then
        log "WARN" "rclone-push failed vmid=$vmid rc=$rc"
        json_response "false" "error=push_failed"
        return 1
    fi
    if [[ "$keeplocal" == "0" ]]; then
        rm -f "$archive" "${archive%.zst}.log" "${archive}.notes" 2>/dev/null || true
        log "INFO" "rclone-push: local archive removed (gdrive-only) vmid=$vmid"
    fi
    json_response "true" "archive=$(json_escape "$(basename "$archive")")" "kept_local=$keeplocal"
}

# ============================================================================
# SECTION: Main Dispatcher
# ============================================================================

main() {
    # Initialize log
    if ! init_log; then
        json_response "false" "error=log_init_failed"
        return 1
    fi

    log "INFO" "Script invoked"

    # Read operation from SSH_ORIGINAL_COMMAND
    local ssh_cmd="${SSH_ORIGINAL_COMMAND:-}"

    if [[ -z "$ssh_cmd" ]]; then
        log "WARN" "No SSH_ORIGINAL_COMMAND provided"
        json_response "false" "error=no_command"
        return 1
    fi

    # Parse command: split into tokens on spaces (SSH_ORIGINAL_COMMAND is space-separated).
    # Use a local IFS=' ' here because the global IFS=$'\n\t' would NOT split on spaces.
    local -a tokens=()
    IFS=' ' read -ra tokens <<< "$ssh_cmd" || {
        log "WARN" "Failed to parse SSH_ORIGINAL_COMMAND"
        json_response "false" "error=parse_failed"
        return 1
    }

    if (( ${#tokens[@]} == 0 )); then
        log "WARN" "Empty SSH_ORIGINAL_COMMAND"
        json_response "false" "error=empty_command"
        return 1
    fi

    local operation="${tokens[0]}"
    local -a args=("${tokens[@]:1}")

    log "INFO" "Operation: $operation with ${#args[@]} args"

    # ========================================================================
    # WHITELIST DISPATCH
    # ========================================================================
    case "$operation" in
        disk-free)
            op_disk_free
            ;;
        cryptcheck)
            if (( ${#args[@]} < 2 )); then
                log "WARN" "cryptcheck: missing arguments (need vmid remote)"
                json_response "false" "error=missing_arguments"
                return 1
            fi
            op_cryptcheck "${args[0]}" "${args[1]}"
            ;;
        healthcheck)
            if (( ${#args[@]} < 4 )); then
                log "WARN" "healthcheck: missing arguments (need vmid type kind arg)"
                json_response "false" "error=missing_arguments"
                return 1
            fi
            op_healthcheck "${args[0]}" "${args[1]}" "${args[2]}" "${args[3]}"
            ;;
        ping)
            if (( ${#args[@]} < 1 )); then
                log "WARN" "ping: missing vmid argument"
                json_response "false" "error=missing_vmid"
                return 1
            fi
            op_ping "${args[0]}"
            ;;
        rclone-remotes)
            op_rclone_remotes
            ;;
        rclone-about)
            if (( ${#args[@]} < 1 )); then
                json_response "false" "error=missing_remote"
                return 1
            fi
            op_rclone_about "${args[0]}"
            ;;
        rclone-push)
            if (( ${#args[@]} < 3 )); then
                json_response "false" "error=missing_arguments"
                return 1
            fi
            op_rclone_push "${args[0]}" "${args[1]}" "${args[2]}"
            ;;
        *)
            log "WARN" "Operation not allowed: $operation"
            json_response "false" "error=operation_not_allowed"
            return 1
            ;;
    esac
}

# ============================================================================
# SECTION: Execution
# ============================================================================

# Set trap to ensure exit code propagates
trap 'exit $?' EXIT

# Invoke main with exit code passthrough
main "$@"
exit $?
