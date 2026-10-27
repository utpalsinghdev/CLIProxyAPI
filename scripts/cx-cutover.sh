#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'USAGE'
Usage:
  cx-cutover.sh                         # safe preflight/dry-run only
  cx-cutover.sh --dry-run               # safe preflight/dry-run only
  cx-cutover.sh --apply                 # manual, guarded cutover
  cx-cutover.sh --rollback              # restore CX and stop replacement
  cx-cutover.sh --test-root DIR --apply|--rollback  # isolated fixture only; internal test interface
USAGE
}

fail() { printf 'cx-cutover: %s\n' "$*" >&2; exit 1; }

mode=dry-run
test_root=
while (($#)); do
  case "$1" in
    --dry-run) mode=dry-run; shift ;;
    --apply) mode=apply; shift ;;
    --rollback) mode=rollback; shift ;;
    --test-root)
      (($# >= 2)) || fail '--test-root requires fixture directory'
      [[ -z $test_root ]] || fail '--test-root may be specified once'
      test_root=$2
      shift 2
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; fail "unknown argument: $1" ;;
  esac
done

if [[ -n $test_root ]]; then
  [[ -f $test_root/.cx-cutover-test-root ]] || fail 'test root marker missing'
  [[ -x $test_root/bin/systemctl ]] || fail 'fixture systemctl shim missing'
  export CX_TEST_ROOT=$test_root
  systemctl_cmd=("$test_root/bin/systemctl")
  home="$test_root/home"
  repo="$test_root/repo"
  state="$test_root/state"
  unit_dir="$home/.config/systemd/user"
  config="$repo/.local-dashboard/migration/cutover/cx-cutover.yaml"
  artifact="$repo/.local-dashboard/migration/cli-proxy-api"
  evidence_dir="$repo/.local-dashboard/migration/cutover"
  test_mode=1
else
  systemctl_cmd=(systemctl --user)
  home=${HOME:?HOME is not set}
  repo=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
  unit_dir="$home/.config/systemd/user"
  evidence_dir="$repo/.local-dashboard/migration/cutover"
  config="$evidence_dir/cx-cutover.yaml"
  artifact="$repo/.local-dashboard/migration/cli-proxy-api"
  state="$evidence_dir/state"
  test_mode=0
  [[ -z ${CX_TEST_ROOT:-} ]] || fail 'CX_TEST_ROOT is fixture-only and cannot affect production mode'
fi

old_unit="$unit_dir/cx-proxy.service"
dashboard_unit="$unit_dir/cliproxy-dashboard.service"
watcher_timer="$unit_dir/cx-auto-switch.timer"
new_unit="$unit_dir/cliproxy-cx.service"
ready="$evidence_dir/READY"
build_hash_file="$evidence_dir/build.sha256"

unit_exec_line() { sed -n '/^ExecStart=/p' "$1" 2>/dev/null | head -n 1; }
unit_active() { "${systemctl_cmd[@]}" is-active "$1" >/dev/null 2>&1; }

check_config() {
  [[ -f $config && ! -L $config ]] || fail "prepared cutover config missing or symlinked: $config"
  local mode_bits
  mode_bits=$(stat -c '%a' "$config" 2>/dev/null || stat -f '%Lp' "$config")
  (( (8#$mode_bits & 077) == 0 )) || fail 'prepared config must be owner-only (mode 600 or stricter)'
  grep -Eq '^port:[[:space:]]*8317[[:space:]]*$' "$config" || fail 'prepared config must use port 8317'
  grep -Eq '^cx-compatibility:[[:space:]]*$' "$config" || fail 'CX compatibility block missing'
  grep -Eq '^  enabled:[[:space:]]*true[[:space:]]*$' "$config" || fail 'CX compatibility must be enabled'
  grep -Eq '^  protected-listeners:[[:space:]]*true[[:space:]]*$' "$config" || fail 'protected-listeners must be enabled'
  grep -Eq '^  keyless:[[:space:]]*true[[:space:]]*$' "$config" || fail 'CX keyless compatibility must be enabled'
  grep -Fqx "  source-home: \"$home\"" "$config" || fail 'source-home must point at the home root containing the canonical CX account store'
  [[ -d $home/.codex-accounts ]] || fail 'canonical CX account store directory missing'
  grep -Eq '^host:[[:space:]]*(""|'"''"'|)$' "$config" || fail 'host setting must be empty; listener safety is enforced by protected listeners and address checks'
}

check_evidence() {
  [[ -f $artifact && -x $artifact && ! -L $artifact ]] || fail 'replacement executable missing, non-executable, or symlinked'
  [[ -f $build_hash_file && ! -L $build_hash_file ]] || fail 'preverified build checksum missing'
  [[ -f $ready && ! -L $ready ]] || fail 'parent-owned READY evidence missing; parity gates are not complete'
  local ready_mode
  ready_mode=$(stat -c '%a' "$ready" 2>/dev/null || stat -f '%Lp' "$ready")
  (( (8#$ready_mode & 077) == 0 )) || fail 'READY evidence must be owner-only'
  local expected actual config_hash ready_build ready_config
  expected=$(tr -d '[:space:]' < "$build_hash_file")
  [[ $expected =~ ^[a-fA-F0-9]{64}$ ]] || fail 'build checksum file must contain one SHA-256 digest'
  actual=$(sha256sum "$artifact" | awk '{print $1}')
  [[ $actual == "$expected" ]] || fail 'replacement executable checksum differs from preverified build'
  config_hash=$(sha256sum "$config" | awk '{print $1}')
  grep -Fxq 'CX_CUTOVER_READY=1' "$ready" || fail 'READY evidence is not approved'
  grep -Fxq 'PARITY_GATES=complete' "$ready" || fail 'READY evidence does not mark all parity gates complete'
  ready_build=$(sed -n 's/^BUILD_SHA256=//p' "$ready" | head -n 1)
  ready_config=$(sed -n 's/^CONFIG_SHA256=//p' "$ready" | head -n 1)
  [[ $ready_build == "$actual" ]] || fail 'READY evidence does not match replacement executable checksum'
  [[ $ready_config == "$config_hash" ]] || fail 'READY evidence does not match prepared config checksum'
}

check_unit_identity() {
  [[ -f $old_unit && ! -L $old_unit ]] || fail 'expected cx-proxy.service file missing'
  [[ $(unit_exec_line "$old_unit") == *'codex-accounts/dist/index.js" "proxy" "--foreground" "--port" "8317'* ||
    $(unit_exec_line "$old_unit") == *'cx-proxy --port 8317'* ]] || fail 'cx-proxy.service identity does not match expected CX process on 8317'
  [[ -f $dashboard_unit && ! -L $dashboard_unit ]] || fail 'dashboard unit missing'
  [[ $(unit_exec_line "$dashboard_unit") == *'cli-proxy-api'* || $(unit_exec_line "$dashboard_unit") == *'dashboard'* ]] || fail 'dashboard unit identity is unexpected'
  [[ -f $watcher_timer && ! -L $watcher_timer ]] || fail 'CX account watcher timer unit missing'
  unit_active cx-proxy.service || fail 'cx-proxy.service must be active before cutover'
  unit_active cliproxy-dashboard.service || fail 'dashboard service must be active before cutover'
  unit_active cx-auto-switch.timer || fail 'CX watcher timer must be active before cutover'
}

check_http_and_ports() {
  if ((test_mode)); then
    [[ $(cat "$state/http-8317" 2>/dev/null || true) == active ]] || fail 'CX /health fixture check failed'
    [[ $(cat "$state/http-8318" 2>/dev/null || true) == active ]] || fail 'dashboard HTTP fixture check failed'
    local endpoints
    endpoints=$(cat "$state/listeners" 2>/dev/null || true)
    grep -Eq '(^|[[:space:]])(127\.0\.0\.1|\[::1\]|100\.64\.[0-9.]+):8317$' <<<"$endpoints" || fail '8317 fixture has no protected local listener'
    if grep -Eq '(^|[[:space:]])(0\.0\.0\.0|\*|\[::\]):831[78]$' <<<"$endpoints"; then fail 'wildcard listener detected'; fi
    grep -q ':8318$' <<<"$endpoints" || fail 'dashboard listener fixture missing'
    return
  fi
  command -v curl >/dev/null || fail 'curl is required for non-generating readiness checks'
  command -v ss >/dev/null || fail 'ss is required to verify listener addresses'
  curl --silent --show-error --fail --max-time 4 http://127.0.0.1:8317/health >/dev/null || fail 'CX /health check failed on loopback'
  local tailscale_ip
  tailscale_ip=$(ip -o -4 addr show dev tailscale0 2>/dev/null | awk 'NR == 1 {sub(/\/.*/, "", $4); print $4}')
  [[ -n $tailscale_ip ]] || fail 'Tailscale IPv4 address unavailable for dashboard readiness check'
  curl --silent --show-error --fail --max-time 4 "http://$tailscale_ip:8318/management.html" >/dev/null || fail 'dashboard HTTP check failed on its protected Tailscale address'
  local listeners
  listeners=$(ss -H -ltn '( sport = :8317 or sport = :8318 )' | awk '{print $4}')
  grep -Eq '^(127\.0\.0\.1|\[::1\]|100\.64\.[0-9.]+):8317$' <<<"$listeners" || fail 'no protected local listener found on 8317'
  if grep -Eq '^(0\.0\.0\.0|\*|\[::\]):831[78]$' <<<"$listeners"; then fail 'wildcard listener detected on 8317/8318'; fi
  grep -Eq ':(8318)$' <<<"$listeners" || fail 'dashboard listener missing on 8318'
}

check_unchanged_services() {
  unit_active cliproxy-dashboard.service || fail 'dashboard service is not active'
  unit_active cx-auto-switch.timer || fail 'CX watcher timer is not active'
}

restore_old_cx() {
  "${systemctl_cmd[@]}" stop cliproxy-cx.service >/dev/null 2>&1 || true
  if ! unit_active cx-proxy.service; then "${systemctl_cmd[@]}" start cx-proxy.service >/dev/null 2>&1 || true; fi
  if ! unit_active cx-proxy.service || ! check_http_and_ports; then
    printf 'cx-cutover: automatic CX restoration could not be verified; run --rollback and inspect service state.\n' >&2
    return 1
  fi
  remove_owned_unit || return 1
  rm -f -- "$evidence_dir/active-cutover"
  "${systemctl_cmd[@]}" daemon-reload >/dev/null 2>&1 || true
}

preflight() {
  check_config
  check_unit_identity
  check_http_and_ports
  if [[ $mode == apply ]]; then check_evidence; fi
  [[ ! -e $new_unit ]] || fail 'cliproxy-cx.service already exists; refusing to overwrite an unowned unit'
  printf 'Preflight passed: CX 8317, dashboard 8318, watcher active; protected listeners only.\n'
  if [[ $mode == dry-run ]]; then
    if [[ ! -f $ready ]]; then
      printf 'Apply blocked: parent parity gates must complete and provide READY plus matching checksums.\n'
    else
      printf 'Dry run only. No unit files or services changed.\n'
    fi
  fi
}

write_new_unit() {
  local tmp="$new_unit.tmp.$$"
  umask 077
  {
    printf '[Unit]\nDescription=CLIProxyAPI CX replacement\nAfter=network-online.target\nWants=network-online.target\n\n'
    printf '[Service]\nType=simple\nWorkingDirectory=%s\nExecStart=%s --config %s\nRestart=on-failure\n\n' "$repo" "$artifact" "$config"
    printf '[Install]\nWantedBy=default.target\n'
  } > "$tmp"
  chmod 600 "$tmp"
  mv -- "$tmp" "$new_unit"
}

remove_owned_unit() {
  [[ -e $new_unit ]] || return 0
  [[ -f $new_unit && ! -L $new_unit ]] || fail 'replacement unit path is not a regular file'
  grep -Fxq 'Description=CLIProxyAPI CX replacement' "$new_unit" || fail 'refusing to remove unowned cliproxy-cx.service'
  rm -- "$new_unit"
}

apply_cutover() {
  preflight
  mkdir -p "$evidence_dir"
  chmod 700 "$evidence_dir"
  local transaction="$evidence_dir/active-cutover"
  [[ ! -e $transaction ]] || fail 'cutover transaction record already exists; rollback or inspect it first'
  write_new_unit
  printf 'CX_CUTOVER_ACTIVE=1\n' > "$transaction"
  chmod 600 "$transaction"
  "${systemctl_cmd[@]}" daemon-reload
  if ! "${systemctl_cmd[@]}" stop cx-proxy.service; then
    remove_owned_unit
    rm -f -- "$transaction"
    "${systemctl_cmd[@]}" daemon-reload >/dev/null 2>&1 || true
    fail 'could not stop CX; replacement not started'
  fi
  if ! "${systemctl_cmd[@]}" start cliproxy-cx.service; then
    restore_old_cx || true
    fail 'replacement start failed; old CX restoration attempted and health checked'
  fi
  local recovery_needed=1
  recover_apply() {
    (( recovery_needed )) || return 0
    restore_old_cx
    recovery_needed=0
  }
  trap recover_apply EXIT
  check_http_and_ports || fail 'replacement readiness or protected-listener check failed after start'
  check_unchanged_services
  recovery_needed=0
  trap - EXIT
  printf 'Cutover complete: replacement active on 8317; CX stopped; dashboard 8318 and watcher unchanged.\n'
  printf 'CX account-management CLI and watcher intentionally remain installed and active.\n'
}

rollback_cutover() {
  if ! unit_active cliproxy-cx.service && unit_active cx-proxy.service; then
    check_http_and_ports || fail 'CX is active but rollback readiness is not healthy'
    check_unchanged_services
    printf 'Rollback already complete: CX active, replacement inactive.\n'
    return 0
  fi
  [[ -f $evidence_dir/active-cutover && -f $new_unit ]] || fail 'no owned cutover transaction to roll back'
  grep -Fxq 'Description=CLIProxyAPI CX replacement' "$new_unit" || fail 'refusing to stop an unowned replacement unit'
  unit_active cliproxy-dashboard.service || fail 'dashboard service must remain active during rollback'
  unit_active cx-auto-switch.timer || fail 'CX watcher timer must remain active during rollback'
  if unit_active cliproxy-cx.service; then "${systemctl_cmd[@]}" stop cliproxy-cx.service; fi
  if ! unit_active cx-proxy.service; then "${systemctl_cmd[@]}" start cx-proxy.service || fail 'CX restart failed; replacement remains stopped'
  fi
  check_http_and_ports || fail 'CX rollback readiness or protected-listener check failed'
  check_unchanged_services
  printf 'Rollback complete: CX active on 8317; replacement stopped. Dashboard and watcher unchanged.\n'
}

case "$mode" in
  dry-run) preflight ;;
  apply) apply_cutover ;;
  rollback) rollback_cutover ;;
esac
