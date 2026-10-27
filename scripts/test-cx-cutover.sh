#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
CUTOVER_SCRIPT="$SCRIPT_DIR/cx-cutover.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

pass=0
fail=0

fail_test() {
  printf 'FAIL: %s\n' "$1" >&2
  fail=$((fail + 1))
}
pass_test() {
  printf 'PASS: %s\n' "$1"
  pass=$((pass + 1))
}

setup_fixture() {
  local name=$1
  ROOT="$TMP/$name"
  mkdir -p "$ROOT/home/.config/systemd/user" "$ROOT/repo/.local-dashboard/migration/cutover" "$ROOT/bin" "$ROOT/state"
  touch "$ROOT/.cx-cutover-test-root"
  printf 'synthetic executable fixture\n' > "$ROOT/repo/.local-dashboard/migration/cli-proxy-api"
  chmod 700 "$ROOT/repo/.local-dashboard/migration/cli-proxy-api"
  sha256sum "$ROOT/repo/.local-dashboard/migration/cli-proxy-api" | awk '{print $1}' > "$ROOT/repo/.local-dashboard/migration/cutover/build.sha256"
  cat > "$ROOT/repo/.local-dashboard/migration/cutover/cx-cutover.yaml" <<CONFIG
host: ""
port: 8317
cx-compatibility:
  enabled: true
  source-home: "$ROOT/home"
  protected-listeners: true
  keyless: true
CONFIG
  chmod 600 "$ROOT/repo/.local-dashboard/migration/cutover/cx-cutover.yaml"
  local config_hash
  config_hash=$(sha256sum "$ROOT/repo/.local-dashboard/migration/cutover/cx-cutover.yaml" | awk '{print $1}')
  build_hash=$(cat "$ROOT/repo/.local-dashboard/migration/cutover/build.sha256")
  cat > "$ROOT/repo/.local-dashboard/migration/cutover/READY" <<READY
CX_CUTOVER_READY=1
PARITY_GATES=complete
BUILD_SHA256=$build_hash
CONFIG_SHA256=$config_hash
READY
  chmod 600 "$ROOT/repo/.local-dashboard/migration/cutover/READY"
  cat > "$ROOT/home/.config/systemd/user/cx-proxy.service" <<'UNIT'
[Unit]
Description=CX Codex account proxy
[Service]
ExecStart=/fixture/cx-proxy --port 8317
UNIT
  cat > "$ROOT/home/.config/systemd/user/cliproxy-dashboard.service" <<'UNIT'
[Unit]
Description=Existing dashboard
[Service]
ExecStart=/fixture/dashboard --config /fixture/dashboard.yaml
UNIT
  cat > "$ROOT/home/.config/systemd/user/cx-auto-switch.timer" <<'UNIT'
[Unit]
Description=Existing account watcher timer
[Timer]
Unit=cx-auto-switch.service
UNIT
  printf 'active\n' > "$ROOT/state/cx-proxy.service"
  printf 'active\n' > "$ROOT/state/cliproxy-dashboard.service"
  printf 'active\n' > "$ROOT/state/cx-auto-switch.timer"
  printf 'inactive\n' > "$ROOT/state/cliproxy-cx.service"
  printf 'active\n' > "$ROOT/state/http-8317"
  printf 'active\n' > "$ROOT/state/http-8318"
  printf '127.0.0.1:8317\n100.64.0.1:8317\n127.0.0.1:8318\n100.64.0.1:8318\n' > "$ROOT/state/listeners"
  mkdir -p "$ROOT/home/.codex-accounts"
  printf '{"fixture":"account data"}\n' > "$ROOT/home/.codex-accounts/accounts.json"
  chmod 600 "$ROOT/home/.codex-accounts/accounts.json"
  cat > "$ROOT/bin/systemctl" <<'SYSTEMCTL'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\n' "$*" >> "$CX_TEST_ROOT/state/systemctl.log"
command=${1:?}
shift
case "$command" in
  --user) command=${1:?}; shift ;;
esac
case "$command" in
  show)
    unit=${*: -1}
    printf 'ActiveState=%s\n' "$(cat "$CX_TEST_ROOT/state/$unit" 2>/dev/null || printf unknown)"
    ;;
  is-active)
    unit=${*: -1}
    state=$(cat "$CX_TEST_ROOT/state/$unit" 2>/dev/null || printf inactive)
    [[ $state == active ]] && exit 0 || exit 3
    ;;
  stop)
    unit=${*: -1}
    printf 'inactive\n' > "$CX_TEST_ROOT/state/$unit"
    ;;
  start)
    unit=${*: -1}
    if [[ $unit == cliproxy-cx.service && -f $CX_TEST_ROOT/state/fail-new-start ]]; then
      exit 1
    fi
    printf 'active\n' > "$CX_TEST_ROOT/state/$unit"
    if [[ $unit == cx-proxy.service ]]; then printf 'active\n' > "$CX_TEST_ROOT/state/http-8317"; fi
    if [[ $unit == cliproxy-cx.service && -f $CX_TEST_ROOT/state/replacement-unhealthy ]]; then printf 'failed\n' > "$CX_TEST_ROOT/state/http-8317"; fi
    ;;
  daemon-reload) : ;;
  *) echo "unsupported fixture systemctl verb: $command" >&2; exit 2 ;;
esac
SYSTEMCTL
  chmod 700 "$ROOT/bin/systemctl"
  export ROOT
}

run_cutover() {
  CX_TEST_ROOT="$ROOT" "$CUTOVER_SCRIPT" --test-root "$ROOT" "$@"
}

setup_fixture success
: > "$ROOT/home/.config/systemd/user/cx-proxy.service.dummy" 2>/dev/null || true
if run_cutover --apply >"$ROOT/out" 2>&1; then
  [[ $(cat "$ROOT/state/cx-proxy.service") == inactive && $(cat "$ROOT/state/cliproxy-cx.service") == active ]] && pass_test 'apply switches isolated CX to replacement' || fail_test 'apply final service state'
  grep -q '^stop cx-proxy.service$' "$ROOT/state/systemctl.log" && ! grep -Eq 'stop (cliproxy-dashboard|cx-auto-switch)' "$ROOT/state/systemctl.log" && pass_test 'apply stops only CX and preserves dashboard/watcher' || fail_test 'apply service isolation'
  cmp -s "$ROOT/home/.codex-accounts/accounts.json" <(printf '{"fixture":"account data"}\n') && pass_test 'account data remains byte-identical' || fail_test 'account data changed'
else
  cat "$ROOT/out" >&2
  fail_test 'apply isolated fixture'
fi

setup_fixture preflight
printf '0.0.0.0:8317\n' > "$ROOT/state/listeners"
if run_cutover --apply >"$ROOT/out" 2>&1; then
  fail_test 'public wildcard listener was accepted'
else
  [[ $(cat "$ROOT/state/cx-proxy.service") == active ]] && ! grep -q '^stop cx-proxy.service$' "$ROOT/state/systemctl.log" && pass_test 'preflight failure leaves CX running' || fail_test 'preflight failure changed CX state'
fi

setup_fixture no-ready
rm "$ROOT/repo/.local-dashboard/migration/cutover/READY"
if run_cutover --apply >"$ROOT/out" 2>&1; then
  fail_test 'missing parent READY evidence was accepted'
else
  [[ $(cat "$ROOT/state/cx-proxy.service") == active ]] && ! grep -q '^stop cx-proxy.service$' "$ROOT/state/systemctl.log" && pass_test 'missing READY evidence blocks cutover before CX stop' || fail_test 'missing READY changed CX state'
fi

setup_fixture checksum-mismatch
printf '%064d\\n' 0 > "$ROOT/repo/.local-dashboard/migration/cutover/build.sha256"
if run_cutover --apply >"$ROOT/out" 2>&1; then
  fail_test 'modified artifact checksum was accepted'
else
  [[ $(cat "$ROOT/state/cx-proxy.service") == active ]] && ! grep -q '^stop cx-proxy.service$' "$ROOT/state/systemctl.log" && pass_test 'checksum mismatch blocks before CX stop' || fail_test 'checksum mismatch changed CX state'
fi

setup_fixture start-failure
touch "$ROOT/state/fail-new-start"
if run_cutover --apply >"$ROOT/out" 2>&1; then
  fail_test 'replacement start failure reported success'
else
  [[ $(cat "$ROOT/state/cx-proxy.service") == active && $(cat "$ROOT/state/cliproxy-cx.service") == inactive ]] && pass_test 'failed replacement start restores old CX' || fail_test 'failed start did not restore CX'
fi

setup_fixture health-failure
touch "$ROOT/state/replacement-unhealthy"
if run_cutover --apply >"$ROOT/out" 2>&1; then
  fail_test 'replacement health failure was accepted'
else
  [[ $(cat "$ROOT/state/cx-proxy.service") == active && $(cat "$ROOT/state/cliproxy-cx.service") == inactive && ! -e $ROOT/home/.config/systemd/user/cliproxy-cx.service ]] && pass_test 'post-start readiness failure traps back to CX and removes staged unit' || fail_test 'post-start readiness failure did not restore CX'
fi

setup_fixture rollback
if run_cutover --apply >/dev/null 2>&1 && run_cutover --rollback >/dev/null 2>&1 && run_cutover --rollback >/dev/null 2>&1; then
  [[ $(cat "$ROOT/state/cx-proxy.service") == active && $(cat "$ROOT/state/cliproxy-cx.service") == inactive ]] && pass_test 'rollback is repeatable and idempotent' || fail_test 'rollback state incorrect'
  cmp -s "$ROOT/home/.codex-accounts/accounts.json" <(printf '{"fixture":"account data"}\n') && pass_test 'rollback leaves account data byte-identical' || fail_test 'rollback changed account data'
else
  fail_test 'rollback invocation'
fi

setup_fixture unchanged
if run_cutover --apply >/dev/null 2>&1; then
  [[ $(cat "$ROOT/state/cliproxy-dashboard.service") == active && $(cat "$ROOT/state/cx-auto-switch.timer") == active ]] && pass_test 'dashboard and watcher timer remain active' || fail_test 'dashboard or watcher changed'
else
  fail_test 'isolated apply for unchanged-service assertions'
fi

printf '\n%d passed, %d failed\n' "$pass" "$fail"
(( fail == 0 ))
