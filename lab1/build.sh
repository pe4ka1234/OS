set -euo pipefail

APP=lab1d
SRC=src/main.cpp
OUT=build/$APP
PID=/tmp/$APP.pid

CXX="${CXX:-g++}"
CXXFLAGS="-std=gnu++17 -O2 -Wall -Wextra -Werror -pthread"

msg(){ echo "[${APP}] $*"; }

build() {
  mkdir -p build
  msg "compile -> $OUT"
  if ! $CXX $CXXFLAGS "$SRC" -o "$OUT"; then
    msg "retry with -lstdc++fs"
    $CXX $CXXFLAGS "$SRC" -o "$OUT" -lstdc++fs
  fi
  msg "ok"
}

run() {
  local conf="${1:-lab1.conf}"
  [[ -x "$OUT" ]] || build
  msg "start with config: $conf"
  "$OUT" "$conf" || true
  sleep 0.2
  if [[ -f "$PID" ]]; then
    msg "running, pid=$(cat "$PID")"
  else
    msg "started (pidfile not found yet — проверяй syslog)"
  fi
}

stop() {
  if [[ ! -f "$PID" ]]; then
    msg "not running (no pidfile)"; return 0
  fi
  local p; p=$(cat "$PID" 2>/dev/null || true)
  if [[ -z "${p:-}" || ! -d "/proc/$p" ]]; then
    msg "stale pidfile -> remove"; rm -f "$PID"; return 0
  fi
  msg "SIGTERM $p"; kill -TERM "$p" || true
  for i in {1..50}; do [[ -d "/proc/$p" ]] || break; sleep 0.1; done
  [[ -d "/proc/$p" ]] && { msg "SIGKILL $p"; kill -KILL "$p" || true; }
  rm -f "$PID"; msg "stopped"
}

status() {
  if [[ -f "$PID" ]]; then
    local p; p=$(cat "$PID" 2>/dev/null || true)
    [[ -n "$p" && -d "/proc/$p" ]] && echo "RUNNING (pid $p)" || echo "NOT RUNNING (stale pidfile)"
  else
    echo "NOT RUNNING"
  fi
}

clean() { rm -rf build; msg "cleaned"; }

usage() {
  cat <<EOF
usage: $0 {build|run [conf]|stop|status|clean}
EOF
}

cmd="${1:-usage}"; shift || true
case "$cmd" in
  build)  build;;
  run)    run "$@";;
  stop)   stop;;
  status) status;;
  clean)  clean;;
  *)      usage;;
esac
