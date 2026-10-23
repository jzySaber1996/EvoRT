#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

HOST="${HOST:-0.0.0.0}"
PORT="${PORT:-5001}"
PYTHON_BIN="${PYTHON_BIN:-python3}"
OLLAMA_MODEL="${OLLAMA_MODEL:-llama3:8b}"
START_OLLAMA="${START_OLLAMA:-1}"
CHECK_MODEL="${CHECK_MODEL:-1}"
INSTALL_DEPS="${INSTALL_DEPS:-0}"
OLLAMA_LOG="${OLLAMA_LOG:-$ROOT_DIR/chain_data/ollama.log}"

export ASB_ROOT="${ASB_ROOT:-$ROOT_DIR/../ASB}"
export ASB_PYTHON="${ASB_PYTHON:-/root/miniconda3/envs/ASB/bin/python}"
export ASB_MODEL="${ASB_MODEL:-ollama/$OLLAMA_MODEL}"
export ASB_MODEL_OPTIONS="${ASB_MODEL_OPTIONS:-$ASB_MODEL}"
export FLASK_APP="${FLASK_APP:-app.py}"
export DEEPSEEK_MODEL="${DEEPSEEK_MODEL:-deepseek-chat}"
# Optional: export DEEPSEEK_API_KEY before running, or fill config.py.

log() {
  printf '[AgentSecuritySAT] %s\n' "$*"
}

warn() {
  printf '[AgentSecuritySAT] WARN: %s\n' "$*" >&2
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    warn "Missing command: $1"
    return 1
  fi
}

if [[ "$INSTALL_DEPS" == "1" ]]; then
  log "Installing Web dependencies with $PYTHON_BIN -m pip install -r requirements.txt"
  "$PYTHON_BIN" -m pip install -r requirements.txt
fi

if [[ ! -d "$ASB_ROOT" ]]; then
  warn "ASB_ROOT does not exist: $ASB_ROOT"
  warn "ASB pages will not work until ASB_ROOT is set correctly."
fi

if [[ ! -x "$ASB_PYTHON" ]]; then
  warn "ASB_PYTHON is not executable: $ASB_PYTHON"
  warn "Set ASB_PYTHON=/path/to/asb/python if you use another environment."
fi

if [[ "$START_OLLAMA" == "1" ]]; then
  if need_cmd ollama; then
    if ollama list >/dev/null 2>&1; then
      log "Ollama is already reachable."
    else
      log "Starting Ollama in background. Log: $OLLAMA_LOG"
      mkdir -p "$(dirname "$OLLAMA_LOG")"
      nohup ollama serve >"$OLLAMA_LOG" 2>&1 &
      sleep 2
      if ! ollama list >/dev/null 2>&1; then
        warn "Ollama did not become reachable. Check $OLLAMA_LOG"
      fi
    fi

    if [[ "$CHECK_MODEL" == "1" ]] && ollama list >/dev/null 2>&1; then
      if ! ollama list | awk 'NR > 1 {print $1}' | grep -Fxq "$OLLAMA_MODEL"; then
        warn "Ollama model '$OLLAMA_MODEL' is not installed. Run: ollama pull $OLLAMA_MODEL"
      fi
    fi
  else
    warn "Skipping Ollama startup. Install Ollama or run with START_OLLAMA=0."
  fi
else
  log "Skipping Ollama startup because START_OLLAMA=0."
fi

log "ASB_ROOT=$ASB_ROOT"
log "ASB_PYTHON=$ASB_PYTHON"
log "ASB_MODEL=$ASB_MODEL"
log "DEEPSEEK_MODEL=$DEEPSEEK_MODEL"
if [[ -n "${DEEPSEEK_API_KEY:-}" ]]; then
  log "DEEPSEEK_API_KEY is configured from environment."
else
  log "DEEPSEEK_API_KEY is empty; DeepSeek UI switch will fall back to local SMT rules unless config.py provides a key."
fi
log "Starting Flask app at http://$HOST:$PORT"

exec "$PYTHON_BIN" - <<PY
from app import app
app.run(debug=True, host="$HOST", port=int("$PORT"))
PY
