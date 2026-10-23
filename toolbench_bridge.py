import json
import os
import subprocess
import sys
import uuid
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from flask import jsonify, request

from smt_rule_engine import normalize_smt_method


BASE_DIR = Path(__file__).resolve().parent
TOOLBENCH_ROOT = Path(os.environ.get("TOOLBENCH_ROOT", BASE_DIR.parent / "LLM_Tool_Learning")).resolve()


def _default_bench_query_file():
    benchmark_root = TOOLBENCH_ROOT / "benchmark"
    preferred = benchmark_root / "generated_asb_20q" / "asb_toolbench_queries.json"
    fallback = benchmark_root / "generated_asb" / "asb_toolbench_queries.json"
    return preferred if preferred.exists() else fallback


def _default_ir_index():
    benchmark_root = TOOLBENCH_ROOT / "benchmark"
    candidates = [
        benchmark_root / "generated_asb_20q" / "tool_ir_index.json",
        benchmark_root / "generated_asb" / "tool_ir_index.json",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[-1]


DEFAULT_BENCH_QUERY_FILE = Path(
    os.environ.get(
        "TOOLBENCH_QUERY_FILE",
        str(_default_bench_query_file()),
    )
).resolve()
DEFAULT_TOOL_ROOT = Path(os.environ.get("TOOLBENCH_TOOL_ROOT", TOOLBENCH_ROOT / "data" / "data" / "toolenv" / "tools")).resolve()
DEFAULT_IR_INDEX = Path(os.environ.get("TOOLBENCH_IR_INDEX", str(_default_ir_index()))).resolve()
DEFAULT_BENCH_METHOD = os.environ.get("TOOLBENCH_METHOD", "DFS_woFilter_w2")
BENCH_RUN_ROOT = BASE_DIR / "chain_data" / "bench_runs"
BENCH_JOBS = {}

DEFAULT_BENCH_PYTHON = os.environ.get(
    "TOOLBENCH_PYTHON",
    sys.executable,
)
DEFAULT_BENCH_MODEL = os.environ.get("TOOLBENCH_MODEL", "llama3:8b")
BENCH_MODEL_OPTIONS = [
    item.strip() for item in os.environ.get("TOOLBENCH_MODEL_OPTIONS", "llama3:8b,llama3.1:8b,llama3.2:3b").split(",") if item.strip()
]
if DEFAULT_BENCH_MODEL not in BENCH_MODEL_OPTIONS:
    BENCH_MODEL_OPTIONS.insert(0, DEFAULT_BENCH_MODEL)

GUARD_BLOCK_STATUS = 13


def _tail(path, max_chars=5000):
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    return text[-max_chars:]


def _bench_paths(job_id):
    run_dir = BENCH_RUN_ROOT / job_id
    output_dir = run_dir / "outputs"
    return {
        "run_dir": run_dir,
        "output_dir": output_dir,
        "log": run_dir / "run.log",
        "query_file": run_dir / "single_query.json",
        "trace": run_dir / "runtime_trace.jsonl",
    }


def _load_queries():
    return json.loads(DEFAULT_BENCH_QUERY_FILE.read_text(encoding="utf-8"))


def _group_queries_by_agent():
    grouped = {}
    for row in _load_queries():
        grouped.setdefault((row.get("asb_meta") or {}).get("agent_name", "unknown"), []).append(row)
    return grouped


@lru_cache(maxsize=1)
def _bench_runtime_status():
    cmd = [
        DEFAULT_BENCH_PYTHON,
        "-c",
        "import json,sys; out={'python_executable':sys.executable}\n"
        "try:\n"
        " import z3\n"
        " out.update({'z3_available':True,'z3_version':z3.get_version_string(),'z3_error':None})\n"
        "except Exception as exc:\n"
        " out.update({'z3_available':False,'z3_version':None,'z3_error':f'{type(exc).__name__}: {exc}'})\n"
        "print(json.dumps(out))",
    ]
    try:
        completed = subprocess.run(cmd, capture_output=True, text=True, check=False, timeout=10)
        if completed.returncode == 0 and completed.stdout.strip():
            return json.loads(completed.stdout.strip())
        return {
            "python_executable": DEFAULT_BENCH_PYTHON,
            "z3_available": False,
            "z3_version": None,
            "z3_error": completed.stderr.strip() or completed.stdout.strip() or f"returncode={completed.returncode}",
        }
    except Exception as exc:
        return {
            "python_executable": DEFAULT_BENCH_PYTHON,
            "z3_available": False,
            "z3_version": None,
            "z3_error": f"{type(exc).__name__}: {exc}",
        }


def _query_label(row):
    task_index = row.get("query_index") or (row.get("asb_meta") or {}).get("source_task_index") or "?"
    variant_index = row.get("query_variant") or (row.get("asb_meta") or {}).get("query_variant_index") or 1
    return f"Q{task_index}-V{variant_index}: {row.get('query', '')}"


def _deepcopy_row(row):
    return json.loads(json.dumps(row, ensure_ascii=False))


def _parse_query_id(path: Path, method: str):
    suffix = f"_{method}.json"
    if path.name.endswith(suffix):
        return path.name[:-len(suffix)]
    return path.stem


def _iter_nodes(node):
    yield node
    for child in node.get("children", []):
        yield from _iter_nodes(child)


def _extract_calls(result):
    root = result.get("tree", {}).get("tree", {})
    nodes = list(_iter_nodes(root))
    calls = []
    for node in nodes:
        if node.get("node_type") != "Action":
            continue
        action_input = next((child for child in node.get("children", []) if child.get("node_type") == "Action Input"), {})
        calls.append({
            "tool": node.get("description") or "",
            "action_input": action_input,
        })
    return calls


def _safe_json_loads(value):
    if isinstance(value, dict):
        return value
    if not isinstance(value, str) or not value.strip():
        return {}
    try:
        return json.loads(value)
    except Exception:
        return {}


def _load_runtime_trace(path: Path):
    events = []
    if not path.exists():
        return events
    with path.open("r", encoding="utf-8", errors="replace") as reader:
        for line in reader:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except Exception:
                continue
    return events


def _trace_event_to_call(event):
    raw_observation = event.get("raw_observation")
    if isinstance(raw_observation, (dict, list)):
        observation_value = json.dumps(raw_observation, ensure_ascii=False)
    elif raw_observation is None:
        observation_value = event.get("observation") or ""
    else:
        observation_value = str(raw_observation)
    return {
        "tool": event.get("tool") or "UnknownTool",
        "action_input": {
            "description": event.get("tool_input") or "",
            "observation": observation_value,
            "observation_code": event.get("observation_code"),
            "io_state": {
                "guard_trace": event.get("guard_trace") or [],
            },
        },
    }


def _available_tools_for_query(query_row):
    tools = []
    for item in query_row.get("api_list", []):
        name = item.get("api_name")
        category = item.get("category_name")
        if name:
            tools.append({"name": name, "description": category or ""})
    return tools


def _decision_formula(decision):
    facts = decision.get("facts") or {}
    true_facts = [name for name, value in facts.items() if name != "_ir_meta" and value is True][:10]
    false_facts = [name for name, value in facts.items() if name != "_ir_meta" and value is False][:4]
    logic = decision.get("logic") or ("QF_SLIA" if decision.get("smt_method") == "ir_hoare" else "QF_UF")
    lines = [
        f";; stage: {decision.get('stage')}",
        f";; tool: {decision.get('tool')}",
        f";; method: {decision.get('smt_method')}",
        f";; solver: {decision.get('solver')}",
        f"(set-logic {logic})",
    ]
    lines.extend(f"(assert {name})" for name in true_facts)
    lines.extend(f"(assert (not {name}))" for name in false_facts)
    active_conditions = decision.get("risk_conditions") or []
    lines.append(f";; active_conditions: {', '.join(active_conditions) if active_conditions else '-'}")
    lines.append("(assert runtime_risk)")
    lines.append("(check-sat)")
    return "\n".join(lines)


def _decision_to_rule(decision, rule_index):
    return {
        "id": f"BENCH-{rule_index}",
        "formula": _decision_formula(decision),
        "result": decision.get("result", "UNKNOWN"),
        "evidence": decision.get("evidence") or decision.get("z3_error") or "-",
        "solver_semantics": decision.get("solver_semantics"),
        "risk": bool(decision.get("risk")),
    }


def _build_bench_start_step(job):
    query_row = job["query_row"]
    meta = query_row.get("asb_meta") or {}
    return {
        "source": "BENCH",
        "tool_call": False,
        "agent": meta.get("agent_path") or meta.get("agent_name") or "Bench",
        "tool": "Bench Job Start",
        "desc": "启动 LLM_Tool_Learning Bench 单样本运行，等待工具链执行与SMT判定。",
        "check": "运行状态",
        "input": {
            "job_id": job["job_id"],
            "query_id": query_row.get("query_id"),
            "query": query_row.get("query"),
            "attack_tools": meta.get("attack_tools", []),
            "attack_types": meta.get("attack_types", []),
            "model": job["llm_name"],
            "smt_method": job.get("smt_method"),
        },
        "output": {
            "python_executable": DEFAULT_BENCH_PYTHON,
            "log_path": job["log_path"],
            "result_path": job["result_path"],
            "trace_path": job.get("trace_path"),
        },
        "path": {"event": "start", "rollback_mode": "smt_solver_guard" if job.get("smt_guard_enabled") else "none"},
        "sat": [],
    }


def _build_bench_rollback_step(blocked_step, last_safe_step):
    return {
        "source": "BENCH",
        "tool_call": False,
        "agent": blocked_step.get("agent"),
        "tool": "Rollback",
        "desc": f"SMT防护命中后，回滚到最近安全节点：{last_safe_step.get('tool')}",
        "check": "回滚",
        "input": {
            "rollbackTo": last_safe_step.get("tool"),
        },
        "output": {
            "from_tool": blocked_step.get("tool"),
            "to_tool": last_safe_step.get("tool"),
        },
        "path": {
            "event": "rollback",
            "rollback_target": last_safe_step.get("tool"),
            "rollback_to_index": (last_safe_step.get("path") or {}).get("index"),
            "rollback_mode": "smt_solver_guard",
        },
        "sat": [],
    }


def _build_bench_call_step(job, call_index, call, last_safe_step):
    query_row = job["query_row"]
    meta = query_row.get("asb_meta") or {}
    action_input = call.get("action_input") or {}
    observation_payload = _safe_json_loads(action_input.get("observation"))
    io_state = action_input.get("io_state") or {}
    guard_trace = io_state.get("guard_trace") or []
    decisions = [((item or {}).get("decision") or {}) for item in guard_trace if isinstance(item, dict)]
    called_tool = call.get("tool") or "UnknownTool"
    if decisions and decisions[-1].get("tool"):
        called_tool = decisions[-1].get("tool")
    actual_called_tool = observation_payload.get("actual_called_tool") or observation_payload.get("called_tool") or called_tool
    sat_rules = [_decision_to_rule(decision, idx + 1) for idx, decision in enumerate(decisions)]
    sat_decisions = [decision for decision in decisions if decision.get("result") == "SAT"]
    blocked_here = action_input.get("observation_code") == GUARD_BLOCK_STATUS
    pre_sat = any(decision.get("result") == "SAT" and decision.get("stage") == "pre" for decision in decisions)
    post_sat = any(decision.get("result") == "SAT" and decision.get("stage") == "post" for decision in decisions)

    if blocked_here and pre_sat:
        check = "高风险：SMT执行前阻断"
    elif blocked_here and post_sat:
        check = "高风险：SMT执行后回滚"
    elif sat_decisions:
        check = "高风险：SAT风险命中"
    elif action_input.get("observation_code") not in (None, 0, 3):
        check = "执行异常"
    else:
        check = "执行通过"

    path = {
        "event": "blocked" if blocked_here else "tool_call",
        "rollback_mode": "smt_solver_guard" if blocked_here else "none",
        "rollback_target": (last_safe_step.get("tool") if blocked_here and last_safe_step else None),
        "rollback_to_index": ((last_safe_step.get("path") or {}).get("index") if blocked_here and last_safe_step else None),
        "index": call_index + 1,
    }

    return {
        "source": "BENCH",
        "tool_call": True,
        "agent": meta.get("agent_path") or meta.get("agent_name") or "Bench",
        "tool": called_tool,
        "desc": f"Bench 第 {call_index + 1} 步工具调用：{called_tool}",
        "check": check,
        "input": {
            "query_id": query_row.get("query_id"),
            "query": query_row.get("query"),
            "step": call_index + 1,
            "step_goal": query_row.get("query"),
            "attack_tool": (meta.get("attack_tools") or [None])[0],
            "injected_target_tool": (meta.get("attack_tools") or [None])[0],
            "selected_attack_tools": meta.get("attack_tools") or [],
            "attack_type": (meta.get("attack_types") or [None])[0],
            "available_tools": _available_tools_for_query(query_row),
        },
        "output": {
            "called_tool": called_tool,
            "actual_called_tool": actual_called_tool,
            "parameters": action_input.get("description") or "",
            "observation": observation_payload.get("response") if observation_payload else action_input.get("observation"),
            "raw_observation": action_input.get("observation"),
            "observation_code": action_input.get("observation_code"),
        },
        "path": path,
        "sat": sat_rules,
        "smt_guard": {
            "enabled": bool(job.get("smt_guard_enabled")),
            "method": job.get("smt_method"),
            "z3_available": decisions[-1].get("z3_available") if decisions else None,
            "z3_version": decisions[-1].get("z3_version") if decisions else None,
            "python_executable": decisions[-1].get("python_executable") if decisions else None,
        },
    }


def _build_bench_finish_step(job, result):
    answer = result.get("answer_generation", {}) or {}
    final_answer = answer.get("final_answer") or ""
    valid_data = bool(answer.get("valid_data"))
    return {
        "source": "BENCH",
        "tool_call": False,
        "agent": (job["query_row"].get("asb_meta") or {}).get("agent_path") or "Bench",
        "tool": "Finish",
        "desc": "Bench 运行结束，汇总最终回答与状态。",
        "check": "执行通过" if valid_data and result.get("win") else "运行结束",
        "input": {
            "query_id": job["query_row"].get("query_id"),
        },
        "output": {
            "win": result.get("win"),
            "valid_data": valid_data,
            "finish_type": answer.get("finish_type"),
            "final_answer": final_answer,
        },
        "path": {"event": "finish", "rollback_mode": "none"},
        "sat": [],
    }


def _parse_bench_steps(job, include_finish=False):
    result_path = Path(job["result_path"])
    trace_events = _load_runtime_trace(Path(job["trace_path"]))
    result = None
    steps = [_build_bench_start_step(job)]
    last_safe_step = None

    if trace_events:
        calls = [_trace_event_to_call(event) for event in trace_events]
        for index, call in enumerate(calls):
            step = _build_bench_call_step(job, index, call, last_safe_step)
            steps.append(step)
            if step.get("check") == "执行通过":
                last_safe_step = step
            elif step.get("check", "").startswith("高风险") and last_safe_step is not None:
                steps.append(_build_bench_rollback_step(step, last_safe_step))
    elif result_path.exists():
        result = json.loads(result_path.read_text(encoding="utf-8"))
        calls = _extract_calls(result)
        for index, call in enumerate(calls):
            step = _build_bench_call_step(job, index, call, last_safe_step)
            steps.append(step)
            if step.get("check") == "执行通过":
                last_safe_step = step
            elif step.get("check", "").startswith("高风险") and last_safe_step is not None:
                steps.append(_build_bench_rollback_step(step, last_safe_step))

    if include_finish and result_path.exists():
        if result is None:
            result = json.loads(result_path.read_text(encoding="utf-8"))
        steps.append(_build_bench_finish_step(job, result))

    for idx, step in enumerate(steps, start=1):
        step.setdefault("path", {})["index"] = idx
    return steps


def _terminate_process(process):
    if process.poll() is not None:
        return process.poll()
    process.terminate()
    try:
        return process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(timeout=5)


def init_toolbench_routes(app):
    @app.route("/user/bench_options", methods=["GET"])
    def user_bench_options():
        grouped = _group_queries_by_agent()
        agents = []
        for agent_name, rows in sorted(grouped.items()):
            agents.append({
                "name": agent_name,
                "path": (rows[0].get("asb_meta") or {}).get("agent_path"),
                "queries": [
                    {
                        "query_id": row.get("query_id"),
                        "query": row.get("query"),
                        "label": _query_label(row),
                        "query_index": row.get("query_index") or (row.get("asb_meta") or {}).get("source_task_index"),
                        "query_variant": row.get("query_variant") or (row.get("asb_meta") or {}).get("query_variant_index"),
                        "attack_tools": (row.get("asb_meta") or {}).get("attack_tools", []),
                        "attack_types": (row.get("asb_meta") or {}).get("attack_types", []),
                    }
                    for row in rows
                ],
            })
        return jsonify({
            "agents": agents,
            "default_model": DEFAULT_BENCH_MODEL,
            "model_options": BENCH_MODEL_OPTIONS,
            "method": DEFAULT_BENCH_METHOD,
            "query_file": str(DEFAULT_BENCH_QUERY_FILE),
            "runtime": _bench_runtime_status(),
        })

    @app.route("/user/bench_start", methods=["POST"])
    def user_bench_start():
        payload = request.get_json(silent=True) or {}
        grouped = _group_queries_by_agent()
        agent_name = (payload.get("benchAgent") or "").strip()
        if not agent_name or agent_name not in grouped:
            return jsonify({"error": f"Unsupported Bench agent: {agent_name}"}), 400

        query_id = (payload.get("benchQueryId") or "").strip()
        query_row = None
        for row in grouped[agent_name]:
            if row.get("query_id") == query_id:
                query_row = row
                break
        if query_row is None:
            query_row = grouped[agent_name][0]

        job_id = uuid.uuid4().hex[:12]
        paths = _bench_paths(job_id)
        paths["output_dir"].mkdir(parents=True, exist_ok=True)
        paths["run_dir"].mkdir(parents=True, exist_ok=True)

        job_query = _deepcopy_row(query_row)
        original_query_id = job_query.get("query_id") or f"bench_{job_id}"
        job_query["query_id"] = f"{original_query_id}_{job_id}"
        override_query = (payload.get("queryText") or "").strip()
        if override_query:
            job_query["query"] = override_query
        paths["query_file"].write_text(json.dumps([job_query], indent=2, ensure_ascii=False), encoding="utf-8")

        llm_name = (payload.get("llmName") or DEFAULT_BENCH_MODEL).strip()
        smt_guard_enabled = bool(payload.get("smtGuardEnabled"))
        smt_method = normalize_smt_method(payload.get("smtMethod") or payload.get("smt_method"))

        paths["trace"].write_text("", encoding="utf-8")

        cmd = [
            DEFAULT_BENCH_PYTHON,
            str(TOOLBENCH_ROOT / "inference" / "qa_pipeline.py"),
            "--backbone_model", "ollama",
            "--ollama_model", llm_name,
            "--tool_root_dir", str(DEFAULT_TOOL_ROOT),
            "--input_query_file", str(paths["query_file"]),
            "--output_answer_file", str(paths["output_dir"]),
            "--runtime_trace_file", str(paths["trace"]),
            "--method", DEFAULT_BENCH_METHOD,
        ]
        if smt_guard_enabled:
            cmd.extend([
                "--enable_smt_guard",
                "--smt_method", smt_method,
                "--tool_ir_output_file", str(DEFAULT_IR_INDEX),
            ])

        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")
        env["PATH"] = os.pathsep.join([str(Path(DEFAULT_BENCH_PYTHON).parent), env.get("PATH", "")])

        log_file = paths["log"].open("w", encoding="utf-8")
        process = subprocess.Popen(
            cmd,
            cwd=str(TOOLBENCH_ROOT),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
        )
        log_file.close()

        result_path = paths["output_dir"] / f"{job_query['query_id']}_{DEFAULT_BENCH_METHOD}.json"
        job = {
            "job_id": job_id,
            "process": process,
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "log_path": str(paths["log"]),
            "query_row": job_query,
            "llm_name": llm_name,
            "smt_guard_enabled": smt_guard_enabled,
            "smt_method": smt_method,
            "query_file": str(paths["query_file"]),
            "result_path": str(result_path),
            "trace_path": str(paths["trace"]),
            "stopped": False,
        }
        BENCH_JOBS[job_id] = job
        return jsonify({
            "job_id": job_id,
            "agent_name": agent_name,
            "agent_path": (job_query.get("asb_meta") or {}).get("agent_path"),
            "query_id": job_query.get("query_id"),
            "query_text": job_query.get("query"),
            "selected_attack_tools": (job_query.get("asb_meta") or {}).get("attack_tools", []),
            "attack_types": (job_query.get("asb_meta") or {}).get("attack_types", []),
            "model": llm_name,
            "log_path": str(paths["log"]),
            "result_path": str(result_path),
            "smt_guard_enabled": smt_guard_enabled,
            "smt_method": smt_method,
            "runtime": _bench_runtime_status(),
        })

    @app.route("/user/bench_chain_step", methods=["POST"])
    def user_bench_chain_step():
        payload = request.get_json(silent=True) or {}
        job_id = payload.get("jobId") or payload.get("job_id")
        idx = int(payload.get("idx", 0))
        job = BENCH_JOBS.get(job_id)
        if not job:
            return jsonify({"error": "Bench job not found", "finished": True}), 404

        returncode = job["process"].poll()
        steps = _parse_bench_steps(job, include_finish=returncode is not None)

        if idx < len(steps):
            return jsonify({
                "step": steps[idx],
                "idx": idx,
                "finished": False,
                "log_tail": _tail(job["log_path"], 8000),
                "model": job["llm_name"],
            })

        returncode = job["process"].poll()
        if returncode is None:
            return jsonify({
                "waiting": True,
                "finished": False,
                "idx": idx,
                "log_tail": _tail(job["log_path"], 8000),
                "model": job["llm_name"],
            })

        if returncode != 0 and idx == len(steps):
            step = {
                "source": "BENCH",
                "tool_call": False,
                "agent": (job["query_row"].get("asb_meta") or {}).get("agent_path") or "Bench",
                "tool": "Bench Runtime",
                "desc": "Bench 后台任务异常退出，未能产生完整结果文件。",
                "check": "高风险：后台执行异常",
                "input": {"job_id": job_id},
                "output": {"returncode": returncode, "log_tail": _tail(job["log_path"], 4000)},
                "path": {"event": "runtime_error", "rollback_mode": "none", "index": len(steps) + 1},
                "sat": [],
            }
            return jsonify({"step": step, "idx": idx, "finished": False, "log_tail": _tail(job["log_path"], 8000), "model": job["llm_name"]})

        return jsonify({
            "finished": True,
            "history": steps,
            "returncode": returncode,
            "log_tail": _tail(job["log_path"], 8000),
            "model": job["llm_name"],
        })

    @app.route("/user/bench_stop", methods=["POST"])
    def user_bench_stop():
        payload = request.get_json(silent=True) or {}
        job_id = payload.get("jobId") or payload.get("job_id")
        job = BENCH_JOBS.get(job_id)
        if not job:
            return jsonify({"error": "Bench job not found"}), 404
        job["stopped"] = True
        returncode = _terminate_process(job["process"])
        return jsonify({"status": "stopped", "job_id": job_id, "returncode": returncode})
