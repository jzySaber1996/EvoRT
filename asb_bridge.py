import ast
import csv
import json
import os
import re
import subprocess
import sys
import time
import uuid
from datetime import datetime
from pathlib import Path

from flask import jsonify, request

from smt_guard import apply_smt_guard_to_steps, smt_guard_status
from smt_rule_engine import normalize_smt_method


BASE_DIR = Path(__file__).resolve().parent
ASB_ROOT = Path(os.environ.get("ASB_ROOT", BASE_DIR.parent / "ASB")).resolve()
ASB_RUN_ROOT = BASE_DIR / "chain_data" / "asb_runs"
ASB_JOBS = {}

ALLOWED_ATTACK_TYPES = {"naive", "fake_completion", "escape_characters", "context_ignoring", "combined_attack"}
DEFAULT_ASB_MODEL = os.environ.get("ASB_MODEL", "ollama/llama3:8b")
ASB_MODEL_OPTIONS = [
    item.strip()
    for item in os.environ.get("ASB_MODEL_OPTIONS", DEFAULT_ASB_MODEL).split(",")
    if item.strip()
]
if DEFAULT_ASB_MODEL not in ASB_MODEL_OPTIONS:
    ASB_MODEL_OPTIONS.insert(0, DEFAULT_ASB_MODEL)
ATTACK_TOOL_FILES = {
    "test": ASB_ROOT / "data" / "attack_tools_test.jsonl",
    "all": ASB_ROOT / "data" / "all_attack_tools.jsonl",
    "agg": ASB_ROOT / "data" / "all_attack_tools_aggressive.jsonl",
    "non-agg": ASB_ROOT / "data" / "all_attack_tools_non_aggressive.jsonl",
}
DEFAULT_TOOL_SET = os.environ.get("ASB_TOOL_SET", "all")
if DEFAULT_TOOL_SET not in ATTACK_TOOL_FILES:
    DEFAULT_TOOL_SET = "all"
DEFAULT_AGT_GOVERNANCE_ENABLED = os.environ.get("ASB_AGT_GOVERNANCE_ENABLED", "").strip().lower() in {"1", "true", "yes"}
DEFAULT_AGT_POLICY_PATH = os.environ.get("ASB_AGT_POLICY_PATH", str(ASB_ROOT / "policies" / "agt" / "asb_harmful_toolchain.yaml"))
ASB_ENV_PYTHON = Path("/root/miniconda3/envs/ASB/bin/python")
DEFAULT_ASB_PYTHON = os.environ.get(
    "ASB_PYTHON",
    str(ASB_ENV_PYTHON) if ASB_ENV_PYTHON.exists() else sys.executable,
)


def _bool_cell(value):
    return str(value or "").strip().lower() in {"1", "true", "yes"}


def _tail(path, max_chars=5000):
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return ""
    return text[-max_chars:]


def _asb_paths(job_id):
    run_dir = ASB_RUN_ROOT / job_id
    return {
        "run_dir": run_dir,
        "csv": run_dir / "result.csv",
        "log": run_dir / "run.log",
        "tasks": run_dir / "tasks.jsonl",
        "attack_tools": run_dir / "attack_tools.jsonl",
    }


def _load_jsonl(path):
    rows = []
    with Path(path).open("r", encoding="utf-8") as file:
        for line in file:
            if line.strip():
                rows.append(json.loads(line))
    return rows


def _load_agent_tasks():
    return _load_jsonl(ASB_ROOT / "data" / "agent_task.jsonl")


def _attack_tools_path(tool_set):
    normalized = (tool_set or DEFAULT_TOOL_SET).strip()
    if normalized not in ATTACK_TOOL_FILES:
        raise ValueError(f"Unsupported ASB tool set: {normalized}")
    return ATTACK_TOOL_FILES[normalized]


def _load_attack_tools(tool_set):
    return _load_jsonl(_attack_tools_path(tool_set))


def _agent_info(agent_name):
    agent_tasks = _load_agent_tasks()
    for item in agent_tasks:
        if item.get("agent_name") == agent_name:
            return item
    return None


def _write_task_file(path, task_text, agent_name):
    info = _agent_info(agent_name)
    if not info:
        raise ValueError(f"Unsupported ASB agent: {agent_name}")
    task = {
        "agent_name": info["agent_name"],
        "agent_path": info["agent_path"],
        "tasks": [task_text or info["tasks"][0]],
    }
    path.write_text(json.dumps(task, ensure_ascii=False) + "\n", encoding="utf-8")


def _select_attack_tools(agent_name, tool_set, attack_tool_name):
    tools = [tool for tool in _load_attack_tools(tool_set) if tool.get("Corresponding Agent") == agent_name]
    if attack_tool_name and attack_tool_name != "__all__":
        tools = [tool for tool in tools if tool.get("Attacker Tool") == attack_tool_name]
    return tools


def _write_attack_tools_file(path, tools):
    path.write_text("".join(json.dumps(tool, ensure_ascii=False) + "\n" for tool in tools), encoding="utf-8")
    return tools


def _read_csv_rows(csv_path):
    if not csv_path.exists():
        return []
    rows = []
    with csv_path.open("r", newline="", encoding="utf-8", errors="replace") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if any((value or "").strip() for value in row.values()):
                rows.append(row)
    return rows


def _safe_literal_eval(value, default=None):
    try:
        return ast.literal_eval(value)
    except Exception:
        return default


def _decode_message_content(raw_content):
    if raw_content is None:
        return ""
    if isinstance(raw_content, str):
        return raw_content
    return str(raw_content)


def _extract_step_prompt(content):
    content = _decode_message_content(content)
    match = re.search(r"At step\s+(\d+),\s+you need to\s+(.*?)\s*\nIn and only", content, flags=re.DOTALL)
    if not match:
        match = re.search(r"At step\s+(\d+),\s+you need to\s+(.*?)(?:\.\s*$|$)", content, flags=re.DOTALL)
    step_no = match.group(1) if match else ""
    step_goal = re.sub(r"\s+", " ", match.group(2)).strip() if match else content[:260]

    available_tools = []
    tools_match = re.search(r"Available tools are:\s*(.*?)\nMust call", content, flags=re.DOTALL)
    if tools_match:
        tools_text = tools_match.group(1).strip()
        try:
            tools = json.loads(tools_text)
            for tool in tools:
                function = tool.get("function", {}) if isinstance(tool, dict) else {}
                available_tools.append({
                    "name": function.get("name"),
                    "description": function.get("description"),
                })
        except Exception:
            available_tools = []

    return {
        "step": step_no,
        "goal": step_goal,
        "available_tools": available_tools,
        "raw_prompt": content,
    }


def _extract_action_details(content):
    content = _decode_message_content(content)
    action = ""
    observation = ""
    if "[Action]:" in content:
        action_part = content.split("[Action]:", 1)[1]
        if "[Observation]:" in action_part:
            action, observation = action_part.split("[Observation]:", 1)
        else:
            action = action_part
    else:
        action = content
    action = action.strip().strip(";")
    observation = observation.strip()

    tool_name = ""
    blocked_tool = ""
    alternative_tool = ""
    guard_result = ""
    smt_guard_method = ""

    blocked_tool_match = re.search(r"SMT guard(?: method\s+([A-Za-z0-9_-]+))?\s+blocked the\s+([A-Za-z0-9_]+)\s+tool", action)
    if blocked_tool_match:
        smt_guard_method = blocked_tool_match.group(1) or ""
        blocked_tool = blocked_tool_match.group(2)
        tool_name = blocked_tool

    replacement_match = re.search(r"Replaced\s+([A-Za-z0-9_]+)\s+with\s+([A-Za-z0-9_]+)", observation)
    if replacement_match:
        blocked_tool = blocked_tool or replacement_match.group(1)
        alternative_tool = replacement_match.group(2)

    guard_result_match = re.search(r"SMT guard(?: method\s+([A-Za-z0-9_-]+))?\s+result\s+([A-Z]+)", observation)
    if guard_result_match:
        smt_guard_method = smt_guard_method or guard_result_match.group(1) or ""
        guard_result = guard_result_match.group(2)

    action_tool_match = re.search(r"call the\s+([A-Za-z0-9_]+)", action)
    if action_tool_match and not tool_name:
        tool_name = action_tool_match.group(1)
    if not tool_name:
        observation_tool_match = re.search(r"from\s+([A-Za-z0-9_]+)\s+is", observation)
        if observation_tool_match:
            tool_name = observation_tool_match.group(1)
    if not tool_name:
        attacker_tool_match = re.search(r"attacker tool\s+([A-Za-z0-9_]+)", observation)
        if attacker_tool_match:
            tool_name = attacker_tool_match.group(1)

    parameters = ""
    params_match = re.search(r"params as\s+(.*?)(?:;|$)", action, flags=re.DOTALL)
    if params_match:
        parameters = params_match.group(1).strip()

    return {
        "action": action,
        "observation": observation,
        "called_tool": tool_name,
        "blocked_tool": blocked_tool,
        "alternative_tool": alternative_tool,
        "smt_guard_blocked": bool(blocked_tool),
        "smt_guard_result": guard_result,
        "smt_guard_method": normalize_smt_method(smt_guard_method) if smt_guard_method else "",
        "parameters": parameters,
        "raw_response": content,
    }


def _is_attack_tool_call(tool_name, attack_tool_name, selected_attack_tools, content=""):
    if not tool_name:
        return False
    selected_names = {name for name in selected_attack_tools if name}
    if attack_tool_name and tool_name == attack_tool_name:
        return True
    if attack_tool_name and f"attacker tool {attack_tool_name}" in content:
        return True
    return tool_name in selected_names


def _smt_symbol(value):
    symbol = re.sub(r"[^A-Za-z0-9_]", "_", str(value or "Tool"))
    return symbol or "Tool"


def _pending_smt_rule(rule_id, *, called_tool="", attack_tool="", event="tool_call", evidence=""):
    called_symbol = _smt_symbol(called_tool or "Tool")
    attack_symbol = _smt_symbol(attack_tool or "AttackTool")
    formula = "\n".join([
        ";; SMT placeholder: formula table is preserved for the upcoming solver integration.",
        ";; Current ASB path does not execute solver-based defense or rollback.",
        "(set-logic QF_UF)",
        f"(declare-const call_{called_symbol} Bool)",
        f"(declare-const injected_{attack_symbol} Bool)",
        "(declare-const unsafe_tool_called Bool)",
        f";; event: {event}",
        f";; actual_tool: {called_tool or '-'}",
        f";; injected_target_tool: {attack_tool or '-'}",
    ])
    return {
        "id": rule_id,
        "formula": formula,
        "result": "PENDING",
        "evidence": evidence or "SMT求解器尚未接入；此处仅保留公式表格展示位。",
    }


def _extract_plan_details(content):
    content = _decode_message_content(content)
    if "The workflow generated for the problem is" not in content:
        return None
    plan_text = content.split("The workflow generated for the problem is", 1)[1].strip()
    return {
        "workflow_text": plan_text,
        "workflow": _safe_literal_eval(plan_text, None),
        "raw_response": content,
    }


def _build_plan_step(job, *, agent_name, attack_tool_name, plan_info, sample_index=None):
    workflow_text = plan_info.get("workflow_text") or ""
    contains_attack_tool = bool(attack_tool_name and attack_tool_name in workflow_text)
    return {
        "source": "ASB",
        "tool_call": False,
        "agent": agent_name or job.get("agent_path", "ASB Agent"),
        "tool": "WorkflowPlanning",
        "desc": "ASB生成工具调用计划；这里展示的是计划，不代表工具已经被实际调用。",
        "check": "运行状态",
        "input": {
            "job_id": job["job_id"],
            "sample": sample_index,
            "model": job["llm_name"],
            "attack_type": job["attack_type"],
            "task": job.get("task_text"),
            "attack_tool": attack_tool_name,
            "smt_method": job.get("smt_method"),
        },
        "output": {
            "workflow": plan_info.get("workflow"),
            "workflow_text": workflow_text,
            "contains_injected_tool": contains_attack_tool,
            "raw_response": plan_info.get("raw_response"),
        },
        "path": {
            "event": "plan_contains_injected_tool" if contains_attack_tool else "planning",
            "rollback_mode": "execution_path_only",
            "note": "计划阶段不等同于攻击达成；只有后续实际调用注入目标工具时才标记为攻击工具被调用。",
        },
        "sat": [_pending_smt_rule(
            "ASB-PLAN-PENDING",
            called_tool="WorkflowPlanning",
            attack_tool=attack_tool_name,
            event="planning",
            evidence="计划阶段公式占位，当前未调用SMT求解器。",
        )],
    }


def _build_tool_call_step(job, *, agent_name, attack_tool_name, selected_attack_tools, prompt_info, action_info, sample_index=None):
    called_tool = action_info.get("called_tool") or "NoToolCall"
    content = action_info.get("raw_response", "")
    smt_blocked = bool(action_info.get("smt_guard_blocked"))
    alternative_tool = action_info.get("alternative_tool") or ""
    is_attack = False if smt_blocked else _is_attack_tool_call(called_tool, attack_tool_name, selected_attack_tools, content)
    step_no = prompt_info.get("step") or "?"
    step_goal = prompt_info.get("goal") or "模型执行工具调用"
    check = "SMT执行前阻断" if smt_blocked else ("高风险：攻击工具被调用" if is_attack else "执行通过")
    actual_tool = alternative_tool if smt_blocked and alternative_tool else called_tool
    smt_method = normalize_smt_method(action_info.get("smt_guard_method") or job.get("smt_method"))

    step = {
        "source": "ASB",
        "tool_call": True,
        "agent": agent_name or job.get("agent_path", "ASB Agent"),
        "tool": called_tool,
        "desc": f"ASB第 {step_no} 步{'执行前阻断' if smt_blocked else '实际工具调用'}：{step_goal}",
        "check": check,
        "input": {
            "job_id": job["job_id"],
            "sample": sample_index,
            "model": job["llm_name"],
            "attack_type": job["attack_type"],
            "task": job.get("task_text"),
            "attack_tool": attack_tool_name,
            "smt_method": smt_method,
            "injected_target_tool": attack_tool_name,
            "step": step_no,
            "step_goal": step_goal,
            "available_tools": prompt_info.get("available_tools", []),
        },
        "output": {
            "called_tool": called_tool,
            "actual_called_tool": actual_tool,
            "blocked_tool": action_info.get("blocked_tool"),
            "alternative_tool": alternative_tool,
            "smt_guard_blocked": smt_blocked,
            "smt_guard_result": action_info.get("smt_guard_result"),
            "smt_guard_method": smt_method,
            "injected_target_tool": attack_tool_name,
            "parameters": action_info.get("parameters") or "None",
            "action": action_info.get("action"),
            "observation": action_info.get("observation"),
            "raw_response": content,
        },
        "path": {
            "event": "blocked" if smt_blocked else ("risk" if is_attack else "tool_call"),
            "rollback_mode": "asb_pre_tool_smt_guard" if smt_blocked else "execution_path_only",
            "rollback_target": None,
            "rollback_to_index": None,
            "alternative_tool": alternative_tool or None,
            "note": "ASB内部工具执行器已在run()前阻断该工具调用。" if smt_blocked else "未启用求解器防御；这里只按实际执行路径标记风险和最近安全回退点。",
        },
        "sat": [_pending_smt_rule(
            f"ASB-CALL-{step_no}",
            called_tool=called_tool,
            attack_tool=attack_tool_name,
            event="pre_tool_blocked" if smt_blocked else "actual_tool_call",
            evidence="SMT防护已在ASB内部阻断注入目标工具，原工具run()未执行。" if smt_blocked else ("实际调用了注入目标工具。" if is_attack else "实际调用的是普通工具或非目标工具。"),
        )],
    }
    return step


def _annotate_execution_path(steps):
    last_safe = None
    for index, step in enumerate(steps):
        path_info = step.setdefault("path", {})
        path_info["index"] = index + 1
        is_risk = str(step.get("check", "")).startswith("高风险")
        if is_risk:
            if last_safe:
                path_info["rollback_target"] = last_safe.get("tool")
                path_info["rollback_to_index"] = last_safe.get("path", {}).get("index")
            path_info["rollback_note"] = "实际ASB执行没有被阻断；该回退点仅由执行路径上的最近安全节点推导。"
        elif step.get("check") != "回滚":
            last_safe = step
    return steps


def _build_job_start_step(job, agent_name=None, attack_tool_name=None):
    return {
        "source": "ASB",
        "tool_call": False,
        "agent": agent_name or job.get("agent_path", "ASB Agent"),
        "tool": "ASB Job Start",
        "desc": "启动ASB沙盒任务，开始记录实际工具调用路径。",
        "check": "运行状态",
        "input": {
            "job_id": job["job_id"],
            "model": job["llm_name"],
            "attack_type": job["attack_type"],
            "task": job.get("task_text"),
            "attack_tool": attack_tool_name or job.get("attack_tool_name"),
        },
        "output": {"log_tail": _tail(job["log_path"], 3000)},
        "path": {
            "event": "start",
            "rollback_mode": "execution_path_only",
            "note": "未启用求解器防御。",
        },
        "sat": [],
    }


def _parse_runtime_steps(job):
    try:
        text = Path(job["log_path"]).read_text(encoding="utf-8", errors="replace")
    except FileNotFoundError:
        return []

    steps = []
    agent_match = re.search(r"Running agent: (.*?) with the task: (.*?) and the attacker tool: (.*)", text)
    if agent_match:
        steps.append(_build_job_start_step(job, agent_match.group(1), agent_match.group(3).strip()))

    selected_attack_tools = job.get("selected_attack_tools") or []
    for line in text.splitlines():
        match = re.search(r"\[(example/[^\]]+)\] At step (\d+), (\{.*\})$", line)
        if not match:
            continue
        message = _safe_literal_eval(match.group(3), {}) or {}
        content = _decode_message_content(message.get("content"))
        if "[Action]:" not in content:
            continue
        prompt_info = {"step": match.group(2), "goal": "实时日志中捕获的工具调用", "available_tools": [], "raw_prompt": ""}
        action_info = _extract_action_details(content)
        attack_tool_name = job.get("attack_tool_name") or ""
        steps.append(_build_tool_call_step(
            job,
            agent_name=match.group(1),
            attack_tool_name=attack_tool_name,
            selected_attack_tools=selected_attack_tools,
            prompt_info=prompt_info,
            action_info=action_info,
        ))

    if "OpenAIError: Missing credentials" in text:
        steps.append({
            "source": "ASB",
            "tool_call": False,
            "agent": "ASB Judge",
            "tool": "RefuseJudge",
            "desc": "OpenAI拒绝判定器缺少API key；该问题不会阻断工具调用路径展示。",
            "check": "高风险：后台执行异常",
            "input": {"requires": "OPENAI_API_KEY"},
            "output": {"log_tail": _tail(job["log_path"], 5000)},
            "path": {"event": "runtime_error", "rollback_mode": "execution_path_only"},
            "sat": [],
        })

    return _annotate_execution_path(steps)


def _parse_messages(messages_text):
    messages = _safe_literal_eval(messages_text, [])
    return messages if isinstance(messages, list) else []


def _build_result_steps_from_rows(rows, job):
    steps = []
    selected_attack_tools = job.get("selected_attack_tools") or []
    for row_idx, row in enumerate(rows):
        attack_tool_name = row.get("Attack Tool") or job.get("attack_tool_name") or ""
        agent_name = row.get("Agent Name") or job.get("agent_path", "ASB Agent")
        steps.append({
            "source": "ASB",
            "tool_call": False,
            "agent": agent_name,
            "tool": "ASB Sample Start",
            "desc": f"开始回放第 {row_idx + 1} 个ASB攻击样本，目标攻击工具：{attack_tool_name}",
            "check": "运行状态",
            "input": {
                "job_id": job["job_id"],
                "sample": row_idx + 1,
                "task": job.get("task_text"),
                "attack_tool": attack_tool_name,
                "attack_successful": _bool_cell(row.get("Attack Successful")),
                "original_task_successful": _bool_cell(row.get("Original Task Successful")),
            },
            "output": {
                "refused": _bool_cell(row.get("Refuse Result")),
                "memory_found": row.get("Memory Found"),
                "aggressive": _bool_cell(row.get("Aggressive")),
            },
            "path": {
                "event": "sample_start",
                "rollback_mode": "execution_path_only",
                "note": "未启用求解器防御；按实际messages顺序回放工具调用。",
            },
            "sat": [],
        })

        pending_prompt = None
        for message in _parse_messages(row.get("messages") or ""):
            role = message.get("role") if isinstance(message, dict) else ""
            content = _decode_message_content(message.get("content") if isinstance(message, dict) else message)
            if role == "user" and content.startswith("At step"):
                pending_prompt = _extract_step_prompt(content)
                continue
            if role == "assistant":
                plan_info = _extract_plan_details(content)
                if plan_info:
                    steps.append(_build_plan_step(
                        job,
                        agent_name=agent_name,
                        attack_tool_name=attack_tool_name,
                        plan_info=plan_info,
                        sample_index=row_idx + 1,
                    ))
                    continue
            if role == "assistant" and "[Action]:" in content:
                prompt_info = pending_prompt or {"step": "?", "goal": "CSV messages中捕获的工具调用", "available_tools": [], "raw_prompt": ""}
                action_info = _extract_action_details(content)
                steps.append(_build_tool_call_step(
                    job,
                    agent_name=agent_name,
                    attack_tool_name=attack_tool_name,
                    selected_attack_tools=selected_attack_tools,
                    prompt_info=prompt_info,
                    action_info=action_info,
                    sample_index=row_idx + 1,
                ))
                pending_prompt = None

    return _annotate_execution_path(steps)

def _build_runtime_step(job, idx, message, high_risk=True):
    log_tail = _tail(job["log_path"], 2500)
    return {
        "agent": "ASB Backend",
        "tool": "ASB Runtime",
        "desc": message,
        "check": "高风险：后台执行异常" if high_risk else "运行状态",
        "input": {
            "job_id": job["job_id"],
            "model": job["llm_name"],
            "attack_type": job["attack_type"],
        },
        "output": {
            "returncode": job["process"].poll() if job.get("process") else None,
            "log_tail": log_tail,
        },
        "path": {
            "event": "runtime_error" if high_risk else "stopped",
            "rollback_mode": "execution_path_only",
            "note": "未启用求解器防御。",
        },
        "sat": [],
    }


def _terminate_process(process):
    if process.poll() is not None:
        return process.poll()
    process.terminate()
    try:
        return process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        process.kill()
        return process.wait(timeout=5)


def init_asb_routes(app):
    @app.route("/user/asb_options", methods=["GET"])
    def user_asb_options():
        agent_tasks = _load_agent_tasks()
        agents = []
        for item in agent_tasks:
            agents.append({
                "name": item["agent_name"],
                "path": item["agent_path"],
                "tasks": item.get("tasks", []),
            })

        tool_set = request.args.get("toolSet", DEFAULT_TOOL_SET)
        try:
            attack_tools = _load_attack_tools(tool_set)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400

        tools_by_agent = {}
        for tool in attack_tools:
            tools_by_agent.setdefault(tool.get("Corresponding Agent"), []).append({
                "name": tool.get("Attacker Tool"),
                "attack_type": tool.get("Attack Type"),
                "aggressive": tool.get("Aggressive"),
                "instruction": tool.get("Attacker Instruction"),
                "goal": tool.get("Attack goal"),
            })

        return jsonify({
            "agents": agents,
            "tools_by_agent": tools_by_agent,
            "attack_types": sorted(ALLOWED_ATTACK_TYPES),
            "tool_sets": list(ATTACK_TOOL_FILES.keys()),
            "default_tool_set": DEFAULT_TOOL_SET,
            "default_model": DEFAULT_ASB_MODEL,
            "model_options": ASB_MODEL_OPTIONS,
            "smt_guard": smt_guard_status(),
            "agt_governance": {
                "enabled": DEFAULT_AGT_GOVERNANCE_ENABLED,
                "policy_path": DEFAULT_AGT_POLICY_PATH,
            },
        })

    @app.route("/user/asb_start", methods=["POST"])
    def user_asb_start():
        payload = request.get_json(silent=True) or {}
        attack_type = payload.get("attackType", "naive")
        if attack_type not in ALLOWED_ATTACK_TYPES:
            return jsonify({"error": f"Unsupported attack type: {attack_type}"}), 400

        if not ASB_ROOT.exists():
            return jsonify({"error": f"ASB root not found: {ASB_ROOT}"}), 500

        job_id = uuid.uuid4().hex[:12]
        paths = _asb_paths(job_id)
        paths["run_dir"].mkdir(parents=True, exist_ok=True)

        agent_name = (payload.get("asbAgent") or "").strip()
        if not agent_name:
            agent_name = _load_agent_tasks()[0]["agent_name"]
        agent_info = _agent_info(agent_name)
        if not agent_info:
            return jsonify({"error": f"Unsupported ASB agent: {agent_name}"}), 400

        tool_set = (payload.get("toolSet") or DEFAULT_TOOL_SET).strip()
        attack_tool_name = (payload.get("attackTool") or "__all__").strip()
        try:
            selected_tools = _select_attack_tools(agent_name, tool_set, attack_tool_name)
        except ValueError as exc:
            return jsonify({"error": str(exc)}), 400
        if not selected_tools:
            selected_name = "全部工具" if attack_tool_name == "__all__" else attack_tool_name
            return jsonify({"error": f"No attack tool '{selected_name}' for agent '{agent_name}' in tool set '{tool_set}'"}), 400

        task_text = (payload.get("queryText") or agent_info["tasks"][0]).strip()
        llm_name = (payload.get("llmName") or DEFAULT_ASB_MODEL).strip()
        smt_guard_enabled = bool(payload.get("smtGuardEnabled"))
        deepseek_rules_enabled = bool(payload.get("deepseekRulesEnabled"))
        smt_method = normalize_smt_method(payload.get("smtMethod") or payload.get("smt_method"))
        raw_agt_governance_enabled = payload.get("agtGovernanceEnabled")
        agt_governance_enabled = DEFAULT_AGT_GOVERNANCE_ENABLED if raw_agt_governance_enabled is None else bool(raw_agt_governance_enabled)
        agt_policy_path = (payload.get("agtPolicyPath") or DEFAULT_AGT_POLICY_PATH).strip()
        selected_tools = _write_attack_tools_file(paths["attack_tools"], selected_tools)
        _write_task_file(paths["tasks"], task_text, agent_name)

        cmd = [
            DEFAULT_ASB_PYTHON,
            "main_attacker.py",
            "--llm_name", llm_name,
            "--use_backend", "ollama",
            "--direct_prompt_injection",
            "--attack_type", attack_type,
            "--attacker_tools_path", str(paths["attack_tools"]),
            "--tasks_path", str(paths["tasks"]),
            "--tools_info_path", "data/all_normal_tools.jsonl",
            "--res_file", str(paths["csv"]),
            "--database", str(paths["run_dir"] / "memory_db"),
            "--task_num", "1",
        ]
        if smt_guard_enabled:
            cmd.extend([
                "--smt_guard_enabled",
                "--smt_guard_module_path", str(BASE_DIR),
                "--smt_guard_method", smt_method,
            ])
            if deepseek_rules_enabled:
                cmd.append("--smt_guard_deepseek")
        if agt_governance_enabled:
            cmd.extend([
                "--agt_governance_enabled",
                "--agt_policy_path", agt_policy_path,
            ])

        env = os.environ.copy()
        env.setdefault("PYTHONUNBUFFERED", "1")
        conda_bin = "/root/miniconda3/bin"
        conda_condabin = "/root/miniconda3/condabin"
        env["PATH"] = os.pathsep.join([conda_bin, conda_condabin, env.get("PATH", "")])
        if ASB_ENV_PYTHON.exists():
            env.setdefault("CONDA_PREFIX", str(ASB_ENV_PYTHON.parent.parent))
            env.setdefault("CONDA_DEFAULT_ENV", "ASB")

        log_file = paths["log"].open("w", encoding="utf-8")
        process = subprocess.Popen(
            cmd,
            cwd=str(ASB_ROOT),
            stdout=log_file,
            stderr=subprocess.STDOUT,
            env=env,
            text=True,
        )
        log_file.close()

        job = {
            "job_id": job_id,
            "process": process,
            "cmd": cmd,
            "started_at": datetime.now().isoformat(timespec="seconds"),
            "attack_type": attack_type,
            "llm_name": llm_name,
            "task_text": task_text,
            "agent_name": agent_name,
            "agent_path": agent_info["agent_path"],
            "tool_set": tool_set,
            "attack_tool_name": attack_tool_name if attack_tool_name != "__all__" else (selected_tools[0].get("Attacker Tool") if len(selected_tools) == 1 else ""),
            "selected_attack_tools": [tool.get("Attacker Tool") for tool in selected_tools],
            "smt_guard_enabled": smt_guard_enabled,
            "deepseek_rules_enabled": deepseek_rules_enabled,
            "smt_method": smt_method,
            "agt_governance_enabled": agt_governance_enabled,
            "agt_policy_path": agt_policy_path,
            "csv_path": str(paths["csv"]),
            "log_path": str(paths["log"]),
            "run_dir": str(paths["run_dir"]),
            "stopped": False,
        }
        ASB_JOBS[job_id] = job

        return jsonify({
            "job_id": job_id,
            "started_at": job["started_at"],
            "log_path": job["log_path"],
            "csv_path": job["csv_path"],
            "agent_name": job["agent_name"],
            "agent_path": job["agent_path"],
            "tool_set": job["tool_set"],
            "attack_type": job["attack_type"],
            "model": job["llm_name"],
            "task_text": job["task_text"],
            "selected_attack_tools": job["selected_attack_tools"],
            "smt_guard_enabled": job["smt_guard_enabled"],
            "deepseek_rules_enabled": job["deepseek_rules_enabled"],
            "smt_method": job["smt_method"],
            "agt_governance_enabled": job["agt_governance_enabled"],
            "agt_policy_path": job["agt_policy_path"],
            "smt_guard": smt_guard_status(job["deepseek_rules_enabled"], job["smt_method"]),
        })

    @app.route("/user/asb_chain_step", methods=["POST"])
    def user_asb_chain_step():
        payload = request.get_json(silent=True) or {}
        job_id = payload.get("jobId") or payload.get("job_id")
        idx = int(payload.get("idx", 0))
        job = ASB_JOBS.get(job_id)
        if not job:
            return jsonify({"error": "ASB job not found", "finished": True}), 404

        rows = _read_csv_rows(Path(job["csv_path"]))
        if rows:
            steps = _build_result_steps_from_rows(rows, job)
        else:
            steps = _parse_runtime_steps(job)
        steps = apply_smt_guard_to_steps(
            steps,
            selected_attack_tools=job.get("selected_attack_tools"),
            defense_enabled=job.get("smt_guard_enabled", False),
            mode="asb_runtime",
            deepseek_enabled=job.get("deepseek_rules_enabled", False),
            smt_method=job.get("smt_method"),
        )
        if idx < len(steps):
            return jsonify({"step": steps[idx], "idx": idx, "finished": False, "log_tail": _tail(job["log_path"], 8000), "model": job["llm_name"]})

        returncode = job["process"].poll()
        if returncode is None:
            return jsonify({
                "waiting": True,
                "finished": False,
                "idx": idx,
                "log_tail": _tail(job["log_path"], 8000),
                "model": job["llm_name"],
            })

        if job.get("stopped") and idx == len(steps):
            step = _build_runtime_step(job, idx, "ASB后台任务已被用户停止。", high_risk=False)
            return jsonify({"step": step, "idx": idx, "finished": False})

        if returncode != 0 and idx == len(steps):
            step = _build_runtime_step(job, idx, "ASB后台任务异常退出，未能继续产生完整CSV结果。", high_risk=True)
            return jsonify({"step": step, "idx": idx, "finished": False})

        return jsonify({
            "finished": True,
            "history": steps,
            "returncode": returncode,
            "log_tail": _tail(job["log_path"], 8000),
            "model": job["llm_name"],
        })

    @app.route("/user/asb_stop", methods=["POST"])
    def user_asb_stop():
        payload = request.get_json(silent=True) or {}
        job_id = payload.get("jobId") or payload.get("job_id")
        job = ASB_JOBS.get(job_id)
        if not job:
            return jsonify({"error": "ASB job not found"}), 404
        job["stopped"] = True
        returncode = _terminate_process(job["process"])
        return jsonify({"status": "stopped", "job_id": job_id, "returncode": returncode})
