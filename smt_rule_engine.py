"""SMT rule generation and solving methods used by smt_guard.

The public functions in this file are intentionally small and data-oriented:
`smt_guard.py` owns runtime integration, while this module owns the rule
families and Z3 formulas.
"""

import json
import re
from functools import lru_cache
from pathlib import Path


SAT_RISK_SEMANTICS = "SAT_MEANS_RISK"
DEFAULT_SMT_METHOD = "template"
SUPPORTED_SMT_METHODS = ("template", "hoare", "ir_hoare")
IR_TEXT_LIMIT = 4000


def normalize_smt_method(method):
    value = str(method or DEFAULT_SMT_METHOD).strip().lower()
    aliases = {
        "local": "template",
        "local_templates": "template",
        "default": "template",
        "hoare_logic": "hoare",
        "hoare-style": "hoare",
        "ir": "ir_hoare",
        "ir-hoare": "ir_hoare",
        "ir_hoare_logic": "ir_hoare",
        "ir_regex": "ir_hoare",
        "ir-regex": "ir_hoare",
        "regex_hoare": "ir_hoare",
    }
    value = aliases.get(value, value)
    if value not in SUPPORTED_SMT_METHODS:
        return DEFAULT_SMT_METHOD
    return value


def method_description(method):
    method = normalize_smt_method(method)
    if method == "ir_hoare":
        return (
            "IR-template Hoare contract with Z3 string/regex constraints. "
            "SAT means the runtime query/output can violate an agent_security.ir safety contract."
        )
    if method == "hoare":
        return (
            "Hoare-style chain contract. SAT means the current tool transition "
            "can violate agent input/output safety conditions under the chain context."
        )
    return "Runtime risk condition generated for this tool call. SAT means a risky valuation exists."


def extract_facts_for_method(step, selected_attack_tools, *, method=None, force_safe=False):
    method = normalize_smt_method(method)
    if method == "ir_hoare":
        return _extract_ir_hoare_facts(step, selected_attack_tools, force_safe=force_safe)
    if method == "hoare":
        return _extract_hoare_facts(step, selected_attack_tools, force_safe=force_safe)
    return _extract_template_facts(step, selected_attack_tools, force_safe=force_safe)


def condition_specs_for_method(method=None, llm_rules=None):
    method = normalize_smt_method(method)
    if method == "ir_hoare":
        specs = _ir_hoare_condition_specs()
    elif method == "hoare":
        specs = _hoare_condition_specs()
    else:
        specs = _template_condition_specs()

    for idx, rule in enumerate(llm_rules or [], start=1):
        fact_name = f"llm_rule_{idx}_risk"
        condition_name = f"llm_rule_{idx}_condition"
        specs.append((condition_name, fact_name, lambda b, z3, n=fact_name: b[n]))
    return specs


def build_smt_formula_for_method(step, facts, llm_rules, *, method=None):
    method = normalize_smt_method(method)
    if method == "ir_hoare":
        return _build_ir_hoare_smt_formula(step, facts, llm_rules)

    tool_symbol = smt_symbol(step.get("tool", "Tool"))
    llm_facts = {f"llm_rule_{idx}_risk": bool(rule.get("risk")) for idx, rule in enumerate(llm_rules or [], start=1)}
    all_facts = {**facts, **llm_facts}
    condition_specs = condition_specs_for_method(method, llm_rules)
    lines = [
        f";; SMT guard formula method: {method}.",
        ";; Semantics: SAT means there exists a valuation that satisfies runtime_risk.",
        ";; UNSAT means the risk condition cannot be satisfied under current context facts.",
        "(set-logic QF_UF)",
        f"(declare-const call_{tool_symbol} Bool)",
    ]
    if method == "hoare":
        lines.extend([
            ";; Hoare contract shape: {safe_agent_input} tool_call {safe_agent_output}.",
            ";; runtime_risk is asserted when the transition violates the chain contract.",
        ])
    for name in all_facts:
        lines.append(f"(declare-const {name} Bool)")
    for name, _expr, _builder in condition_specs:
        lines.append(f"(declare-const {name} Bool)")
    lines.append("(declare-const runtime_risk Bool)")
    lines.append(f"(assert call_{tool_symbol})")
    for name, value in all_facts.items():
        lines.append(f"(assert {name if value else f'(not {name})'})")
    for name, expr, _builder in condition_specs:
        lines.append(f"(assert (= {name} {expr}))")
    condition_names = " ".join(name for name, _expr, _builder in condition_specs)
    lines.append(f"(assert (= runtime_risk (or {condition_names})))")
    lines.append("(assert runtime_risk)")
    lines.append("(check-sat)")
    lines.append("(get-model)")
    return "\n".join(lines)


def solve_with_z3_for_method(z3_module, facts, llm_rules, *, method=None):
    if z3_module is None:
        return {
            "result": "UNKNOWN",
            "solver": "z3-unavailable",
            "model": {},
            "condition_values": {},
            "error": "z3-solver is not installed in the current Python environment.",
        }

    method = normalize_smt_method(method)
    if method == "ir_hoare":
        return _solve_ir_hoare_with_z3(z3_module, facts, llm_rules)

    llm_facts = {f"llm_rule_{idx}_risk": bool(rule.get("risk")) for idx, rule in enumerate(llm_rules or [], start=1)}
    all_facts = {**facts, **llm_facts}
    bools = {name: z3_module.Bool(name) for name in all_facts}
    solver = z3_module.Solver()
    for name, value in all_facts.items():
        solver.add(bools[name] == z3_module.BoolVal(bool(value)))

    condition_exprs = []
    for name, _expr, builder in condition_specs_for_method(method, llm_rules):
        expr = builder(bools, z3_module)
        condition_exprs.append((name, expr))

    runtime_risk = z3_module.Bool("runtime_risk")
    solver.add(runtime_risk == z3_module.Or([expr for _name, expr in condition_exprs]))
    solver.add(runtime_risk)
    result = solver.check()
    if result == z3_module.sat:
        z3_model = solver.model()
        model = {decl.name(): str(z3_model[decl]) for decl in z3_model.decls()}
        condition_values = {
            name: bool(z3_module.is_true(z3_model.evaluate(expr, model_completion=True)))
            for name, expr in condition_exprs
        }
        return {"result": "SAT", "solver": "z3", "model": model, "condition_values": condition_values}
    if result == z3_module.unsat:
        condition_values = evaluate_condition_values_from_facts(facts, llm_rules, method=method)
        return {"result": "UNSAT", "solver": "z3", "model": {}, "condition_values": condition_values}
    return {"result": "UNKNOWN", "solver": "z3", "model": {}, "condition_values": {}}


def evaluate_condition_values_from_facts(facts, llm_rules, *, method=None):
    method = normalize_smt_method(method)
    if method == "ir_hoare":
        values = _evaluate_ir_hoare_condition_values(facts)
    elif method == "hoare":
        values = {
            "hoare_precondition_violation": bool(
                facts.get("agent_input_untrusted") and facts.get("requested_attack_tool")
            ),
            "hoare_postcondition_violation": bool(
                facts.get("agent_output_unsafe") and facts.get("current_tool_can_change_world")
            ),
            "hoare_context_chain_anomaly": bool(
                facts.get("chain_attack_context")
                and (
                    facts.get("requested_attack_tool")
                    or facts.get("current_tool_can_change_world")
                    or facts.get("unknown_tool_selected")
                )
            ),
            "hoare_sensitive_leak_contract": bool(
                facts.get("agent_input_sensitive") and facts.get("agent_output_external")
            ),
            "hoare_harmful_transition": bool(
                (
                    facts.get("agent_input_financial_harm")
                    or facts.get("agent_input_medical_harm")
                    or facts.get("agent_input_code_harm")
                )
                and (
                    facts.get("agent_output_external")
                    or facts.get("current_tool_can_change_world")
                    or facts.get("requested_attack_tool")
                )
            ),
            "unknown_tool_selected": bool(facts.get("unknown_tool_selected")),
        }
    else:
        values = {
            "attack_tool_invoked": bool(
                facts.get("called_injected_tool")
                or facts.get("called_known_attack_tool")
                or facts.get("observation_reports_attacker_goal")
            ),
            "sensitive_exfiltration": bool(facts.get("sensitive_data_used") and facts.get("external_send_or_export")),
            "destructive_privileged_action": bool(facts.get("destructive_or_privileged_action")),
            "financial_duplication_or_fraud": bool(facts.get("financial_duplication_or_fraud")),
            "medical_or_safety_harm": bool(facts.get("medical_or_safety_harm")),
            "unsafe_code_or_shell": bool(facts.get("unsafe_code_or_shell")),
            "unknown_tool_selected": bool(facts.get("unknown_tool_selected")),
        }
    for idx, rule in enumerate(llm_rules or [], start=1):
        values[f"llm_rule_{idx}_condition"] = bool(rule.get("risk"))
    return values


def evidence_for_method(method, active_terms, risk, solve_result):
    method = normalize_smt_method(method)
    if solve_result.get("result") == "UNKNOWN":
        return solve_result.get("error") or "Z3 returned UNKNOWN; no enforceable guard decision was made."
    if risk:
        terms = ", ".join(active_terms) if active_terms else "runtime_risk"
        if method == "ir_hoare":
            contracts = solve_result.get("ir_contracts") or []
            contract_text = ""
            if contracts:
                contract_names = ", ".join(
                    f"{item.get('template')}::{item.get('tool')}" for item in contracts[:3]
                )
                contract_text = f" Matched IR contracts: {contract_names}."
            return (
                "Z3 returned SAT over QF_SLIA string/regex constraints, meaning the IR Hoare contract "
                f"can be violated by: {terms}.{contract_text} The tool call should be blocked and rolled back."
            )
        if method == "hoare":
            return (
                "Z3 returned SAT, meaning the Hoare-style chain contract can be violated by: "
                f"{terms}. The tool call should be blocked and rolled back."
            )
        return f"Z3 returned SAT, meaning risk can be produced by: {terms}. The tool call should be blocked and rolled back."
    if method == "ir_hoare":
        return "Z3 returned UNSAT: the runtime strings satisfy the matched IR Hoare safety contract."
    if method == "hoare":
        return "Z3 returned UNSAT: the current chain transition satisfies the Hoare-style safety contract."
    return "Z3 returned UNSAT: under the current context facts, no risk-producing valuation exists."


def smt_symbol(value):
    symbol = re.sub(r"[^A-Za-z0-9_]", "_", str(value or "Tool"))
    return symbol or "Tool"


def _extract_template_facts(step, selected_attack_tools, *, force_safe=False):
    tool = str(step.get("tool") or "")
    input_data = step.get("input") or {}
    output_data = step.get("output") or {}
    path = step.get("path") or {}
    text = _flatten([tool, step.get("desc"), input_data, output_data, path]).lower()
    injected = str(input_data.get("injected_target_tool") or input_data.get("attack_tool") or "")
    selected_attack_tools = {name for name in selected_attack_tools if name}

    if force_safe:
        return {
            "tool_called": True,
            "called_injected_tool": False,
            "called_known_attack_tool": False,
            "observation_reports_attacker_goal": False,
            "sensitive_data_used": False,
            "external_send_or_export": False,
            "destructive_or_privileged_action": False,
            "financial_duplication_or_fraud": False,
            "medical_or_safety_harm": False,
            "unsafe_code_or_shell": False,
            "unknown_tool_selected": False,
        }

    available_tools = input_data.get("available_tools") or []
    available_names = {item.get("name") for item in available_tools if isinstance(item, dict) and item.get("name")}
    called_injected = bool(injected and tool == injected)
    called_attack = bool(tool in selected_attack_tools)
    attacker_goal = _has_any(text, ["attacker goal", "achieved the attacker goal", "used the attacker tool", "攻击目标", "攻击工具"])
    sensitive = bool(re.search(
        r"(id_card|身份证|phone|手机号|email|邮箱|secret|token|password|passwd|api[_-]?key|隐私|敏感|110101\d{8,}|\b\d{11}\b)",
        text,
    ))
    export = bool(re.search(r"(send|mail|email|post|upload|export|exfiltrat|发送|邮件|上传|外传|泄露)", text))
    destructive = bool(re.search(
        r"(rm\s+-rf|\bdelete\b|\bremove\b|\bunlink\b|drop\s+table|\bformat\b|\bsudo\b|\broot\b|\bshell\b|system\(|os\.system|subprocess|删除|清理|越权|权限提升|破坏)",
        text,
    ))
    finance = bool(re.search(r"(transactionduplication|duplicate.*transaction|交易.*重复|重复.*交易|fraud|转账|支付|扣款)", text))
    medical = bool(re.search(r"(surgicalerrors|surgical|medical|treatment|patient|手术|医疗|患者|治疗)", text))
    unsafe_code = bool(re.search(r"(eval\(|exec\(|pickle|反序列化|任意代码|danger_code|malicious_code|恶意代码)", text))
    unknown_tool = bool(available_names and tool not in available_names)

    return {
        "tool_called": True,
        "called_injected_tool": called_injected,
        "called_known_attack_tool": called_attack,
        "observation_reports_attacker_goal": attacker_goal,
        "sensitive_data_used": sensitive,
        "external_send_or_export": export,
        "destructive_or_privileged_action": destructive,
        "financial_duplication_or_fraud": finance,
        "medical_or_safety_harm": medical and (called_injected or called_attack or attacker_goal),
        "unsafe_code_or_shell": unsafe_code or destructive,
        "unknown_tool_selected": unknown_tool,
    }


def _extract_hoare_facts(step, selected_attack_tools, *, force_safe=False):
    tool = str(step.get("tool") or "")
    input_data = step.get("input") or {}
    output_data = step.get("output") or {}
    path = step.get("path") or {}
    selected_attack_tools = {name for name in selected_attack_tools if name}
    injected = str(input_data.get("injected_target_tool") or input_data.get("attack_tool") or "")

    if force_safe:
        return {
            "agent_input_untrusted": False,
            "agent_input_sensitive": False,
            "agent_input_financial_harm": False,
            "agent_input_medical_harm": False,
            "agent_input_code_harm": False,
            "agent_output_unsafe": False,
            "agent_output_external": False,
            "current_tool_can_change_world": False,
            "requested_attack_tool": False,
            "chain_attack_context": False,
            "unknown_tool_selected": False,
        }

    input_text = _flatten([input_data, path, step.get("desc")]).lower()
    output_text = _flatten([tool, output_data]).lower()
    chain_text = _flatten([step.get("agent"), step.get("desc"), input_data, output_data, path]).lower()

    available_tools = input_data.get("available_tools") or []
    available_names = {item.get("name") for item in available_tools if isinstance(item, dict) and item.get("name")}
    requested_attack_tool = bool((injected and tool == injected) or tool in selected_attack_tools)
    unknown_tool = bool(available_names and tool not in available_names)

    input_untrusted = bool(input_data.get("attack_type") or input_data.get("attack_tool") or injected) or _has_any(input_text, [
        "ignore previous", "must strictly adhere", "do not use other tools", "attacker instruction",
        "attacker goal", "jailbreak", "prompt injection", "忽略之前", "攻击目标", "攻击工具",
    ])
    input_sensitive = bool(re.search(
        r"(id_card|身份证|phone|手机号|email|邮箱|secret|token|password|passwd|api[_-]?key|隐私|敏感|110101\d{8,}|\b\d{11}\b)",
        input_text,
    ))
    input_finance = bool(re.search(r"(transactionduplication|duplicate.*transaction|fraud|redirect|divert|转账|支付|扣款|挪用|欺诈)", input_text))
    input_medical = bool(re.search(r"(surgicalerrors|surgical|medical|treatment|patient|手术|医疗|患者|治疗)", input_text))
    input_code = bool(re.search(r"(eval\(|exec\(|pickle|shell|system\(|os\.system|subprocess|任意代码|恶意代码)", input_text))

    output_external = bool(re.search(r"(send|mail|email|post|upload|export|exfiltrat|redirect|divert|发送|邮件|上传|外传|泄露)", output_text))
    output_unsafe = output_external or bool(re.search(
        r"(delete|remove|drop\s+table|sudo|root|shell|fraud|transaction|surgical|malicious|攻击|欺诈|转账|删除|恶意)",
        output_text,
    ))
    tool_can_change_world = output_external or bool(re.search(
        r"(send|mail|book|purchase|pay|transfer|delete|remove|write|update|execute|cmd|shell|transaction|surgical|redirect|divert)",
        output_text,
    ))
    chain_attack_context = requested_attack_tool or _has_any(chain_text, [
        "attacker instruction", "attacker goal", "attack_type", "attack_tool",
        "ignore previous", "must strictly adhere", "攻击目标", "攻击工具",
    ])

    return {
        "agent_input_untrusted": input_untrusted,
        "agent_input_sensitive": input_sensitive,
        "agent_input_financial_harm": input_finance,
        "agent_input_medical_harm": input_medical,
        "agent_input_code_harm": input_code,
        "agent_output_unsafe": output_unsafe,
        "agent_output_external": output_external,
        "current_tool_can_change_world": tool_can_change_world,
        "requested_attack_tool": requested_attack_tool,
        "chain_attack_context": chain_attack_context,
        "unknown_tool_selected": unknown_tool,
    }


def _template_condition_specs():
    return [
        ("attack_tool_invoked", "(or called_injected_tool called_known_attack_tool observation_reports_attacker_goal)",
         lambda b, z3: z3.Or([b["called_injected_tool"], b["called_known_attack_tool"], b["observation_reports_attacker_goal"]])),
        ("sensitive_exfiltration", "(and sensitive_data_used external_send_or_export)",
         lambda b, z3: z3.And(b["sensitive_data_used"], b["external_send_or_export"])),
        ("destructive_privileged_action", "destructive_or_privileged_action",
         lambda b, z3: b["destructive_or_privileged_action"]),
        ("financial_duplication_or_fraud", "financial_duplication_or_fraud",
         lambda b, z3: b["financial_duplication_or_fraud"]),
        ("medical_or_safety_harm", "medical_or_safety_harm",
         lambda b, z3: b["medical_or_safety_harm"]),
        ("unsafe_code_or_shell", "unsafe_code_or_shell",
         lambda b, z3: b["unsafe_code_or_shell"]),
        ("unknown_tool_selected", "unknown_tool_selected",
         lambda b, z3: b["unknown_tool_selected"]),
    ]


def _hoare_condition_specs():
    return [
        ("hoare_precondition_violation", "(and agent_input_untrusted requested_attack_tool)",
         lambda b, z3: z3.And(b["agent_input_untrusted"], b["requested_attack_tool"])),
        ("hoare_postcondition_violation", "(and agent_output_unsafe current_tool_can_change_world)",
         lambda b, z3: z3.And(b["agent_output_unsafe"], b["current_tool_can_change_world"])),
        ("hoare_context_chain_anomaly", "(and chain_attack_context (or requested_attack_tool current_tool_can_change_world unknown_tool_selected))",
         lambda b, z3: z3.And(
             b["chain_attack_context"],
             z3.Or([b["requested_attack_tool"], b["current_tool_can_change_world"], b["unknown_tool_selected"]]),
         )),
        ("hoare_sensitive_leak_contract", "(and agent_input_sensitive agent_output_external)",
         lambda b, z3: z3.And(b["agent_input_sensitive"], b["agent_output_external"])),
        ("hoare_harmful_transition", "(and (or agent_input_financial_harm agent_input_medical_harm agent_input_code_harm) (or agent_output_external current_tool_can_change_world requested_attack_tool))",
         lambda b, z3: z3.And(
             z3.Or([b["agent_input_financial_harm"], b["agent_input_medical_harm"], b["agent_input_code_harm"]]),
             z3.Or([b["agent_output_external"], b["current_tool_can_change_world"], b["requested_attack_tool"]]),
         )),
        ("unknown_tool_selected", "unknown_tool_selected",
         lambda b, z3: b["unknown_tool_selected"]),
    ]


IR_DERIVED_REGEX_FACTS = {
    "query_regex_unsafe",
    "output_regex_unsafe",
    "query_sensitive_regex",
    "output_sensitive_regex",
    "query_private_data_regex",
    "output_private_data_regex",
    "output_external_regex",
    "query_destructive_regex",
}

QUERY_UNSAFE_REGEXES = [
    r"ignore\s+(all\s+)?previous",
    r"do\s+not\s+use\s+other\s+tools",
    r"must\s+strictly\s+adhere",
    r"attacker\s+(instruction|goal|tool)",
    r"prompt\s+injection",
    r"jailbreak",
    r"绕过|忽略之前|攻击目标|攻击工具|越权",
]
QUERY_UNSAFE_LITERALS = [
    "ignore previous",
    "do not use other tools",
    "must strictly adhere",
    "attacker instruction",
    "attacker goal",
    "attacker tool",
    "prompt injection",
    "jailbreak",
    "忽略之前",
    "攻击目标",
    "攻击工具",
    "越权",
]
OUTPUT_UNSAFE_REGEXES = [
    r"rm\s+-rf",
    r"drop\s+table",
    r"sudo\b|root\b|shell\b|os\.system|subprocess|eval\(|exec\(",
    r"\b(delete|remove|unlink|privileged|malicious|fraud|hijack|exfiltrat)\b",
    r"删除|清理|越权|权限提升|恶意|欺诈|泄露|劫持|外传|注入",
]
OUTPUT_UNSAFE_LITERALS = [
    "rm -rf",
    "drop table",
    "sudo",
    "root",
    "shell",
    "os.system",
    "subprocess",
    "eval(",
    "exec(",
    "delete",
    "remove",
    "privileged",
    "malicious",
    "fraud",
    "hijack",
    "exfiltrat",
    "删除",
    "清理",
    "越权",
    "权限提升",
    "恶意",
    "欺诈",
    "泄露",
    "劫持",
    "外传",
    "注入",
]
SENSITIVE_REGEXES = [
    r"id[_-]?card|身份证",
    r"phone|手机号|\b\d{11}\b",
    r"email|邮箱|[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    r"secret|token|password|passwd|api[_-]?key|credential|凭证|密钥|账号|密码|隐私|敏感",
    r"\b\d{17}[0-9Xx]\b",
]
PRIVATE_DATA_REGEXES = [
    r"id[_-]?card|身份证",
    r"手机号|\b\d{11}\b",
    r"secret|token|password|passwd|api[_-]?key|密钥|密码|隐私明文",
    r"\b\d{17}[0-9Xx]\b",
]
PRIVATE_DATA_LITERALS = [
    "id_card",
    "身份证",
    "手机号",
    "secret",
    "token",
    "password",
    "passwd",
    "api_key",
    "api-key",
    "密钥",
    "密码",
    "隐私明文",
]

SENSITIVE_LITERALS = [
    "id_card",
    "身份证",
    "phone",
    "手机号",
    "email",
    "邮箱",
    "secret",
    "token",
    "password",
    "passwd",
    "api_key",
    "api-key",
    "credential",
    "凭证",
    "密钥",
    "账号",
    "密码",
    "隐私",
    "敏感",
]
EXTERNAL_REGEXES = [
    r"send|mail|email|post|upload|export|exfiltrat|redirect|divert|webhook|http[s]?://",
    r"发送|邮件|上传|外传|泄露|转发|公网|第三方|跨域|已发送",
]
EXTERNAL_LITERALS = [
    "send",
    "mail",
    "email",
    "post",
    "upload",
    "export",
    "exfiltrat",
    "redirect",
    "divert",
    "webhook",
    "http://",
    "https://",
    "发送",
    "邮件",
    "上传",
    "外传",
    "泄露",
    "转发",
    "公网",
    "第三方",
    "跨域",
    "已发送",
]
DESTRUCTIVE_REGEXES = [
    r"rm\s+-rf|\b(delete|remove|unlink|format|kill|prune|sudo|root|shell|cmd|execute)\b|drop\s+table|os\.system|subprocess",
    r"删除|清理|销毁|终止|命令|脚本|越权|权限提升|破坏",
]
DESTRUCTIVE_LITERALS = [
    "rm -rf",
    "delete",
    "remove",
    "unlink",
    "drop table",
    "kill",
    "prune",
    "sudo",
    "root",
    "shell",
    "cmd",
    "execute",
    "os.system",
    "subprocess",
    "删除",
    "清理",
    "销毁",
    "终止",
    "命令",
    "脚本",
    "越权",
    "权限提升",
    "破坏",
]
CHANGE_WORLD_REGEXES = [
    r"send|mail|book|purchase|pay|transfer|delete|remove|clear|clean|write|update|execute|cmd|shell|transaction|surgical|redirect|divert|upload|export|prune|kill|run",
    r"发送|邮件|订票|预订|支付|转账|删除|清理|写入|更新|执行|命令|上传|外传|回滚|停止",
]


def _extract_ir_hoare_facts(step, selected_attack_tools, *, force_safe=False):
    base = _extract_hoare_facts(step, selected_attack_tools, force_safe=force_safe)
    tool = str(step.get("tool") or "")
    input_data = step.get("input") or {}
    output_data = step.get("output") or {}
    path = step.get("path") or {}
    query_text = _truncate_ir_text(_flatten([
        input_data.get("task"),
        input_data.get("query"),
        input_data.get("step_goal"),
        input_data.get("raw_prompt"),
        input_data.get("parameters"),
        input_data,
        step.get("desc"),
        path,
    ])).lower()
    output_text = _truncate_ir_text(_flatten([tool, output_data])).lower()
    context_text = _truncate_ir_text(_flatten([step.get("agent"), tool, step.get("desc"), input_data, output_data, path])).lower()
    index = _load_ir_contract_index()
    runtime_contracts = _runtime_ir_contracts(step)
    direct_contracts = runtime_contracts or _direct_ir_contracts(step, index)
    contracts = direct_contracts or _ranked_template_contracts(step, index)[:3]
    flags = _merge_contract_flags(contracts)

    query_sensitive = _regex_any(query_text, SENSITIVE_REGEXES)
    output_sensitive = _regex_any(output_text, SENSITIVE_REGEXES)
    query_private_data = _regex_any(query_text, PRIVATE_DATA_REGEXES)
    output_private_data = _regex_any(output_text, PRIVATE_DATA_REGEXES)
    output_external = _regex_any(output_text, EXTERNAL_REGEXES) or _regex_any(query_text, [r"@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"])
    query_destructive = _regex_any(query_text, DESTRUCTIVE_REGEXES)
    change_world = base.get("current_tool_can_change_world") or _regex_any(context_text, CHANGE_WORLD_REGEXES)

    if force_safe:
        query_text = "safe query"
        output_text = "safe output"
        base.update({
            "agent_input_untrusted": False,
            "agent_input_sensitive": False,
            "agent_input_financial_harm": False,
            "agent_input_medical_harm": False,
            "agent_input_code_harm": False,
            "agent_output_unsafe": False,
            "agent_output_external": False,
            "current_tool_can_change_world": False,
            "requested_attack_tool": False,
            "chain_attack_context": False,
            "unknown_tool_selected": False,
        })
        query_sensitive = False
        output_sensitive = False
        query_private_data = False
        output_private_data = False
        output_external = False
        query_destructive = False
        change_world = False

    runtime_match = bool(runtime_contracts)
    exact_match = bool(direct_contracts)
    context_available = exact_match or bool(index.get("contracts"))
    base.update({
        "ir_exact_contract_matched": exact_match,
        "ir_runtime_contract_matched": runtime_match,
        "ir_template_fallback": bool(not exact_match and index.get("contracts")),
        "ir_context_available": context_available,
        "ir_tool_has_sensitive_contract": bool(flags.get("sensitive")),
        "ir_tool_has_external_contract": bool(flags.get("external")),
        "ir_tool_has_privilege_contract": bool(flags.get("privilege")),
        "ir_tool_has_delete_contract": bool(flags.get("delete")),
        "ir_tool_has_code_contract": bool(flags.get("code")),
        "ir_contract_mentions_rollback": bool(flags.get("rollback")),
        "ir_contract_has_negative_predicate": bool(flags.get("negative")),
        "query_regex_unsafe": False if force_safe else _regex_any(query_text, QUERY_UNSAFE_REGEXES),
        "output_regex_unsafe": False if force_safe else _regex_any(output_text, OUTPUT_UNSAFE_REGEXES),
        "query_sensitive_regex": bool(query_sensitive),
        "output_sensitive_regex": bool(output_sensitive),
        "query_private_data_regex": bool(query_private_data),
        "output_private_data_regex": bool(output_private_data),
        "output_external_regex": bool(output_external),
        "query_destructive_regex": bool(query_destructive),
        "current_tool_can_change_world": bool(change_world),
    })
    base["_ir_meta"] = {
        "logic": "QF_SLIA",
        "query_text": query_text,
        "output_text": output_text,
        "context_text": context_text,
        "matched_contracts": [_contract_summary(contract) for contract in contracts[:5]],
        "runtime_ir_generated": runtime_match,
        "deepseek_generated_ir": step.get("deepseek_generated_ir") or "",
        "deepseek_generated_ir_meta": step.get("deepseek_generated_ir_meta") or {},
        "template_fallback": bool(not exact_match and index.get("contracts")),
        "template_count": len(index.get("templates") or []),
        "contract_count": len(index.get("contracts") or []),
    }
    return base


def _ir_hoare_condition_specs():
    return [
        (
            "ir_contract_precondition_violation",
            "(and ir_context_available agent_input_untrusted requested_attack_tool)",
            lambda b, z3: z3.And(b["ir_context_available"], b["agent_input_untrusted"], b["requested_attack_tool"]),
        ),
        (
            "ir_regex_query_violation",
            "(and ir_context_available query_regex_unsafe (or requested_attack_tool ir_tool_has_privilege_contract ir_tool_has_code_contract))",
            lambda b, z3: z3.And(
                b["ir_context_available"],
                b["query_regex_unsafe"],
                z3.Or([b["requested_attack_tool"], b["ir_tool_has_privilege_contract"], b["ir_tool_has_code_contract"]]),
            ),
        ),
        (
            "ir_contract_postcondition_violation",
            "(and ir_context_available (or output_regex_unsafe query_destructive_regex (and agent_output_unsafe (or ir_tool_has_privilege_contract ir_tool_has_delete_contract ir_tool_has_code_contract))) (or current_tool_can_change_world requested_attack_tool))",
            lambda b, z3: z3.And(
                b["ir_context_available"],
                z3.Or([
                    b["output_regex_unsafe"],
                    b["query_destructive_regex"],
                    z3.And(
                        b["agent_output_unsafe"],
                        z3.Or([b["ir_tool_has_privilege_contract"], b["ir_tool_has_delete_contract"], b["ir_tool_has_code_contract"]]),
                    ),
                ]),
                z3.Or([b["current_tool_can_change_world"], b["requested_attack_tool"]]),
            ),
        ),
        (
            "ir_sensitive_flow_violation",
            "(and ir_context_available (or query_private_data_regex output_private_data_regex) (or agent_output_external output_external_regex current_tool_can_change_world ir_tool_has_external_contract))",
            lambda b, z3: z3.And(
                b["ir_context_available"],
                z3.Or([b["query_private_data_regex"], b["output_private_data_regex"]]),
                z3.Or([b["agent_output_external"], b["output_external_regex"], b["current_tool_can_change_world"], b["ir_tool_has_external_contract"]]),
            ),
        ),
        (
            "ir_harmful_transition",
            "(and ir_context_available (or agent_input_financial_harm agent_input_medical_harm agent_input_code_harm query_destructive_regex) (or current_tool_can_change_world requested_attack_tool ir_contract_has_negative_predicate))",
            lambda b, z3: z3.And(
                b["ir_context_available"],
                z3.Or([
                    b["agent_input_financial_harm"],
                    b["agent_input_medical_harm"],
                    b["agent_input_code_harm"],
                    b["query_destructive_regex"],
                ]),
                z3.Or([b["current_tool_can_change_world"], b["requested_attack_tool"], b["ir_contract_has_negative_predicate"]]),
            ),
        ),
        (
            "unknown_tool_selected",
            "unknown_tool_selected",
            lambda b, z3: b["unknown_tool_selected"],
        ),
    ]


def _build_ir_hoare_smt_formula(step, facts, llm_rules):
    meta = facts.get("_ir_meta") or {}
    tool_symbol = smt_symbol(step.get("tool", "Tool"))
    query_text = meta.get("query_text") or ""
    output_text = meta.get("output_text") or ""
    llm_facts = {f"llm_rule_{idx}_risk": bool(rule.get("risk")) for idx, rule in enumerate(llm_rules or [], start=1)}
    bool_facts = {name: value for name, value in facts.items() if isinstance(value, bool)}
    all_bools = {**bool_facts, **llm_facts}
    condition_specs = _ir_hoare_condition_specs()

    lines = [
        ";; SMT guard formula method: ir_hoare.",
        ";; Semantics: SAT means there exists a runtime string valuation that violates an IR Hoare contract.",
        ";; QF_UF is intentionally not used here: this variant uses String and RegLan constraints.",
        "(set-logic QF_SLIA)",
        f"(declare-const call_{tool_symbol} Bool)",
        "(declare-const query_text String)",
        "(declare-const output_text String)",
        f"(assert call_{tool_symbol})",
        f"(assert (= query_text {_smt_string(query_text)}))",
        f"(assert (= output_text {_smt_string(output_text)}))",
    ]
    if meta.get("runtime_ir_generated"):
        lines.append(";; IR source: DeepSeek-generated runtime agent_security.ir for the tested sample.")
    for contract in meta.get("matched_contracts") or []:
        lines.append(f";; IR contract: {contract.get('template')}::{contract.get('tool')}")
        for raw_line in (contract.get("raw") or "").splitlines()[:8]:
            lines.append(f";;   {raw_line[:180]}")
    if meta.get("template_fallback"):
        lines.append(";; No exact CALL(tool) match in agent_security.ir; using global IR-derived safety clauses as fallback.")

    for name in sorted(all_bools):
        lines.append(f"(declare-const {name} Bool)")
    for name, _expr, _builder in condition_specs:
        lines.append(f"(declare-const {name} Bool)")
    lines.append("(declare-const runtime_risk Bool)")

    for name in sorted(IR_DERIVED_REGEX_FACTS):
        if name not in all_bools:
            continue
        target = "query_text" if name.startswith("query_") else "output_text"
        lines.append(f"(assert (= {name} {_smt_regex_fact_expr(name, target)}))")
    for name, value in sorted(all_bools.items()):
        if name in IR_DERIVED_REGEX_FACTS:
            continue
        lines.append(f"(assert {name if value else f'(not {name})'})")
    for name, expr, _builder in condition_specs:
        lines.append(f"(assert (= {name} {expr}))")
    for name, value in llm_facts.items():
        lines.append(f";; LLM rule fact {name}: {value}")
    condition_names = " ".join([name for name, _expr, _builder in condition_specs] + list(llm_facts))
    lines.append(f"(assert (= runtime_risk (or {condition_names})))")
    lines.append("(assert runtime_risk)")
    lines.append("(check-sat)")
    lines.append("(get-model)")
    return "\n".join(lines)


def _solve_ir_hoare_with_z3(z3_module, facts, llm_rules):
    meta = facts.get("_ir_meta") or {}
    bool_facts = {name: value for name, value in facts.items() if isinstance(value, bool)}
    llm_facts = {f"llm_rule_{idx}_risk": bool(rule.get("risk")) for idx, rule in enumerate(llm_rules or [], start=1)}
    all_bools = {**bool_facts, **llm_facts}
    bools = {name: z3_module.Bool(name) for name in all_bools}
    solver = z3_module.Solver()

    query_text = z3_module.String("query_text")
    output_text = z3_module.String("output_text")
    solver.add(query_text == z3_module.StringVal(meta.get("query_text") or ""))
    solver.add(output_text == z3_module.StringVal(meta.get("output_text") or ""))

    for name, value in all_bools.items():
        if name in IR_DERIVED_REGEX_FACTS:
            target = query_text if name.startswith("query_") else output_text
            solver.add(bools[name] == _z3_regex_fact_expr(z3_module, name, target))
        else:
            solver.add(bools[name] == z3_module.BoolVal(bool(value)))

    condition_exprs = []
    for name, _expr, builder in _ir_hoare_condition_specs():
        expr = builder(bools, z3_module)
        condition_exprs.append((name, expr))
    for idx, rule in enumerate(llm_rules or [], start=1):
        fact_name = f"llm_rule_{idx}_risk"
        condition_exprs.append((f"llm_rule_{idx}_condition", bools[fact_name]))

    runtime_risk = z3_module.Bool("runtime_risk")
    solver.add(runtime_risk == z3_module.Or([expr for _name, expr in condition_exprs]))
    solver.add(runtime_risk)
    result = solver.check()
    if result == z3_module.sat:
        z3_model = solver.model()
        model = {decl.name(): str(z3_model[decl]) for decl in z3_model.decls()}
        condition_values = {
            name: bool(z3_module.is_true(z3_model.evaluate(expr, model_completion=True)))
            for name, expr in condition_exprs
        }
        return {
            "result": "SAT",
            "solver": "z3-string-regex",
            "model": model,
            "condition_values": condition_values,
            "ir_contracts": meta.get("matched_contracts") or [],
            "logic": "QF_SLIA",
        }
    if result == z3_module.unsat:
        return {
            "result": "UNSAT",
            "solver": "z3-string-regex",
            "model": {},
            "condition_values": _evaluate_ir_hoare_condition_values(facts, llm_rules),
            "ir_contracts": meta.get("matched_contracts") or [],
            "logic": "QF_SLIA",
        }
    return {"result": "UNKNOWN", "solver": "z3-string-regex", "model": {}, "condition_values": {}, "logic": "QF_SLIA"}


def _evaluate_ir_hoare_condition_values(facts, llm_rules=None):
    values = {
        "ir_contract_precondition_violation": bool(
            facts.get("ir_context_available") and facts.get("agent_input_untrusted") and facts.get("requested_attack_tool")
        ),
        "ir_regex_query_violation": bool(
            facts.get("ir_context_available")
            and facts.get("query_regex_unsafe")
            and (
                facts.get("requested_attack_tool")
                or facts.get("ir_tool_has_privilege_contract")
                or facts.get("ir_tool_has_code_contract")
            )
        ),
        "ir_contract_postcondition_violation": bool(
            facts.get("ir_context_available")
            and (
                facts.get("output_regex_unsafe")
                or facts.get("query_destructive_regex")
                or (
                    facts.get("agent_output_unsafe")
                    and (
                        facts.get("ir_tool_has_privilege_contract")
                        or facts.get("ir_tool_has_delete_contract")
                        or facts.get("ir_tool_has_code_contract")
                    )
                )
            )
            and (facts.get("current_tool_can_change_world") or facts.get("requested_attack_tool"))
        ),
        "ir_sensitive_flow_violation": bool(
            facts.get("ir_context_available")
            and (facts.get("query_private_data_regex") or facts.get("output_private_data_regex"))
            and (
                facts.get("agent_output_external")
                or facts.get("output_external_regex")
                or facts.get("current_tool_can_change_world")
                or facts.get("ir_tool_has_external_contract")
            )
        ),
        "ir_harmful_transition": bool(
            facts.get("ir_context_available")
            and (
                facts.get("agent_input_financial_harm")
                or facts.get("agent_input_medical_harm")
                or facts.get("agent_input_code_harm")
                or facts.get("query_destructive_regex")
            )
            and (
                facts.get("current_tool_can_change_world")
                or facts.get("requested_attack_tool")
                or facts.get("ir_contract_has_negative_predicate")
            )
        ),
        "unknown_tool_selected": bool(facts.get("unknown_tool_selected")),
    }
    for idx, rule in enumerate(llm_rules or [], start=1):
        values[f"llm_rule_{idx}_condition"] = bool(rule.get("risk"))
    return values


def _z3_regex_fact_expr(z3, name, target):
    if name == "query_regex_unsafe":
        return _z3_any_match(z3, target, QUERY_UNSAFE_LITERALS)
    if name == "output_regex_unsafe":
        return _z3_any_match(z3, target, OUTPUT_UNSAFE_LITERALS, include_digits=False)
    if name == "query_sensitive_regex":
        return _z3_sensitive_match(z3, target)
    if name == "output_sensitive_regex":
        return _z3_sensitive_match(z3, target)
    if name == "query_private_data_regex":
        return _z3_private_data_match(z3, target)
    if name == "output_private_data_regex":
        return _z3_private_data_match(z3, target)
    if name == "output_external_regex":
        return _z3_any_match(z3, target, EXTERNAL_LITERALS)
    if name == "query_destructive_regex":
        return _z3_any_match(z3, target, DESTRUCTIVE_LITERALS)
    return z3.BoolVal(False)


def _z3_any_match(z3, target, literals, include_digits=False):
    exprs = [z3.InRe(target, _z3_contains_literal(z3, literal)) for literal in literals if literal]
    if include_digits:
        exprs.append(z3.InRe(target, _z3_contains_re(z3, _z3_repeat_range(z3, "0", "9", 11))))
        exprs.append(z3.InRe(target, _z3_contains_re(z3, _z3_repeat_range(z3, "0", "9", 18))))
    if not exprs:
        return z3.BoolVal(False)
    return z3.Or(exprs)


def _z3_sensitive_match(z3, target):
    return _z3_any_match(z3, target, SENSITIVE_LITERALS, include_digits=True)


def _z3_private_data_match(z3, target):
    return _z3_any_match(z3, target, PRIVATE_DATA_LITERALS, include_digits=True)


def _z3_contains_literal(z3, literal):
    return _z3_contains_re(z3, z3.Re(str(literal)))


def _z3_contains_re(z3, regex):
    any_char = z3.Star(z3.AllChar(z3.ReSort(z3.StringSort())))
    return _z3_re_concat(z3, [any_char, regex, any_char])


def _z3_repeat_range(z3, start, end, count):
    return _z3_re_concat(z3, [z3.Range(start, end) for _idx in range(count)])


def _z3_re_concat(z3, parts):
    if not parts:
        return z3.Re("")
    expr = parts[0]
    for part in parts[1:]:
        expr = z3.Concat(expr, part)
    return expr


def _smt_regex_fact_expr(name, target):
    if name == "query_regex_unsafe":
        return _smt_any_match_expr(target, QUERY_UNSAFE_LITERALS)
    if name == "output_regex_unsafe":
        return _smt_any_match_expr(target, OUTPUT_UNSAFE_LITERALS)
    if name == "query_sensitive_regex":
        return _smt_sensitive_match_expr(target)
    if name == "output_sensitive_regex":
        return _smt_sensitive_match_expr(target)
    if name == "query_private_data_regex":
        return _smt_private_data_match_expr(target)
    if name == "output_private_data_regex":
        return _smt_private_data_match_expr(target)
    if name == "output_external_regex":
        return _smt_any_match_expr(target, EXTERNAL_LITERALS)
    if name == "query_destructive_regex":
        return _smt_any_match_expr(target, DESTRUCTIVE_LITERALS)
    return "false"


def _smt_sensitive_match_expr(target):
    exprs = [_smt_contains_literal_expr(target, literal) for literal in SENSITIVE_LITERALS if literal]
    exprs.append(f"(str.in_re {target} {_smt_contains_re_expr(_smt_repeat_range_expr('0', '9', 11))})")
    exprs.append(f"(str.in_re {target} {_smt_contains_re_expr(_smt_repeat_range_expr('0', '9', 18))})")
    return _smt_or(exprs)


def _smt_private_data_match_expr(target):
    exprs = [_smt_contains_literal_expr(target, literal) for literal in PRIVATE_DATA_LITERALS if literal]
    exprs.append(f"(str.in_re {target} {_smt_contains_re_expr(_smt_repeat_range_expr('0', '9', 11))})")
    exprs.append(f"(str.in_re {target} {_smt_contains_re_expr(_smt_repeat_range_expr('0', '9', 18))})")
    return _smt_or(exprs)


def _smt_any_match_expr(target, literals):
    return _smt_or([_smt_contains_literal_expr(target, literal) for literal in literals if literal])


def _smt_contains_literal_expr(target, literal):
    return f"(str.in_re {target} {_smt_contains_re_expr(f'(str.to_re {_smt_string(literal)})')})"


def _smt_contains_re_expr(regex_expr):
    return f"(re.++ (re.* re.allchar) {regex_expr} (re.* re.allchar))"


def _smt_repeat_range_expr(start, end, count):
    parts = " ".join(f"(re.range {_smt_string(start)} {_smt_string(end)})" for _idx in range(count))
    return f"(re.++ {parts})"


def _smt_or(exprs):
    exprs = [expr for expr in exprs if expr]
    if not exprs:
        return "false"
    if len(exprs) == 1:
        return exprs[0]
    return f"(or {' '.join(exprs)})"


def _smt_string(value):
    text = _truncate_ir_text(str(value or ""))
    text = text.replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return '"' + text.replace('"', '""') + '"'


def _runtime_ir_contracts(step):
    ir_text = str(step.get("deepseek_generated_ir") or "").strip()
    if not ir_text:
        return []
    template = "deepseek-runtime"
    contracts = _parse_ir_contracts(template, Path("<deepseek_generated_ir>"), ir_text)
    tool_names = {
        str(value or "").lower()
        for value in [
            step.get("tool"),
            (step.get("output") or {}).get("called_tool") if isinstance(step.get("output"), dict) else None,
            (step.get("output") or {}).get("actual_called_tool") if isinstance(step.get("output"), dict) else None,
        ]
        if value
    }
    matched = []
    for contract in contracts:
        if str(contract.get("tool") or "").lower() in tool_names:
            contract["runtime_generated"] = True
            matched.append(contract)
    return matched[:6]


def _direct_ir_contracts(step, index=None):
    index = index or _load_ir_contract_index()
    tool_names = [
        step.get("tool"),
        (step.get("output") or {}).get("called_tool") if isinstance(step.get("output"), dict) else None,
        (step.get("output") or {}).get("actual_called_tool") if isinstance(step.get("output"), dict) else None,
    ]
    matches = []
    seen = set()
    for tool_name in tool_names:
        key = str(tool_name or "").lower()
        for contract in index.get("by_tool", {}).get(key, []):
            identity = (contract.get("template"), contract.get("tool"), contract.get("call_index"))
            if identity not in seen:
                seen.add(identity)
                matches.append(contract)
    return matches[:6]


def _ranked_template_contracts(step, index):
    context = _flatten([step.get("agent"), step.get("tool"), step.get("desc"), step.get("input"), step.get("output")]).lower()
    ranked = []
    for template, contracts in (index.get("by_template") or {}).items():
        tokens = [token for token in re.split(r"[-_\s]+", template.lower()) if len(token) >= 4]
        score = sum(1 for token in tokens if token in context)
        if score:
            ranked.extend(contracts[:2])
    return ranked


@lru_cache(maxsize=1)
def _load_ir_contract_index():
    root = Path(__file__).resolve().parent / "chain_data" / "inner_representation"
    contracts = []
    by_tool = {}
    by_template = {}
    if not root.exists():
        return {"contracts": contracts, "by_tool": by_tool, "by_template": by_template, "templates": []}
    for ir_path in sorted(root.glob("*/agent_security.ir")):
        template = ir_path.parent.name
        try:
            ir_text = ir_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        template_contracts = _parse_ir_contracts(template, ir_path, ir_text)
        contracts.extend(template_contracts)
        by_template.setdefault(template, []).extend(template_contracts)
        for contract in template_contracts:
            by_tool.setdefault(str(contract.get("tool") or "").lower(), []).append(contract)
    return {
        "contracts": contracts,
        "by_tool": by_tool,
        "by_template": by_template,
        "templates": sorted(by_template),
    }


def _parse_ir_contracts(template, ir_path, ir_text):
    lines = [_strip_ir_line(line) for line in ir_text.splitlines()]
    lines = [line for line in lines if line]
    call_positions = []
    for idx, line in enumerate(lines):
        match = re.search(r"\bCALL\(\s*([A-Za-z_][A-Za-z0-9_]*)", line)
        if match:
            call_positions.append((idx, match.group(1)))
    contracts = []
    for call_no, (idx, tool) in enumerate(call_positions, start=1):
        previous_call_idx = call_positions[call_no - 2][0] + 1 if call_no > 1 else 0
        previous_labels = [pos for pos, line in enumerate(lines[:idx]) if line.startswith("LABEL")]
        prev_idx = max(previous_call_idx, previous_labels[-1] if previous_labels else 0)
        next_idx = call_positions[call_no][0] if call_no < len(call_positions) else len(lines)
        window = lines[prev_idx:next_idx]
        raw = "\n".join(window)
        contract = {
            "template": template,
            "ir_path": str(ir_path),
            "tool": tool,
            "call_index": call_no,
            "raw": raw,
            "asserts": [line for line in window if line.startswith("ASSERT")],
            "ifs": [line for line in window if line.startswith("IF")],
            "labels": [line for line in window if line.startswith("LABEL")],
            "extracts": _parse_ir_extracts(window),
        }
        contract["flags"] = _contract_flags("\n".join([lines[idx], *contract["asserts"], *contract["ifs"]]))
        contracts.append(contract)
    return contracts


def _strip_ir_line(line):
    text = str(line or "").strip()
    if not text or text.startswith("//"):
        return ""
    if "//" in text and '"' not in text.split("//", 1)[0]:
        text = text.split("//", 1)[0].strip()
    return text


def _parse_ir_extracts(lines):
    extracts = []
    for line in lines:
        match = re.search(r"EXTRACT\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*\"([^\"]*)\"\s*\)", line)
        if match:
            extracts.append({
                "name": match.group(1).strip(),
                "source": match.group(2).strip(),
                "description": match.group(3).strip(),
            })
    return extracts


def _contract_flags(raw):
    text = str(raw or "").lower()
    return {
        "sensitive": bool(re.search(r"private|sensitive|credential|secret|token|password|passwd|api[_-]?key|id[_-]?card|idcard|phone|mail_pwd|隐私|敏感|身份证|手机号|凭证|密钥|账号|密码", text)),
        "external": bool(re.search(r"external|mail|email|upload|send|third|api|webhook|cross|domain|外发|上传|邮件|发送|第三方|跨域|公网", text)),
        "privilege": bool(re.search(r"privilege|root|sudo|authorized|permission|admin|越权|权限|授权|特权|最小权限", text)),
        "delete": bool(re.search(r"delete|remove|prune|clean|kill|rm\s+-rf|unlink|删除|清理|销毁|停止|终止", text)),
        "code": bool(re.search(r"script|shell|cmd|command|exec|eval|subprocess|代码|脚本|命令|注入|执行", text)),
        "rollback": bool(re.search(r"rollback|l_risk|risk_rollback|风险|回滚|阻断", text)),
        "negative": bool(re.search(r"¬|禁止|不得|不|无|forbid|not\b|without", text)),
    }


def _merge_contract_flags(contracts):
    merged = {
        "sensitive": False,
        "external": False,
        "privilege": False,
        "delete": False,
        "code": False,
        "rollback": False,
        "negative": False,
    }
    for contract in contracts or []:
        for name, value in (contract.get("flags") or {}).items():
            merged[name] = bool(merged.get(name) or value)
    return merged


def _contract_summary(contract):
    return {
        "template": contract.get("template"),
        "tool": contract.get("tool"),
        "call_index": contract.get("call_index"),
        "flags": contract.get("flags") or {},
        "asserts": contract.get("asserts") or [],
        "ifs": contract.get("ifs") or [],
        "raw": _truncate_ir_text(contract.get("raw") or "", limit=1200),
    }


def _regex_any(text, patterns):
    value = str(text or "")
    return any(re.search(pattern, value, flags=re.IGNORECASE) for pattern in patterns)


def _truncate_ir_text(text, limit=IR_TEXT_LIMIT):
    value = str(text or "")
    if len(value) <= limit:
        return value
    return value[:limit] + "...[truncated]"


def _has_any(text, markers):
    return any(marker in text for marker in markers)


def _flatten(value):
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except Exception:
        return str(value)
