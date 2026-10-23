from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from datetime import datetime
import json
import os
from asb_bridge import init_asb_routes
from toolbench_bridge import init_toolbench_routes
from smt_guard import apply_smt_guard_to_steps
from smt_rule_engine import normalize_smt_method

# 初始化Flask应用
app = Flask(__name__)
app.secret_key = "agent_security_sat_2025"  # 会话密钥
init_asb_routes(app)
init_toolbench_routes(app)

# ===================== 模拟数据 =====================
# 用户账号
users = {
    "user": "user123",
    "admin": "admin123"
}

# 约束规则
rules = [
    {"id": 1, "name": "权限越界检测", "content": "禁止智能体访问未授权系统API"},
    {"id": 2, "name": "数据泄露防护", "content": "禁止输出敏感隐私数据"},
    {"id": 3, "name": "执行逻辑安全", "content": "禁止循环死锁与恶意递归"}
]

# 检测历史
history = [
    {"id": 1, "agent": "ToolLLaMA", "method": "DFS", "time": "2.5s", "result": "安全", "date": "2025-01-10"},
    {"id": 2, "agent": "ChatGLM", "method": "SAT", "time": "0.8s", "result": "安全", "date": "2025-01-10"},
    {"id": 3, "agent": "Qwen", "method": "混合验证", "time": "1.2s", "result": "发现风险", "date": "2025-01-11"}
]

# 对比数据
compare_data = {
    "dfs": {"time": 2.5, "accuracy": 89, "risk": 3},
    "sat": {"time": 0.8, "accuracy": 97, "risk": 0},
    "reduce": 1.7  # 减少1.7秒
}

# 历史调用记录
history_chain = []

# ===================== 路由 =====================
# 首页（优势展示）
@app.route('/')
def index():
    return render_template('index.html')

# 登录
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and users[username] == password:
            session['user'] = username
            if username == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('user_dashboard'))
        else:
            flash("账号或密码错误")
    
    return render_template('login.html')

# 退出登录
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ===================== 用户侧 =====================
@app.route('/user/dashboard')
def user_dashboard():
    if 'user' not in session or session['user'] != 'user':
        return redirect(url_for('login'))
    return render_template('user/dashboard.html')

# 动态监管
@app.route('/user/dynamic', methods=['GET', 'POST'])
def user_dynamic():
    if request.method == 'POST':
        # 假设前端POST过来一个json，包含检查结果
        result = request.json
        # 读取已有结果
        file_path = 'chain_data/dynamic_check_results.json'
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                results = json.load(f)
        else:
            results = []
        # 添加新结果
        results.append(result)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        return jsonify({'status': 'success'})
    else:
        return render_template('user/dynamic.html', data=compare_data)


# 程序代码智能体运行时安全检查
@app.route('/user/code_runtime', methods=['GET', 'POST'])
def user_code_runtime():
    if request.method == 'POST':
        result = request.json
        file_path = 'chain_data/code_runtime_check_results.json'
        if os.path.exists(file_path):
            with open(file_path, 'r', encoding='utf-8') as f:
                results = json.load(f)
        else:
            results = []
        results.append(result)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, ensure_ascii=False, indent=2)
        return jsonify({'status': 'success'})
    return render_template('user/code_runtime.html')


@app.route('/user/code_runtime_step', methods=['POST'])
def user_code_runtime_step():
    idx = int(request.json.get('idx', 0))
    scenario = request.json.get('scenario', 'log_cleanup')
    chain_path = 'chain_data/code_agent_chain.json'

    with open(chain_path, 'r', encoding='utf-8') as f:
        chains = json.load(f)

    chain = chains.get(scenario) or chains.get('log_cleanup', [])
    if idx < len(chain):
        return jsonify({'step': chain[idx], 'idx': idx, 'finished': False})
    return jsonify({'finished': True, 'history': chain})

# 静态分析+路径合并
@app.route('/user/static')
def user_static():
    collab_data = {
        "task_name": "航班信息查询与预订综合任务",
        "task_desc": "多智能体分工协作，依次完成信息检索、身份校验、工具调用、结果汇总，SMT求解最优执行路径与工具组合",
        "agent_roles": """
智能体A（调度智能体）：任务分发、流程管控、全局约束校验
智能体B（工具调用智能体）：执行API调用、参数组装、结果返回
        """.strip(),
        "global_constraint": """
协作求解约束（SMT）：
1. 分工约束：AgentA负责调度，AgentB负责执行，职责不可越界
2. 时序约束：前序步骤完成后，方可执行下一环节
3. 安全约束：全程禁止敏感数据泄露、权限越界
4. 最优目标：选择耗时最短、合规性最高的工具组合与执行路径
        """.strip(),
        "solve_summary": """
协作执行结论：
1. 两智能体分工明确，时序流程满足所有SMT约束 → 全部 SAT
2. 工具组合经求解筛选，确定当前链路为全局最优方案
3. 全程无安全风险，任务完整执行完成
        """.strip()
    }
    return render_template('user/static.html', collab=collab_data)


# 多智能体协作分步接口：返回每一步协作内容、工具、SMT校验
@app.route('/user/static_step', methods=['POST'])
def user_static_step():
    idx = int(request.json.get('idx', 0))
    agent_type = request.json.get('agentType', 'ToolLLaMA')

    # 扩充后完整多智能体协作流程（10步）
    collab_steps = [
        # 步骤1：调度智能体A - 任务解析拆分
        {
            "agent": "智能体A(调度)",
            "role": "任务解析与分发",
            "tool": "TaskParser",
            "desc": "解析用户航班查询预订需求，拆解多级子任务，分配执行权限",
            "check": "流程合规，任务拆分完成",
            "input": {"user_query": "查询2025-06-01 北京出发航班并完成预订"},
            "output": {"task_list": ["航班检索", "身份校验", "风险检测", "订单提交"], "assign_to": "智能体B"},
            "sat": [
                {"rule": "R1: 调度智能体仅负责任务分发，不执行业务调用", "result": "SAT"},
                {"rule": "R2: 任务拆分完整，无环节缺失", "result": "SAT"}
            ]
        },
        # 步骤2：执行智能体B - 航班基础检索
        {
            "agent": "智能体B(执行)",
            "role": "公开数据检索",
            "tool": "FlightInformationRetrieval",
            "desc": "根据日期、目的地调用查询接口，拉取全部可用航班信息",
            "check": "参数合法，检索成功",
            "input": {"flight_date": "2025-06-01", "city": "北京"},
            "output": {"flight_list": ["CA1234", "MU5678"], "depart_time": ["08:00", "10:30"]},
            "sat": [
                {"rule": "R3: 公开航班数据查询，无权限越界风险", "result": "SAT"}
            ]
        },
        # 步骤3：调度智能体A - 检索结果初审
        {
            "agent": "智能体A(调度)",
            "role": "前置条件校验",
            "tool": "ResultChecker",
            "desc": "校验航班数据有效性，筛选有效航班，判定是否进入下一环节",
            "check": "数据合法，校验通过",
            "input": {"raw_flight_data": ["CA1234", "MU5678"]},
            "output": {"valid_flight": "CA1234", "next_step": "用户身份核验"},
            "sat": [
                {"rule": "R4: 前序任务合法，方可流转至下一流程", "result": "SAT"}
            ]
        },
        # 步骤4：执行智能体B - 身份信息校验
        {
            "agent": "智能体B(执行)",
            "role": "实名身份验证",
            "tool": "UserIDValidation",
            "desc": "调用身份核验工具，验证预订人实名信息合法性",
            "check": "身份有效，验证通过",
            "input": {"user_name": "张三", "id_card": "110101199001011234"},
            "output": {"valid": True},
            "sat": [
                {"rule": "R5: 敏感证件数据仅做校验，不对外明文返回", "result": "SAT"}
            ]
        },
        # 步骤5：执行智能体B - 手机号核验
        {
            "agent": "智能体B(执行)",
            "role": "联系方式核验",
            "tool": "UserPhonenumberValidation",
            "desc": "验证用户手机号有效性，发送核验验证码",
            "check": "手机号合法，验证码已下发",
            "input": {"phone_num": "138****8888"},
            "output": {"sms_status": "已发送", "verify_state": "待用户确认"},
            "sat": [
                {"rule": "R6: 手机号做脱敏处理，禁止全明文传输", "result": "SAT"}
            ]
        },
        # 步骤6：调度智能体A - 全流程风险检测
        {
            "agent": "智能体A(调度)",
            "role": "全局安全检测",
            "tool": "RiskDetector",
            "desc": "遍历当前全流程数据，检测数据泄露、非法调用、异常参数等风险",
            "check": "无安全风险",
            "input": {"full_process_log": "身份信息+航班数据+联系方式"},
            "output": {"risk_level": "安全", "allow_execute": True},
            "sat": [
                {"rule": "R7: 全流程无敏感数据泄露、无非法API调用", "result": "SAT"}
            ]
        },
        # 步骤7：调度智能体A - 最优工具路径求解
        {
            "agent": "智能体A(调度)",
            "role": "工具择优与路径规划",
            "tool": "PathOptimizer",
            "desc": "基于SMT约束比对多套工具方案，筛选耗时最短、合规性最高的最优组合",
            "check": "最优工具与执行路径已确定",
            "input": {"candidate_tools": ["BookCtripFlight", "BookTargetFlight"]},
            "output": {"optimal_tool": "BookTargetFlight", "plan": "优先使用轻量化预订工具"},
            "sat": [
                {"rule": "R8: 满足耗时、安全、合规多目标最优约束", "result": "SAT"}
            ]
        },
        # 步骤8：执行智能体B - 正式订单提交
        {
            "agent": "智能体B(执行)",
            "role": "核心业务执行",
            "tool": "BookTargetFlight",
            "desc": "使用求解得到的最优工具，提交航班预订订单",
            "check": "订单提交成功",
            "input": {"flight_no": "CA1234", "user": "张三"},
            "output": {"order_id": "TK20250601001", "order_status": "已下单"},
            "sat": [
                {"rule": "R9: 工具权限匹配，无越权调用行为", "result": "SAT"}
            ]
        },
        # 步骤9：调度智能体A - 订单结果复核
        {
            "agent": "智能体A(调度)",
            "role": "执行结果复核",
            "tool": "OrderReview",
            "desc": "复核订单状态、流程完整性，二次校验安全约束",
            "check": "订单状态正常，复核通过",
            "input": {"order_info": "TK20250601001"},
            "output": {"review_result": "正常", "final_confirm": True},
            "sat": [
                {"rule": "R10: 最终结果符合全部协作与安全约束", "result": "SAT"}
            ]
        },
        # 步骤10：调度智能体A - 任务汇总收尾
        {
            "agent": "智能体A(调度)",
            "role": "任务汇总与输出",
            "tool": "ResultSummary",
            "desc": "汇总全流程日志、执行结果、最优路径报告，输出最终答复",
            "check": "多智能体协作任务全部完成",
            "input": {"all_step_log": "全10步协作流程数据"},
            "output": {"final_reply": "航班CA1234预订成功，当前为全局最优执行方案"},
            "sat": [
                {"rule": "R11: 多智能体分工、时序、安全、最优目标全部满足", "result": "SAT"}
            ]
        }
    ]

    if idx < len(collab_steps):
        return jsonify({'step': collab_steps[idx], 'idx': idx, 'finished': False})
    else:
        return jsonify({'finished': True})

# 检测对比
@app.route('/user/compare')
def user_compare():
    # 读取动态检查结果
    file_path = 'chain_data/dynamic_check_results.json'
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8') as f:
            dynamic_results = json.load(f)
    else:
        dynamic_results = []
    return render_template('user/compare.html', data=compare_data, dynamic_results=dynamic_results)

# 历史调用记录
@app.route('/user/chain_step', methods=['POST'])
def user_chain_step():
    payload = request.json or {}
    idx = int(payload.get('idx', 0))
    agent_type = payload.get('agentType', 'ToolLLaMA')
    smt_guard_enabled = bool(payload.get('smtGuardEnabled'))
    deepseek_rules_enabled = bool(payload.get('deepseekRulesEnabled'))
    smt_method = normalize_smt_method(payload.get('smtMethod') or payload.get('smt_method'))

    # 根据智能体类型选择不同链条文件
    if agent_type == "OpenClaw":
        chain_path = 'chain_data/open_claw_chain.json'
    else:
        chain_path = 'chain_data/demo_chain.json'

    with open(chain_path, 'r', encoding='utf-8') as f:
        chain = json.load(f)
    chain = apply_smt_guard_to_steps(
        chain,
        defense_enabled=smt_guard_enabled,
        mode='demo_runtime',
        deepseek_enabled=deepseek_rules_enabled,
        smt_method=smt_method,
    )
    if idx < len(chain):
        step = chain[idx]
        # 记录历史
        history_chain.append(step)
        return jsonify({'step': step, 'idx': idx, 'finished': False})
    else:
        return jsonify({'finished': True, 'history': chain})

# ===================== 管理员侧 =====================
@app.route('/admin/dashboard')
def admin_dashboard():
    if 'user' not in session or session['user'] != 'admin':
        return redirect(url_for('login'))
    return render_template('admin/dashboard.html')

# 查看约束规则
@app.route('/admin/rules')
def admin_rules():
    # 先做管理员权限判断
    if 'user' not in session or session['user'] != 'admin':
        return redirect(url_for('login'))
    
    # 读取规则文件
    rules_path = 'chain_data/rules.json'
    if os.path.exists(rules_path):
        with open(rules_path, 'r', encoding='utf-8') as f:
            rules_data = json.load(f)
    else:
        rules_data = []
        
    return render_template('admin/rules.html', rules=rules_data)

# 查看检测历史
@app.route('/admin/history')
def admin_history():
    return render_template('admin/history.html', history=history)

# 管理员对比效果
@app.route('/admin/compare')
def admin_compare():
    return render_template('admin/compare.html', data=compare_data)

# 持续优化
@app.route('/admin/optimize')
def admin_optimize():
    return render_template('admin/optimize.html')

# 智能体中间表示
@app.route('/admin/ir')
def admin_ir():
    if 'user' not in session or session['user'] != 'admin':
        return redirect(url_for('login'))

    ir_root = 'chain_data/inner_representation'
    ir_list = []

    if os.path.exists(ir_root):
        # 遍历所有 智能体案例文件夹
        for dir_name in os.listdir(ir_root):
            dir_path = os.path.join(ir_root, dir_name)
            if os.path.isdir(dir_path):
                # 1. 左侧：未经过 SMT → graph_wo_check.md
                graph_wo_path = os.path.join(dir_path, 'graph_wo_check.md')
                mermaid_wo = ''
                if os.path.exists(graph_wo_path):
                    with open(graph_wo_path, 'r', encoding='utf-8') as f:
                        mermaid_wo = f.read()

                # 2. 右侧：经过 SMT → graph.md
                graph_path = os.path.join(dir_path, 'graph.md')
                mermaid_normal = ''
                if os.path.exists(graph_path):
                    with open(graph_path, 'r', encoding='utf-8') as f:
                        mermaid_normal = f.read()

                # 3. 读取同级的 agent_security.ir
                ir_file_path = os.path.join(dir_path, 'agent_security.ir')
                ir_code_content = ''
                if os.path.exists(ir_file_path):
                    with open(ir_file_path, 'r', encoding='utf-8') as f:
                        ir_code_content = f.read()

                # 传给前端：左右两张图
                ir_list.append({
                    'title': dir_name,
                    'mermaid_wo': mermaid_wo,    # 左
                    'mermaid': mermaid_normal,   # 右
                    'ir_code': ir_code_content
                })

    return render_template('admin/ir.html', ir_list=ir_list)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5003)