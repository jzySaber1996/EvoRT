# EvoRT

EvoRT 集成了 AgentSAT 智能体运行时安全原型，用于查看智能体执行链路并检查工具调用风险。AgentSAT 核心代码位于仓库根目录，沿用原有相对路径组织 Flask 应用、模板、静态资源和演示数据。

## 功能

- 展示智能体执行链路和运行时检查结果。
- 使用 Z3 对工具调用风险进行模板规则、Hoare 风格及 IR/Hoare 风格检查。
- 可选连接 ASB，执行动态攻击验证；也可连接 ToolBench 运行基准任务。
- 配置后可选用 DeepSeek 生成补充规则或运行时 IR。

## 目录结构

```text
EvoRT/
├── app.py                    # Flask 应用
├── start.sh                  # 启动脚本
├── smt_guard.py              # 运行时 SMT 防护
├── smt_rule_engine.py        # 风险事实、规则与 Z3 公式
├── asb_bridge.py             # 可选的 ASB 子进程桥接
├── toolbench_bridge.py       # 可选的 ToolBench 子进程桥接
├── templates/                # Flask 页面模板
├── static/                   # Web 静态资源
└── chain_data/               # 演示链路、IR 示例和运行结果
```

## 环境与启动

推荐使用 Python 3.10 或更新版本。创建虚拟环境并安装 Web 应用依赖：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

启动 Web 应用且不自动启动 Ollama：

```bash
START_OLLAMA=0 ./start.sh
```

默认端口为 `5001`，可通过 `PORT` 修改，例如 `PORT=5002 START_OLLAMA=0 ./start.sh`。启动脚本默认监听 `0.0.0.0`；仅在本机访问时可设置 `HOST=127.0.0.1`。

演示账号为 `user` / `user123` 和 `admin` / `admin123`。这些是原型系统的默认凭据，不应直接用于可被网络访问的部署。

## 可选后端

没有 ASB 或 ToolBench 时，Flask Web 应用仍可启动；对应页面和执行接口需要安装并配置各自的外部项目及运行环境。

默认从 `../ASB` 查找 ASB。可通过 `ASB_ROOT` 和 `ASB_PYTHON` 指定 ASB 路径及 Python 解释器。将 ASB 仓库放在默认的同级目录后，再在 ASB 环境中按需安装 `requirements-asb.txt`。

默认从 `../LLM_Tool_Learning` 查找 ToolBench。可通过 `TOOLBENCH_ROOT` 和 `TOOLBENCH_PYTHON` 指定其他代码路径和 Python 环境。

SMT 检查默认使用本地规则。需要启用 DeepSeek 规则生成时，在环境中配置 `DEEPSEEK_API_KEY`。不要将 API Key 或本地凭据提交到仓库。

## 许可证与来源

本仓库包含的 AgentSAT 文件遵循 Apache License 2.0，详见 [LICENSE](LICENSE)。

英文文档见 [README.md](README.md)。
