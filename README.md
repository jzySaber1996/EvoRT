# EvoRT

EvoRT includes the AgentSAT runtime security prototype for inspecting agent execution paths and checking tool-call risk conditions. The AgentSAT implementation is integrated at the repository root so its Flask app, templates, static files, and sample data work with their existing relative paths.

## Features

- Visualize example agent execution chains and runtime-check results.
- Evaluate tool-call risks with Z3 using template, Hoare-style, and IR/Hoare-style checks.
- Optionally connect to ASB for dynamic attack validation and ToolBench for benchmark runs.
- Optionally use DeepSeek to generate additional rules or runtime IR when configured.

## Repository Layout

```text
EvoRT/
├── app.py                    # Flask application
├── start.sh                  # Application startup script
├── smt_guard.py              # Runtime SMT guard
├── smt_rule_engine.py        # Risk facts, rules, and Z3 formulas
├── asb_bridge.py             # Optional ASB subprocess integration
├── toolbench_bridge.py       # Optional ToolBench subprocess integration
├── templates/                # Flask HTML templates
├── static/                   # Web assets
└── chain_data/               # Demo chains, IR examples, and runtime results
```

## Requirements and Setup

Python 3.10 or newer is recommended. Create an environment and install the Web application dependencies:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Start the Web application without starting Ollama:

```bash
START_OLLAMA=0 ./start.sh
```

The default port is `5001`; override it with `PORT`, for example `PORT=5002 START_OLLAMA=0 ./start.sh`. The startup script binds to `0.0.0.0` by default. For local-only access, set `HOST=127.0.0.1`.

Demo credentials are `user` / `user123` and `admin` / `admin123`. These are prototype credentials and should not be used for a network-accessible deployment.

## Optional Backends

The Flask application can start without ASB or ToolBench, but their pages and execution endpoints need the corresponding external projects and environments.

ASB is expected at `../ASB` by default. Set `ASB_ROOT` and `ASB_PYTHON` to override its path and Python executable. Install `requirements-asb.txt` only in the ASB environment after placing the ASB repository at the expected sibling path.

ToolBench is expected at `../LLM_Tool_Learning` by default. Configure `TOOLBENCH_ROOT` and `TOOLBENCH_PYTHON` to use a different checkout or environment.

SMT checks use the local rules by default. To enable optional DeepSeek rule generation, provide `DEEPSEEK_API_KEY` in the environment. Do not commit API keys or local credential files.

## License and Attribution

The AgentSAT files included in this repository retain their Apache License 2.0 terms; see [LICENSE](LICENSE).

See [README_cn.md](README_cn.md) for the Chinese documentation.
