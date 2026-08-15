"""``vulnforge serve``：启动 FastAPI 控制面。"""

from __future__ import annotations


def cmd_serve(args) -> int:
    """加载配置并启动 uvicorn；缺依赖时给出安装提示。"""
    from vulnforge.config import load_config

    cfg = load_config(getattr(args, "config", None))
    api_cfg = cfg.get("api", {}) if isinstance(cfg, dict) else {}
    host = args.host or api_cfg.get("host", "127.0.0.1")
    port = args.port or api_cfg.get("port", 8000)

    try:
        import uvicorn  # noqa: F401
    except ImportError:
        print('未安装 uvicorn。请执行: pip install -e ".[full]"')
        return 1

    from vulnforge.api import create_app

    app = create_app(cfg)
    print(f"vulnforge 控制面启动于 http://{host}:{port}")
    uvicorn.run(app, host=host, port=port)
    return 0
