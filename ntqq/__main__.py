"""允许通过 ``python -m ntqq`` 运行命令行界面。"""

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
