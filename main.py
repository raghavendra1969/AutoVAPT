#!/usr/bin/env python3
"""
AutoVAPT - Web & API Security Assessment Framework
====================================================
Single entry point that dispatches to each module's CLI.

Usage:
    python main.py jwt <token>
    python main.py jwt --file token.txt
    python main.py enum --config findings/auth_checker_config.sample.json --yes
    python main.py map --list
    python main.py map --report reports/api_inventory_report.md
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "modules"))

import jwt_analyzer   # noqa: E402
import auth_checker   # noqa: E402
import api_mapper      # noqa: E402

USAGE = """\
AutoVAPT - Web & API Security Assessment Framework

Usage:
  python main.py jwt   [token] [--file FILE] [--json]
  python main.py enum  --config CONFIG [--yes] [--save PATH]
  python main.py map   [--list] [--add PATH ...] [--report PATH]

Modules can also be run directly, e.g.:
  python modules/jwt_analyzer.py <token>
  python modules/auth_checker.py --config findings/auth_checker_config.sample.json --yes
  python modules/api_mapper.py --report reports/api_inventory_report.md
"""


def main():
    if len(sys.argv) < 2:
        print(USAGE)
        sys.exit(1)

    command, rest = sys.argv[1], sys.argv[2:]

    if command == "jwt":
        jwt_analyzer.main(rest)
    elif command == "enum":
        auth_checker.main(rest)
    elif command == "map":
        api_mapper.main(rest)
    elif command in ("-h", "--help"):
        print(USAGE)
    else:
        print(f"Unknown command: {command}\n")
        print(USAGE)
        sys.exit(1)


if __name__ == "__main__":
    main()
