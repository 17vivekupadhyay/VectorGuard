"""VectorGuard Web Agent Commands.

Each command is a separate module for clarity and maintainability.
"""

from .agent import cmd_agent
from .check import cmd_check
from .generate import cmd_generate_tests
from .plan import cmd_plan
from .report import cmd_report
from .scan import cmd_scan
from .validate import cmd_validate

__all__ = [
    "cmd_plan",
    "cmd_generate_tests",
    "cmd_agent",
    "cmd_validate",
    "cmd_scan",
    "cmd_check",
    "cmd_report",
]
