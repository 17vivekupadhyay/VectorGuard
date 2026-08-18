"""
VectorGuard Black-Box Agent CLI — point-and-shoot chatbot pentesting.

    python -m vectorguard.blackbox.cli pentest \
        --url http://localhost:8000/chat --scope localhost

Given just a URL (and a required scope), it auto-detects the API shape and runs
the autonomous LLM-security battery. Defensive and authorization-first: the
target host must match --scope; it is talk-only.
"""

from __future__ import annotations

import argparse

from .adapter import AdapterError
from .campaign import ScopeError, run_blackbox
from .llm import LLMClient
from .operator import build_operator
from .report import save_report

GREEN, RED, YELLOW, DIM, BOLD, RESET = (
    "\033[92m", "\033[91m", "\033[93m", "\033[90m", "\033[1m", "\033[0m"
)

_CONF_COLOR = {"deterministic": RED, "high": RED, "medium": YELLOW, "low": DIM, "none": GREEN}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m vectorguard.blackbox.cli",
        description="VectorGuard black-box agent — point-and-shoot chatbot pentesting.",
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    p = sub.add_parser("pentest", help="Auto-detect a chatbot URL and run the battery.")
    p.add_argument("--url", help="Chatbot endpoint URL, e.g. http://localhost:8000/chat")
    p.add_argument("--scope", action="append", default=[],
                   help="Allowed host (repeatable). Required; target host must match.")
    p.add_argument("--objectives", default="all",
                   help="Comma-separated: injection,consumption,disclosure,system_prompt (or all).")
    p.add_argument("--canary", default=None, help="Injection canary token (default: random).")
    p.add_argument("--operator", choices=["battery", "llm"], default="battery",
                   help="Attacker brain. 'llm' generates & adapts payloads (set LLM_BASE_URL / "
                        "LLM_MODEL / LLM_API_KEY); falls back to battery if unavailable.")
    p.add_argument("--max-steps", type=int, default=5,
                   help="Max independent probes per objective (single-shot mode).")
    p.add_argument("--max-turns", type=int, default=1,
                   help="Turns per objective. >1 enables MULTI-TURN mode: one evolving "
                        "conversation (prime a premise, then strike).")
    p.add_argument("--max-chars", type=int, default=6000, help="Response-size budget.")
    p.add_argument("--max-latency-ms", type=float, default=25000.0, help="Latency budget (ms).")
    p.add_argument("--out", default=None, help="If set, write JSON + Markdown reports here.")
    p.add_argument("--fail-on-capture", action="store_true", help="Exit 1 if any finding fires.")
    p.set_defaults(func=cmd_pentest)
    return parser


def cmd_pentest(args: argparse.Namespace) -> int:
    if not args.url:
        print(f"{RED}--url is required.{RESET}")
        return 2
    if not args.scope:
        print(f"{RED}--scope is required{RESET} (authorization gate; e.g. --scope localhost).")
        return 2

    objectives = None if args.objectives == "all" else args.objectives.split(",")

    print(f"{BOLD}VectorGuard :: black-box agent{RESET}")
    print(f"{DIM}point-and-shoot · talk-only · scope={args.scope}{RESET}")

    operator = None
    if args.operator == "llm":
        client = LLMClient.from_env()
        if client is None:
            print(f"{YELLOW}[operator] LLM not configured (set LLM_BASE_URL + LLM_MODEL); "
                  f"using deterministic battery.{RESET}")
        else:
            print(f"{DIM}[operator] LLM: {client.describe()} (battery fallback armed){RESET}")
            operator = build_operator("llm", client)

    try:
        run = run_blackbox(
            url=args.url, scope=args.scope, objectives=objectives, canary=args.canary,
            operator=operator, max_steps=args.max_steps, max_turns=args.max_turns,
            max_chars=args.max_chars, max_latency_ms=args.max_latency_ms, verbose=True,
        )
    except ScopeError as error:
        print(f"{RED}Refusing to run:{RESET} {error}")
        return 2
    except AdapterError as error:
        print(f"{RED}Auto-adapt failed:{RESET} {error}")
        return 3

    print(f"\n{BOLD}── findings ──{RESET}")
    for f in run.findings:
        color = _CONF_COLOR.get(f.confidence, DIM)
        if f.captured:
            print(f"  {color}{f.confidence.upper():<13}{RESET} {f.objective:<18} "
                  f"{f.owasp}  ({f.method}) — {f.evidence}")
        else:
            print(f"  {GREEN}none         {RESET} {f.objective:<18} {f.owasp}")

    if args.out:
        jp, mp = save_report(run, args.out)
        print(f"{DIM}reports: {jp} · {mp}{RESET}")

    n = len(run.captured)
    print(f"\n{BOLD}{n}/{len(run.findings)} objectives produced a signal.{RESET}")
    if args.fail_on_capture and n:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return 1
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
