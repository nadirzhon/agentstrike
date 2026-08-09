"""Command-line interface for agentstrike."""

from __future__ import annotations

import argparse
import sys

from . import report
from .consent import BANNER, is_authorized
from .engine import run_campaign
from .techniques.library import TECHNIQUES


def _build_target(args):
    if args.target_cmd:
        from .targets.command import CommandTarget
        return CommandTarget(args.target_cmd, timeout=args.timeout)
    tgt = args.target
    if tgt is None or tgt.startswith("mock"):
        from .targets.mock import get
        return get(tgt or "mock")
    if tgt.startswith("http://") or tgt.startswith("https://"):
        from .targets.http import HTTPTarget
        headers = {}
        for h in args.http_header or []:
            if ":" in h:
                k, v = h.split(":", 1)
                headers[k.strip()] = v.strip()
        return HTTPTarget(
            tgt, field=args.http_field, response_path=args.http_response_path,
            headers=headers, timeout=args.timeout,
        )
    # Anything else: treat as a local command string.
    from .targets.command import CommandTarget
    return CommandTarget(tgt, timeout=args.timeout)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agentstrike",
        description="Authorized red-team fuzzer for LLM agents (prompt injection).",
        epilog=BANNER,
    )
    p.add_argument("target", nargs="?", default="mock",
                   help="HTTP URL, 'mock' / 'mock:hardened', or a local command string")
    p.add_argument("--target-cmd", help="explicit local command target (stdin→stdout)")
    p.add_argument("--authorized", action="store_true",
                   help="confirm you are authorized to test this target")
    p.add_argument("-t", "--technique", action="append", dest="techniques",
                   help="restrict to a technique key (repeatable); default: all")
    p.add_argument("-g", "--generations", type=int, default=3)
    p.add_argument("-p", "--population", type=int, default=6)
    p.add_argument("--seed", type=int, default=1337, help="RNG seed (reproducible runs)")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--http-field", default="message")
    p.add_argument("--http-response-path", default="response")
    p.add_argument("--http-header", action="append", help='e.g. "Authorization: Bearer TOKEN"')
    p.add_argument("-f", "--format", choices=["terminal", "json", "html", "sarif"], default="terminal")
    p.add_argument("-o", "--output", help="write report to a file instead of stdout")
    p.add_argument("--fail-on-breach", action="store_true",
                   help="exit non-zero if any breach is found (for CI)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--list-techniques", action="store_true")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    if args.list_techniques:
        for t in TECHNIQUES:
            print(f"{t.key:22} [{t.severity.label:8}] {t.title}")
        return 0

    target = _build_target(args)
    local = getattr(target, "is_local", False)
    if not is_authorized(args.authorized, target_is_local=local):
        sys.stderr.write(
            "\nRefusing to run: no authorization for a non-local target.\n"
            "Re-run with --authorized (or set AGENTSTRIKE_AUTHORIZED=1) only if\n"
            "you own or have written permission to test it.\n"
        )
        return 2

    result = run_campaign(
        target,
        technique_keys=args.techniques,
        generations=args.generations,
        population=args.population,
        seed=args.seed,
    )

    out = report.render(result, args.format, color=not args.no_color and not args.output)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out)
        sys.stderr.write(f"agentstrike: report written to {args.output}\n")
    else:
        print(out)

    if args.fail_on_breach and result.breaches:
        return 1
    return 0
