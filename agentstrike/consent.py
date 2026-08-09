"""
Authorization gate.

agentstrike attacks LLM agents. Attacking a system you do not own or have
written permission to test is illegal. This gate makes authorization an
explicit, deliberate act — there is no way to run a live campaign by accident.

Local demo targets (the bundled mock agent) are always allowed: nothing leaves
the machine and no third party is involved.
"""

from __future__ import annotations

import os
import sys

_ENV = "AGENTSTRIKE_AUTHORIZED"

BANNER = (
    "agentstrike is an authorized-only AI red-team tool.\n"
    "Only run it against agents you own or have explicit written permission\n"
    "to test. You are responsible for staying within that scope."
)


def is_authorized(
    flag: bool = False,
    *,
    target_is_local: bool = False,
    interactive: bool | None = None,
) -> bool:
    """Return True only if the operator authorized this run.

    Priority: local target → always ok; --authorized flag; env var; else an
    interactive y/N confirmation. Non-interactive without flag/env → denied.
    """
    if target_is_local:
        return True
    if flag or os.environ.get(_ENV) == "1":
        return True

    if interactive is None:
        interactive = sys.stdin.isatty() and sys.stdout.isatty()
    if not interactive:
        return False

    sys.stderr.write(BANNER + "\n")
    try:
        answer = input("Do you have authorization to test this target? [y/N] ")
    except (EOFError, KeyboardInterrupt):
        return False
    return answer.strip().lower() in {"y", "yes"}
