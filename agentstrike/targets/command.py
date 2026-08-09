"""
Command target adapter.

Wrap a local CLI agent: agentstrike writes the prompt to stdin and reads the
reply from stdout. Useful for testing a chatbot binary or a script before it
ever ships behind an HTTP layer.

Example:
    agentstrike run --target-cmd "python my_agent.py" --authorized
"""

from __future__ import annotations

import shlex
import subprocess


class CommandTarget:
    is_local = True  # runs on this machine; still your own code

    def __init__(self, command: str, *, timeout: float = 30.0) -> None:
        self.command = command
        self.name = f"cmd:{command}"
        self.argv = shlex.split(command)
        self.timeout = timeout

    def send(self, prompt: str) -> str:
        try:
            proc = subprocess.run(
                self.argv,
                input=prompt,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return "[timeout]"
        except (OSError, ValueError) as e:
            return f"[spawn-error: {e}]"
        return (proc.stdout or proc.stderr or "").strip()
