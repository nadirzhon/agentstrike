"""Target abstraction: anything agentstrike can send a prompt to."""

from __future__ import annotations

from typing import Protocol


class Target(Protocol):
    """A thing under test. `send` delivers one user turn, returns the reply."""

    name: str
    is_local: bool

    def send(self, prompt: str) -> str: ...
