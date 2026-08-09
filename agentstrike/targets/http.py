"""
HTTP target adapter.

Point agentstrike at a real agent's HTTP endpoint. The request/response shape
varies per app, so the prompt field and the JSON path to the reply are
configurable. Pure stdlib (urllib) — zero dependencies.

Example:
    agentstrike run https://my-agent.example/chat --authorized \\
        --http-field message --http-response-path choices.0.text \\
        --http-header "Authorization: Bearer $TOKEN"
"""

from __future__ import annotations

import json
import urllib.request
import urllib.error


class HTTPTarget:
    is_local = False

    def __init__(
        self,
        url: str,
        *,
        field: str = "message",
        response_path: str = "response",
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
        method: str = "POST",
    ) -> None:
        self.url = url
        self.name = url
        self.field = field
        self.response_path = response_path
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self.timeout = timeout
        self.method = method

    def send(self, prompt: str) -> str:
        body = json.dumps({self.field: prompt}).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, headers=self.headers, method=self.method)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                raw = resp.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            raw = e.read().decode("utf-8", "replace")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            return f"[transport-error: {e}]"
        return self._extract(raw)

    def _extract(self, raw: str) -> str:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            return raw  # plain-text endpoint
        cur = data
        for part in self.response_path.split("."):
            if isinstance(cur, list):
                try:
                    cur = cur[int(part)]
                    continue
                except (ValueError, IndexError):
                    return raw
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return raw
        return cur if isinstance(cur, str) else json.dumps(cur)
