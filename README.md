# agentstrike

**A red-team fuzzer for LLM agents.**

agentstrike evaluates whether an AI agent can be manipulated by prompt injection. It mutates attack techniques, sends them to an authorized target, detects successful canary execution and produces reproducible security reports.

![Python](https://img.shields.io/badge/Python-3.9%2B-5ac8fa?style=for-the-badge)
![CI](https://img.shields.io/badge/tests-16%20passing-3ddc97?style=for-the-badge)
![OWASP](https://img.shields.io/badge/OWASP-LLM%20Top%2010-8b5cf6?style=for-the-badge)

> **Authorized use only.** Run agentstrike only against systems you own or have explicit permission to test. Remote targets require an authorization gate; the bundled mock target works locally without network access.

## What it solves

Static prompt-injection test lists are easy to filter. agentstrike treats the problem as an iterative search:

```
techniques
    ↓
seed payloads
    ↓
mutation
    ↓
target agent
    ↓
canary oracle
    ↓
fitness score
    ↓
survivors → next generation
    ↓
report
```

A unique canary marker provides an objective signal instead of relying on subjective interpretation of a model response.

## Technique coverage

| Technique | OWASP mapping | Severity |
|---|---|---|
| direct override | LLM01 | high |
| system prompt leak | LLM07 | high |
| tool hijack | LLM06 | critical |
| data exfiltration | LLM02 | critical |
| indirect injection | LLM01 | critical |
| payload smuggling | LLM01 | high |
| refusal suppression | LLM01 | medium |
| role-play jailbreak | LLM01 | medium |

## Quick start

Run the local vulnerable target:

```bash
python -m agentstrike mock
```

Run the hardened target:

```bash
python -m agentstrike mock:hardened
```

List techniques:

```bash
python -m agentstrike --list-techniques
```

## Test an authorized agent

HTTP:

```bash
agentstrike https://my-agent.example/chat --authorized \
  --http-field message \
  --http-response-path choices.0.text \
  --http-header "Authorization: Bearer $TOKEN" \
  -f html -o report.html
```

Local command:

```bash
agentstrike --target-cmd "python my_agent.py" --authorized
```

## CI integration

Generate SARIF and fail a pipeline on a breach:

```bash
agentstrike https://staging-agent.internal/chat --authorized \
  --fail-on-breach -f sarif -o agentstrike.sarif
```

## Engineering highlights

- genetic mutation loop rather than a static payload list
- canary-based breach oracle
- local, HTTP and command targets
- explicit authorization gate
- HTML, JSON and SARIF reports
- extensible technique and mutation libraries
- deterministic tests for mutation invariants and consent controls

## Ecosystem

agentstrike is one component of a broader AI-security toolkit:

- [mcpscan](https://github.com/nadirzhon/mcpscan) — MCP server security
- [APEX](https://github.com/nadirzhon/apex) — authorized security orchestration
- [offsec-mcp](https://github.com/nadirzhon/offsec-mcp) — security tooling for AI agents

## License

MIT © nadirzhon — for authorized security testing only.
