"""Reporters: terminal, JSON, SARIF and a self-contained dark HTML dashboard."""

from __future__ import annotations

import html
import json

from .models import CampaignResult, Severity

_COLOR = {
    "CRITICAL": "\033[38;5;203m", "HIGH": "\033[38;5;215m",
    "MEDIUM": "\033[38;5;221m", "LOW": "\033[38;5;151m", "INFO": "\033[38;5;245m",
}
_RESET = "\033[0m"
_DIM = "\033[2m"


def render_terminal(r: CampaignResult, *, color: bool = True) -> str:
    def c(txt, sev):
        return f"{_COLOR.get(sev,'')}{txt}{_RESET}" if color else txt

    lines = [
        "",
        f"  agentstrike — {r.target}",
        f"  {r.probes_sent} probes · {len(r.techniques_run)} techniques · "
        f"{r.generations} generations · {r.duration_sec}s",
        "",
    ]
    breaches = r.sorted_breaches()
    if not breaches:
        lines.append("  ✓ No breaches — the agent held against every technique.")
    else:
        for b in breaches:
            sev = b.severity.label
            lines.append(f"  {c('██', sev)} {c(sev, sev)}  {b.title}")
            lines.append(f"     {_DIM if color else ''}{b.technique} · {b.owasp} · gen {b.generation}{_RESET if color else ''}")
            lines.append(f"     ↳ payload: {b.payload[:88].replace(chr(10),' ')}")
            lines.append(f"     ↳ reply:   {b.response_excerpt[:88]}")
            lines.append(f"     ✎ {b.remediation}")
            lines.append("")
    lines.append("  ── Summary ─────────────────────────────")
    counts = _counts(r)
    lines.append("  " + "   ".join(f"{k}: {v}" for k, v in counts.items() if v))
    lines.append(f"  risk score: {r.risk_score}/100")
    lines.append("")
    return "\n".join(lines)


def _counts(r: CampaignResult) -> dict[str, int]:
    out = {s.label: 0 for s in reversed(Severity)}
    for b in r.breaches:
        out[b.severity.label] += 1
    return out


def render_json(r: CampaignResult) -> str:
    return json.dumps({"tool": "agentstrike", **r.to_dict()}, indent=2, ensure_ascii=False)


def render_sarif(r: CampaignResult) -> str:
    rules, results = {}, []
    for b in r.sorted_breaches():
        rules.setdefault(b.technique, {
            "id": b.technique,
            "name": b.title,
            "shortDescription": {"text": b.title},
            "helpUri": "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
            "properties": {"owasp": b.owasp},
        })
        results.append({
            "ruleId": b.technique,
            "level": b.severity.sarif_level,
            "message": {"text": f"{b.title}: {b.signal}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": r.target},
                }
            }],
            "properties": {"payload": b.payload, "generation": b.generation},
        })
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": "agentstrike",
                "informationUri": "https://github.com/nadirzhon/agentstrike",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(sarif, indent=2, ensure_ascii=False)


def render_html(r: CampaignResult) -> str:
    e = html.escape
    counts = _counts(r)
    chips = "".join(
        f'<span class="chip {k.lower()}">{v} {k}</span>'
        for k, v in counts.items() if v
    ) or '<span class="chip none">0 breaches</span>'
    rows = []
    for b in r.sorted_breaches():
        rows.append(f"""
        <article class="breach {b.severity.label.lower()}">
          <header>
            <span class="sev">{b.severity.label}</span>
            <h3>{e(b.title)}</h3>
            <span class="tech">{e(b.technique)} · gen {b.generation}</span>
          </header>
          <p class="owasp">{e(b.owasp)}</p>
          <p class="signal">✓ {e(b.signal)}</p>
          <pre class="payload">{e(b.payload)}</pre>
          <pre class="reply">{e(b.response_excerpt)}</pre>
          <p class="fix">✎ {e(b.remediation)}</p>
        </article>""")
    body = "\n".join(rows) or '<p class="clean">No breaches — the agent resisted every technique.</p>'
    return f"""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>agentstrike — {e(r.target)}</title>
<style>
 :root{{--bg:#080b12;--panel:#0f141d;--line:#1e2734;--txt:#e6edf3;--dim:#8b98a9;--cyan:#3ddc97}}
 *{{box-sizing:border-box}} body{{margin:0;background:var(--bg);color:var(--txt);
  font:15px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace;padding:2.2rem}}
 h1{{font-size:1.5rem;margin:0}} .sub{{color:var(--dim);margin:.3rem 0 1.4rem}}
 .score{{float:right;font-size:2.6rem;font-weight:800;color:var(--cyan)}}
 .chips{{margin:0 0 1.6rem}} .chip{{display:inline-block;padding:.25rem .7rem;border-radius:999px;
  margin:.2rem .3rem .2rem 0;font-size:.8rem;border:1px solid var(--line)}}
 .critical{{color:#ff6b6b}} .high{{color:#ffa94d}} .medium{{color:#ffd43b}}
 .low{{color:#8ce99a}} .none,.clean{{color:var(--dim)}}
 .breach{{background:var(--panel);border:1px solid var(--line);border-left:3px solid var(--dim);
  border-radius:12px;padding:1.1rem 1.3rem;margin:.7rem 0}}
 .breach.critical{{border-left-color:#ff6b6b}} .breach.high{{border-left-color:#ffa94d}}
 .breach.medium{{border-left-color:#ffd43b}} .breach.low{{border-left-color:#8ce99a}}
 header{{display:flex;align-items:center;gap:.7rem;flex-wrap:wrap}}
 header h3{{margin:0;font-size:1.05rem}} .sev{{font-size:.7rem;font-weight:700;letter-spacing:.08em;
  padding:.15rem .5rem;border:1px solid currentColor;border-radius:6px}}
 .tech{{color:var(--dim);font-size:.8rem;margin-left:auto}}
 .owasp{{color:var(--dim);font-size:.82rem;margin:.5rem 0 .3rem}}
 .signal{{color:var(--cyan);font-size:.85rem;margin:.2rem 0}}
 pre{{background:#0a0e15;border:1px solid var(--line);border-radius:8px;padding:.6rem .8rem;
  overflow-x:auto;white-space:pre-wrap;word-break:break-word;font-size:.82rem;margin:.4rem 0}}
 .reply{{color:var(--dim)}} .fix{{color:#8ce99a;font-size:.85rem;margin:.6rem 0 0}}
</style>
<h1>agentstrike <span class="score" title="risk score">{r.risk_score}</span></h1>
<p class="sub">{e(r.target)} · risk score {r.risk_score}/100 · {r.probes_sent} probes · {len(r.techniques_run)} techniques · {r.generations} generations · {r.duration_sec}s</p>
<div class="chips">{chips}</div>
{body}
</html>"""


def render(r: CampaignResult, fmt: str, *, color: bool = True) -> str:
    return {
        "terminal": lambda: render_terminal(r, color=color),
        "json": lambda: render_json(r),
        "sarif": lambda: render_sarif(r),
        "html": lambda: render_html(r),
    }[fmt]()
