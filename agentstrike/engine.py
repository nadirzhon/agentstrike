"""
Campaign engine.

Runs each technique against the target as a small genetic search: generation 0
is the seed payloads; every payload is scored by the oracle; if none breach,
the fittest survivors are mutated into the next generation. A technique stops as
soon as it lands one breach (that's enough to prove the class is exploitable).

The fitness gradient is what makes mutation productive: an outright refusal
scores low, a normal answer scores mid, an echoed canary is a win.
"""

from __future__ import annotations

import time
from random import Random

from . import oracle
from .models import Breach, CampaignResult
from .techniques.library import Technique, by_key, special_seeds


def _fitness(response: str, canary: str, *, expects_refusal: bool) -> float:
    success, _ = oracle.judge(response, canary, expects_refusal=expects_refusal)
    if success:
        return 1.0
    if oracle.refused(response):
        return 0.1
    return 0.4


def _excerpt(text: str, n: int = 240) -> str:
    text = " ".join((text or "").split())
    return text[:n] + ("…" if len(text) > n else "")


def run_campaign(
    target,
    *,
    technique_keys: list[str] | None = None,
    generations: int = 3,
    population: int = 6,
    seed: int = 1337,
    on_event=None,
) -> CampaignResult:
    """Execute a full red-team campaign and return the result."""
    from .mutator import mutate

    rng = Random(seed)
    start = time.perf_counter()
    techniques: list[Technique] = by_key(technique_keys)
    result = CampaignResult(
        target=getattr(target, "name", "target"),
        generations=generations,
        techniques_run=[t.key for t in techniques],
    )

    for tech in techniques:
        canary = oracle.new_canary()
        seeds = special_seeds(tech, canary) or tech.seeds(canary)
        pop = list(seeds)[:population]
        breached = False

        for gen in range(generations):
            scored: list[tuple[float, str, str]] = []  # (fitness, payload, response)
            for payload in pop:
                response = target.send(payload)
                result.probes_sent += 1
                if on_event:
                    on_event(tech.key, gen, payload, response)
                fit = _fitness(response, canary, expects_refusal=tech.expects_refusal)
                scored.append((fit, payload, response))

                if fit >= 1.0:
                    _, signal = oracle.judge(response, canary, expects_refusal=tech.expects_refusal)
                    result.breaches.append(Breach(
                        technique=tech.key,
                        title=tech.title,
                        severity=tech.severity,
                        owasp=tech.owasp,
                        payload=payload,
                        response_excerpt=_excerpt(response),
                        signal=signal,
                        generation=gen,
                        remediation=tech.remediation,
                    ))
                    breached = True
                    break
            if breached:
                break

            # Breed: keep the fittest, mutate them up to population size.
            scored.sort(key=lambda s: s[0], reverse=True)
            parents = [p for _, p, _ in scored[: max(2, population // 2)]]
            pop = list(parents)
            while len(pop) < population and parents:
                base = rng.choice(parents)
                pop.append(mutate(base, canary, rng, n=rng.randint(1, 2)))

    result.duration_sec = round(time.perf_counter() - start, 3)
    return result
