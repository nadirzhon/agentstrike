"""
agentstrike — an authorized red-team fuzzer for LLM agents.

Sends a mutatable battery of prompt-injection techniques at an agent and proves
breaches with canary tokens. For testing systems you own or are authorized to
test. Pure standard library, zero dependencies.
"""

from .engine import run_campaign
from .models import Breach, CampaignResult, Severity

__version__ = "1.0.0"
__all__ = ["run_campaign", "Breach", "CampaignResult", "Severity", "__version__"]
