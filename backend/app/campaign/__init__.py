"""Autonomous campaign engine: ARTEX-shaped, detection-only.

A campaign takes an objective in plain language, plans intents over a
dual graph, executes them with capped read-only workers, writes the
results back, and replans until the goal is proven, a human approval is
outstanding, or the budget runs out.

    from app.campaign import Scope, run_campaign, render

    scope = Scope(roots=("example.com",), allow_active=True,
                  allow_exploit_confirm=False, max_requests=40)
    result = run_campaign("find exposed secrets and access paths", scope,
                          seeds=["https://example.com"])
    print(render(result))

The engine never exploits a target: every action is a GET/HEAD or a
read-only query, impact enumeration needs an explicit approval, and the
report labels each finding with the exact request that decided it.
"""
from .engine import preview, resume_campaign, run_campaign
from .graph import Graph
from .models import Attempt, Budget, Intent
from .planner import goal_proven, goals_for, next_intents
from .report import render
from .scope import Scope
from .store import CampaignStore

__all__ = [
    "Attempt", "Budget", "CampaignStore", "Graph", "Intent", "Scope",
    "goal_proven", "goals_for", "next_intents", "preview", "render",
    "resume_campaign", "run_campaign",
]
