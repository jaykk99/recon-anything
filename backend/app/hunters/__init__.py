"""The hunter layer: 20 non-chat hunter agents for ReconAnything.

Jay's rule (2026-10-20): the agents do not chat, they hunt. There is
no assistant and no chat box. Each hunter is a specialist that works
the shared known set through the agent data service (app/agentdata):
it reads what every other hunter confirmed, expands it with its pivot
rules, hands candidates to the existing detection plugins for
verification, and writes confirmed assets and dead ends back.

"They can use known to find more" is the primary mechanism: every
asset type has explicit expansion rules (see EXPANSION in roles.py).
Confirmed candidates join the known set and expand again, bounded by
depth and task budgets. The known set persists across runs, so a
repeat scan starts from everything already known and only expands
the frontier.
"""
