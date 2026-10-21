"""Agent data service: the learning and data layer FOR the agents.

Hunters (and later other agent systems: Error Inbox swarm, bro-agent)
go through this package for everything they know:

- knowledge packs (bundled lists/patterns the hunters consult)
- the resource library (curated public recon/red-team references,
  fetched and cached with attribution)
- the known set (confirmed assets per target, namespaced by system)
- hunt memory (per-target summaries, dead ends, recent finds)

No hunter reads files or keeps private state directly: reads and
writes land here so every agent shares what every other agent found.
"""
