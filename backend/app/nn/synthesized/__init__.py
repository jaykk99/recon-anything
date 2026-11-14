"""Staging area for synthesized tools. NOT a plugin package.

Files here are produced by the Sandboxed Synthesizer and await HUMAN
review. The plugin registry only scans app/plugins/, so nothing in this
directory ever runs in the live scanner. A staged file refuses to run
(HUMAN_REVIEWED = False) until a human moves it into app/plugins/ and
flips the flag. Never import from here in production code.
"""
