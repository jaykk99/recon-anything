"""Depth config gate: the site crawlers must honor the RECON_CRAWL_* /
RECON_JS_* knobs, not re-hardcode shallow caps.

These were module constants (80 pages / depth 6 / 8 JS bundles). Making
them configurable is what lets the tool "go deeper into websites"; this
test keeps them wired to app/config so a refactor can't quietly revert.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import config  # noqa: E402


def test_crawlers_read_depth_from_config():
    import app.plugins.deepcrawl as deepcrawl
    import app.plugins.crawler as crawler

    assert deepcrawl.MAX_PAGES == config.CRAWL_MAX_PAGES
    assert deepcrawl.MAX_DEPTH == config.CRAWL_MAX_DEPTH
    assert deepcrawl.CONCURRENCY == config.CRAWL_CONCURRENCY
    assert crawler.MAX_PAGES == config.CRAWL_MAX_PAGES
    assert crawler.MAX_DEPTH == config.CRAWL_MAX_DEPTH


def test_js_miner_reads_depth_from_config():
    import app.plugins.js_linkfinder as jl

    assert jl.MAX_BUNDLES == config.JS_MAX_BUNDLES
    assert jl.MAX_ENDPOINT_FINDINGS == config.JS_MAX_ENDPOINT_FINDINGS


def test_depth_defaults_are_deeper_than_legacy():
    # Guard against a regression back to the old shallow caps.
    assert config.CRAWL_MAX_PAGES >= 200
    assert config.CRAWL_MAX_DEPTH >= 8
    assert config.JS_MAX_BUNDLES >= 24
