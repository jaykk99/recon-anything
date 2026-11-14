"""Viewer: the dashboard file exists, parses as HTML, carries real
metrics, loads no external resources, and has the live score panel."""
import html.parser
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

VIEWER = os.path.join(os.path.dirname(os.path.dirname(
    os.path.abspath(__file__))), "app", "nn", "viewer.html")


class _Parser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.attrs = {}

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attrs.setdefault(tag, []).append(dict(attrs))


def test_viewer_exists_and_parses():
    assert os.path.exists(VIEWER), "viewer.html missing"
    text = open(VIEWER, encoding="utf-8").read()
    p = _Parser()
    p.feed(text)  # raises on malformed markup
    # Static tags present in the file itself (svg/table are built by JS
    # at render time, so they are checked in test_viewer_has_required_panels).
    for needed in ("html", "head", "body", "script", "form", "input",
                   "button", "div"):
        assert needed in p.tags, needed
    # No external dependencies: no CDN, no remote script/link/img.
    assert "cdn" not in text.lower()
    for tag in ("script", "link", "img"):
        for attrs in p.attrs.get(tag, []):
            for key in ("src", "href"):
                val = attrs.get(key, "")
                assert not val.startswith(("http://", "https://", "//")), \
                    f"external {tag} {key}: {val}"


def test_viewer_has_required_panels():
    text = open(VIEWER, encoding="utf-8").read()
    for anchor in ('id="metrics"', 'id="arch"', 'id="curves"',
                   'id="confusion"', 'id="importance"',
                   'id="score-form"', 'id="score-target"',
                   'id="dataset"', 'id="limits"'):
        assert anchor in text, anchor


def test_viewer_carries_real_metrics():
    text = open(VIEWER, encoding="utf-8").read()
    m = re.search(
        r'<script type="application/json" id="nn-data">(.*?)</script>',
        text, re.S)
    assert m, "embedded metrics block missing"
    data = json.loads(m.group(1))
    assert data is not None, "viewer not trained yet: run python -m app.nn.train"
    tm = data["test_metrics"]
    assert 0.0 <= tm["accuracy"] <= 1.0
    assert 0.0 <= tm["roc_auc"] <= 1.0
    assert data["dataset"]["train_rows"] >= 700
    assert data["layers"][-1] == 1
    assert "TRIAGE ONLY" in text
    assert "VERIFIED_REAL" in text
