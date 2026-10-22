"""Username-exposure deepening tests (plugin usernames).

On-target only: usernames baked into the site's own JS, and the site's
public WordPress author accounts (with default-account flagging).
Pure parsers get positive + empty cases; the plugin gets a full
fixture run for the positive detections.
"""
import asyncio

from app.plugins.usernames import parse_wp_users, usernames_in_js


def test_usernames_in_js_positive_and_empty():
    js = ('const cfg = {"username": "deploy-bot", '
          '"login": "svc-reports", "env": "prod"};')
    assert usernames_in_js(js) == ["deploy-bot", "svc-reports"]
    assert usernames_in_js("const x = 1; fetch('/api');") == []
    # config placeholders / type words are not handles
    assert usernames_in_js('{"username": "string"}') == []


def test_parse_wp_users_positive_and_empty():
    body = ('[{"id": 1, "slug": "fixture-admin", "name": "Fixture Admin"},'
            ' {"id": 2, "slug": "admin", "name": "Site Admin"}]')
    users = parse_wp_users(body)
    assert [u["slug"] for u in users] == ["fixture-admin", "admin"]
    assert parse_wp_users("<html>not json</html>") == []
    assert parse_wp_users('{"name": "index, not a list"}') == []


def test_plugin_finds_exposed_accounts_on_fixture():
    from app.plugins.usernames import UsernamesPlugin
    from plugin_fixtures import run_plugin_fixture, url_target
    status, findings, err = asyncio.run(
        run_plugin_fixture(UsernamesPlugin, url_target(), "passive"))
    assert status == "ok", err
    by_key = {}
    for f in findings:
        by_key.setdefault(f.key, []).append(f)
    assert "username_in_code" in by_key
    names = by_key["username_in_code"][0].evidence["usernames"]
    assert "deploy-bot" in names and "svc-reports" in names
    assert "wp_author_accounts" in by_key
    wp = by_key["wp_author_accounts"][0]
    assert "fixture-admin" in wp.value
    assert wp.evidence["default_accounts"] == ["admin"]
