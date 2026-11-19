"""Content-signature verification: real exposures confirm, SPA/WAF
catch-alls and bare status hits do not."""
from app.plugins.exposure_signatures import (
    confirm_exposure, signature_expected)

SPA = ('<!doctype html><html><head><title>MyApp</title></head>'
       '<body><div id="root"></div><script src="/app.js"></script>'
       '</body></html>')


def test_spa_catchall_env_not_confirmed():
    # The #1 false positive: SPA returns 200 + index.html for /.env
    assert confirm_exposure("/.env", 200, SPA) is None


def test_spa_catchall_git_config_not_confirmed():
    assert confirm_exposure("/.git/config", 200, SPA) is None


def test_real_env_confirmed_with_secret_keys():
    body = ("# app config\nDB_HOST=10.0.0.5\nDB_PASSWORD=s3cr3tp4ss\n"
            "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI\nDEBUG=true\n")
    r = confirm_exposure("/.env", 200, body)
    assert r is not None
    assert r["kind"] == "exposed_file"
    assert r["severity"] == "critical"  # credential keys escalate high->critical
    assert "DB_PASSWORD" in r["proof"] or "credential" in r["proof"].lower()


def test_real_git_head_confirmed():
    r = confirm_exposure("/.git/HEAD", 200, "ref: refs/heads/main\n")
    assert r is not None and "git" in r["label"].lower()


def test_git_head_detached_sha_confirmed():
    r = confirm_exposure("/.git/HEAD", 200, "a" * 40)
    assert r is not None


def test_git_config_confirmed():
    body = ("[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n"
            "\turl = git@github.com:acme/secret.git\n")
    r = confirm_exposure("/.git/config", 200, body)
    assert r is not None and r["severity"] == "high"


def test_directory_listing_confirmed_any_path():
    body = "<html><head><title>Index of /backups</title></head><body><h1>Index of /backups</h1><a href='db.sql'>db.sql</a></body></html>"
    r = confirm_exposure("/backups/", 200, body)
    assert r is not None and r["kind"] == "directory_listing"


def test_sql_dump_confirmed():
    body = "-- MySQL dump 10.13\nCREATE TABLE `users` (id INT);\nINSERT INTO `users` VALUES (1);"
    r = confirm_exposure("/backup.sql", 200, body)
    assert r is not None and "dump" in r["label"].lower()


def test_openapi_confirmed():
    body = '{"openapi":"3.0.0","paths":{"/users":{},"/admin":{}}}'
    r = confirm_exposure("/openapi.json", 200, body)
    assert r is not None and "2 paths" in r["proof"]


def test_openapi_html_not_confirmed():
    assert confirm_exposure("/swagger.json", 200, SPA) is None


def test_htpasswd_confirmed():
    body = "admin:$apr1$abcd$ef.gh/\nuser:$2y$10$abcdefghijklmnopqrstuv\n"
    r = confirm_exposure("/.htpasswd", 200, body)
    assert r is not None and "htpasswd" in r["label"].lower()


def test_php_source_with_db_creds_escalates():
    body = "<?php\ndefine('DB_PASSWORD', 'hunter2');\n$x = 1;"
    r = confirm_exposure("/wp-config.php.bak", 200, body)
    assert r is not None and r["severity"] == "critical"


def test_aws_credentials_confirmed():
    body = "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalr\n"
    r = confirm_exposure("/.aws/credentials", 200, body)
    assert r is not None and r["severity"] == "critical"


def test_404_never_confirms():
    body = "DB_PASSWORD=real\n" * 5
    assert confirm_exposure("/.env", 404, body) is None


def test_empty_body_never_confirms():
    assert confirm_exposure("/.env", 200, "") is None


def test_graphql_introspection_confirmed():
    body = '{"data":{"__schema":{"queryType":{"name":"Query"},"types":[{"kind":"OBJECT","name":"User"}]}}}'
    r = confirm_exposure("/graphql", 200, body)
    assert r is not None


def test_prose_with_one_equals_not_env():
    # a page that happens to contain "a=b" is not an env file
    body = SPA + "\nnote: set x=1 in your shell"
    assert confirm_exposure("/.env", 200, body) is None


def test_signature_expected_flags_sensitive_paths():
    assert signature_expected("/.env")
    assert signature_expected("/.git/config")
    assert signature_expected("/wp-config.php.bak")
    assert not signature_expected("/admin")
    assert not signature_expected("/dashboard")
