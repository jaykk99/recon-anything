"""Crypto-class target priority (Jay, 2026-10-23).

"Make sure if doing a crypto.com url like Crypto.com it should
find private keys not just whatever it's finding."

Covered here:
- classification: crypto/web3 seed targets are recognized
  (domain keywords, wallet-address targets, pack selection) and
  ordinary sites are not;
- the key-hunter set: cp_secret_*/cp_wallet_* + core hunters,
  never the address-format plugins;
- claiming: on a crypto-class run the key hunters claim FIRST
  and are exempt from the time-budget skips; on a non-crypto
  run nothing changes;
- enqueue: key hunters go in at HIGH priority on crypto runs;
- ranking: findings_dump puts exposed key/seed/keystore
  findings on top of a crypto run, flagged critical, and leaves
  non-crypto runs untouched;
- CANARY end-to-end: a fake crypto site (MockTransport, zero
  network) serving a BIP-39 seed in its JS bundle, a WIF + hex
  private key in /.env, and a keystore JSON at /keystore.json -
  the real hunter plugins find all of them, and no finding value
  ever carries a full secret. All canary secrets are published
  test vectors (BIP-39 zero-entropy phrase, the Bitcoin-wiki
  WIF for private key 1, private key 0x00..01): fake by design.
"""
import asyncio
import hashlib
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import httpx  # noqa: E402
import pytest  # noqa: E402
from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app import cryptotarget as ct  # noqa: E402
from app import models  # noqa: E402
from app import runner  # noqa: E402
from app.classifier import classify  # noqa: E402
from app.models import Finding, PluginJob, Run, Target as TargetRow  # noqa: E402

_TMPDB = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                      "_tmp_crypto_priority.db")


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------

def _classify(raw):
    return ct.classify_crypto_targets([classify(raw)])


def test_crypto_domains_classify_crypto():
    for raw in ("crypto.com", "https://crypto.com/en",
                "my-wallet-service.io", "app.uniswap.org",
                "bitcoin-vault.example.com", "shop.solana-pay.net",
                "defi-yield-farm.xyz", "trezor-bridge.io"):
        info = _classify(raw)
        assert info["crypto"], f"{raw} -> {info}"


def test_plain_domains_do_not_classify_crypto():
    for raw in ("example.com", "methodist-church.org",
                "winnipegwebworks.com", "guttergenie.pages.dev",
                "news.ycombinator.com", "ethical-hacking.io"):
        info = _classify(raw)
        assert not info["crypto"], f"{raw} -> {info}"


def test_wallet_address_target_is_crypto():
    info = _classify("1BoatSLRHtKNngkdXEeobR76b53LETtpyT")
    assert info["crypto"] and info["reasons"]


def test_pack_selection_marks_run_crypto():
    info = ct.classify_crypto_targets(
        [classify("example.com")], plugin_ids=["cp_secret_env_privkey"])
    assert info["crypto"]
    info2 = ct.classify_crypto_targets(
        [classify("example.com")], plugin_ids=["port_scan"])
    assert not info2["crypto"]


def test_key_hunter_set_membership():
    ids = ["cp_secret_env_privkey", "cp_wallet_keystore_file",
           "cp_wallet_metamask_vault", "cp_btc_legacy", "cp_eth_eip55",
           "wallets", "secrets", "keyleak", "keyharvest", "js_secrets",
           "port_scan", "headers", "cp_drainer_seedform"]
    hunters = ct.key_hunter_ids(ids)
    for expected in ("cp_secret_env_privkey", "cp_wallet_keystore_file",
                     "cp_wallet_metamask_vault", "wallets", "secrets",
                     "keyleak", "keyharvest", "js_secrets"):
        assert expected in hunters, expected
    # address formats and drainer lures are NOT key hunters
    for excluded in ("cp_btc_legacy", "cp_eth_eip55", "port_scan",
                     "headers", "cp_drainer_seedform"):
        assert excluded not in hunters, excluded


def test_real_registry_hunters_exist():
    from app.plugins.registry import discover
    reg = discover()
    hunters = ct.key_hunter_ids(list(reg))
    # 21 cp_secret + 14 cp_wallet + 5 core, as of the v2 pack
    assert len(hunters) >= 35, len(hunters)
    for pid in ("cp_secret_bip39_sequence", "cp_secret_env_privkey",
                "cp_wallet_keystore_file", "cp_wallet_metamask_vault",
                "cp_wallet_phantom_vault", "wallets", "secrets"):
        assert pid in hunters, pid


# ---------------------------------------------------------------------------
# Claiming + enqueue (throwaway DB, the test_selected_means_run pattern)
# ---------------------------------------------------------------------------

@pytest.fixture()
def db():
    engine = create_engine(f"sqlite:///{_TMPDB}")
    models.Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    orig_engine, orig_factory = models.engine, models.SessionLocal
    models.engine, models.SessionLocal = engine, factory
    runner._run_clocks.clear()
    session = factory()
    yield session
    session.close()
    models.engine, models.SessionLocal = orig_engine, orig_factory
    engine.dispose()
    runner._run_clocks.clear()
    try:
        os.unlink(_TMPDB)
    except OSError:
        pass


def _mk_run(session, run_id, crypto=False, hunters=None, plugin_ids=None):
    meta = {"mode": "passive", "plugin_ids": plugin_ids,
            "source_type": "website", "crypto_target": crypto,
            "crypto_reasons": ["domain keyword 'crypto'"] if crypto else [],
            "key_hunter_ids": hunters or []}
    run = Run(id=run_id, mode="passive", status="running",
              summary={"queue_meta": meta})
    session.add(run)
    t = TargetRow(id=f"t-{run_id}", run_id=run_id, raw="crypto-canary.test",
                  type="domain", normalized="crypto-canary.test")
    session.add(t)
    session.commit()
    return t


def _mk_job(session, run_id, target_id, plugin_id, priority=3):
    job = PluginJob(run_id=run_id, target_id=target_id,
                    plugin_id=plugin_id, phase=1, priority=priority,
                    estimate_s=60, status="queued")
    session.add(job)
    session.commit()
    return job


def _age_past_hard_stop(run_id):
    runner._run_clocks[run_id] = (
        time.monotonic() - (runner.SCAN_HARD_STOP_S + 500))


def test_key_hunter_claimed_past_hard_stop_on_crypto_run(db):
    t = _mk_run(db, "run-crypto", crypto=True,
                hunters=["cp_secret_env_privkey", "wallets"])
    kh = _mk_job(db, "run-crypto", t.id, "cp_secret_env_privkey")
    generic = _mk_job(db, "run-crypto", t.id, "port_scan")
    _age_past_hard_stop("run-crypto")
    claimed = runner._claim_jobs(db, limit=10)
    claimed_ids = [j.id for j in claimed]
    assert kh.id in claimed_ids
    assert generic.id not in claimed_ids
    db.refresh(generic)
    assert generic.status == "skipped"
    assert "time budget" in (generic.result or {}).get("reason", "")


def test_key_hunter_claims_first_on_crypto_run(db):
    t = _mk_run(db, "run-order-c", crypto=True,
                hunters=["cp_secret_env_privkey"])
    hi = _mk_job(db, "run-order-c", t.id, "port_scan", priority=1)
    kh = _mk_job(db, "run-order-c", t.id, "cp_secret_env_privkey",
                 priority=3)
    claimed = runner._claim_jobs(db, limit=1)
    assert [j.id for j in claimed] == [kh.id]
    db.refresh(hi)
    assert hi.status == "queued"


def test_no_crypto_flag_no_exemption(db):
    # key_hunter_ids recorded but the run is NOT crypto-class:
    # the old budget behavior must apply unchanged.
    t = _mk_run(db, "run-plain", crypto=False,
                hunters=["cp_secret_env_privkey"])
    kh = _mk_job(db, "run-plain", t.id, "cp_secret_env_privkey")
    _age_past_hard_stop("run-plain")
    claimed = runner._claim_jobs(db, limit=10)
    assert kh.id not in [j.id for j in claimed]
    db.refresh(kh)
    assert kh.status == "skipped"


def test_enqueue_boosts_key_hunters_to_high(db):
    from app.plugins.base import Target as PluginTarget
    from app.plugins.registry import discover
    reg = discover()
    plugins = [reg["cp_secret_env_privkey"](), reg["port_scan"]()]
    trobj = [PluginTarget(raw="crypto-canary.test", type="domain",
                          normalized="crypto-canary.test")]
    n = runner._enqueue_jobs(db, "run-boost", plugins, trobj,
                             boost_ids={"cp_secret_env_privkey"})
    assert n == 2
    rows = {j.plugin_id: j for j in
            db.query(PluginJob).filter_by(run_id="run-boost").all()}
    assert rows["cp_secret_env_privkey"].priority == 1
    assert rows["port_scan"].priority == 3  # static tier kept


# ---------------------------------------------------------------------------
# Ranking at read time (findings_dump)
# ---------------------------------------------------------------------------

def _add_finding(session, run_id, plugin, key, category="leak",
                 value="x", confidence=80):
    f = Finding(run_id=run_id, target_id="t", plugin_id=plugin,
                category=category, key=key, value=value,
                source="test", confidence=confidence,
                evidence={"severity": "high"}, passive=True)
    session.add(f)
    session.commit()
    return f


def test_findings_dump_ranks_keys_first_on_crypto_run(db):
    from app.reporting import findings_dump
    _mk_run(db, "run-rank", crypto=True,
            hunters=["cp_secret_env_privkey"])
    _add_finding(db, "run-rank", "headers", "missing_hsts",
                 category="web", value="no HSTS header")
    _add_finding(db, "run-rank", "subdomains", "subdomain_found",
                 category="dns", value="dev.crypto-canary.test")
    _add_finding(db, "run-rank", "cp_secret_env_privkey",
                 "env_private_key", value="CRITICAL: key abcd...wxyz")
    _add_finding(db, "run-rank", "wallets", "keystore_json",
                 value="keystore stub")
    rows = findings_dump(db, "run-rank")
    keys = [r["key"] for r in rows]
    assert keys.index("env_private_key") < keys.index("missing_hsts")
    assert keys.index("keystore_json") < keys.index("missing_hsts")
    top = [r for r in rows if r.get("crypto_key_finding")]
    assert {r["key"] for r in top} == {"env_private_key", "keystore_json"}
    for r in top:
        assert r["bounty_value"] == "critical"
        assert r["evidence"]["severity"] == "critical"
    generic = [r for r in rows if not r.get("crypto_key_finding")]
    assert all(r["bounty_value"] != "critical" for r in generic)


def test_findings_dump_untouched_on_plain_run(db):
    from app.reporting import findings_dump
    _mk_run(db, "run-rank-plain", crypto=False)
    _add_finding(db, "run-rank-plain", "headers", "missing_hsts",
                 category="web", value="no HSTS header")
    _add_finding(db, "run-rank-plain", "cp_secret_env_privkey",
                 "env_private_key", value="CRITICAL: key abcd...wxyz")
    rows = findings_dump(db, "run-rank-plain")
    assert all(not r.get("crypto_key_finding") for r in rows)
    assert rows[0]["key"] == "missing_hsts"  # insertion order kept


def test_exposed_key_matcher_precision():
    assert ct.is_exposed_key_finding(
        {"plugin": "cp_secret_wif_uncompressed", "key": "wif_key",
         "category": "leak"})
    assert ct.is_exposed_key_finding(
        {"plugin": "wallets", "key": "keystore_json", "category": "leak"})
    assert ct.is_exposed_key_finding(
        {"plugin": "secrets", "key": "private_key", "category": "leak"})
    # a drainer kit's seed-form lure is a phishing artifact, not the
    # target's own exposed key - it must not rank as one
    assert not ct.is_exposed_key_finding(
        {"plugin": "cp_drainer_seedform", "key": "seed_form_lure",
         "category": "web3"})
    assert not ct.is_exposed_key_finding(
        {"plugin": "headers", "key": "missing_hsts", "category": "web"})


# ---------------------------------------------------------------------------
# CANARY: real hunter plugins vs a fake crypto site (MockTransport)
# ---------------------------------------------------------------------------

CANARY_HOST = "crypto-canary.test"

# Published test vectors, fake by design: BIP-39 zero-entropy
# phrase, the Bitcoin-wiki WIF for private key 1, private key 1.
def _canary_phrase() -> str:
    from app.plugins.cryptopack_secrets import BIP39_WORDS
    ent = bytes(16)
    bits = "".join(format(b, "08b") for b in ent)
    bits += format(hashlib.sha256(ent).digest()[0], "08b")[:4]
    return " ".join(BIP39_WORDS[int(bits[i:i + 11], 2)]
                    for i in range(0, len(bits), 11))


CANARY_WIF = "5Kb8kLf9zgWQnogidDA76MzPL6TsZZY36hWXMssSzNydYXYB9KF"
CANARY_HEX = "0x" + "0" * 63 + "1"  # private key 1, exactly 64 hex

CANARY_KEYSTORE = (
    '{"version": 3, "id": "canary", '
    '"address": "7e5f4552091a69125d5dfcb7b8c2659029395bdf", '
    '"crypto": {"cipher": "aes-128-ctr", '
    '"ciphertext": "canaryciphertext", "kdf": "scrypt", '
    '"kdfparams": {}, "mac": "canarymac"}}')


def _canary_routes(phrase: str):
    home = ("<!DOCTYPE html><html><head><title>Crypto Canary "
            "Exchange</title></head><body><h1>Crypto Canary</h1>"
            '<script src="/static/app.js"></script>'
            "</body></html>")
    app_js = (f'const backupPhrase = "{phrase}";\n'
              f'const cfg = {{ MNEMONIC: "{phrase}" }};\n')
    env = (f"# canary config - fake test values only\n"
           f"PRIVATE_KEY={CANARY_HEX}\nWALLET_WIF={CANARY_WIF}\n")
    return {"/": home, "/static/app.js": app_js, "/.env": env,
            "/keystore.json": CANARY_KEYSTORE}


def _run_canary_plugins(plugin_ids, crypto_flag=True):
    from app.cache import Cache
    from app.plugins.base import Ctx, Target
    from app.plugins.registry import discover
    from app.ratelimit import RateLimiter
    phrase = _canary_phrase()
    routes = _canary_routes(phrase)

    def handler(request: httpx.Request) -> httpx.Response:
        body = routes.get(request.url.path)
        if body is None:
            return httpx.Response(404, text="not found")
        return httpx.Response(200, text=body)

    async def main():
        transport = httpx.MockTransport(handler)
        async with httpx.AsyncClient(transport=transport,
                                     follow_redirects=True,
                                     trust_env=False) as client:
            ctx = Ctx(run_id="canary", mode="passive", http=client,
                      cache=Cache(), keys={}, limiter=RateLimiter(50))
            ctx.shared["crypto_target"] = crypto_flag
            target = Target(raw=CANARY_HOST, type="domain",
                            normalized=CANARY_HOST)
            reg = discover()
            findings = []
            for pid in plugin_ids:
                result = await reg[pid]().run(target, ctx)
                findings.extend(result.findings)
            return findings

    return asyncio.run(main()), phrase


def test_canary_crypto_site_key_hunters_find_planted_secrets():
    assert _classify(CANARY_HOST)["crypto"]
    plugins = ["cp_secret_bip39_sequence", "cp_secret_env_mnemonic",
               "cp_secret_env_privkey", "cp_secret_wif_uncompressed",
               "cp_wallet_keystore_file", "wallets"]
    findings, phrase = _run_canary_plugins(plugins)
    keys = [f.key for f in findings]
    # the seed phrase in the JS bundle
    assert "bip39_seed_phrase" in keys, keys
    # the hex private key in /.env (pack env detector, crypto surface)
    assert "env_private_key" in keys, keys
    # the WIF in /.env
    assert any("wif" in k for k in keys), keys
    # the keystore JSON at the wallet path
    assert "keystore_file_exposed" in keys, keys
    # full secrets NEVER appear in any finding value
    blob = " ".join(f.value for f in findings)
    assert phrase not in blob
    assert CANARY_WIF not in blob
    assert CANARY_HEX not in blob
    # and the found key findings rank as exposed-key findings
    for f in findings:
        if f.key in ("bip39_seed_phrase", "env_private_key",
                     "keystore_file_exposed") or "wif" in f.key:
            row = {"plugin": f.plugin_id if hasattr(f, "plugin_id")
                   else "", "key": f.key, "category": f.category}
            assert ct.is_exposed_key_finding(row), row


def test_canary_env_surface_is_crypto_gated():
    # without the crypto flag the pack env detector never sees
    # /.env, so the planted hex key stays unfound by it
    findings, _ = _run_canary_plugins(["cp_secret_env_privkey"],
                                      crypto_flag=False)
    assert "env_private_key" not in [f.key for f in findings]
