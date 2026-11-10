"""Read-only RPC / signer hardblock: broadcasts and signing can't leave."""
import asyncio
import os
import sys

import httpx
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.rpc_guard import (  # noqa: E402
    RpcWriteBlocked, assert_payload_read_only, assert_read_only,
    enforce_read_only_env, is_blocked_method, signing_material_env,
)
from app import net  # noqa: E402

BLOCKED = ["eth_sendRawTransaction", "eth_sendTransaction", "eth_sign",
           "eth_signTransaction", "personal_sign", "personal_sendTransaction",
           "personal_unlockAccount", "sendTransaction", "requestAirdrop",
           "weird_sendRawTransaction"]
ALLOWED = ["eth_call", "eth_getCode", "eth_getStorageAt", "eth_getBalance",
           "eth_blockNumber", "getAccountInfo", "getProgramAccounts",
           "simulateTransaction"]  # simulate is read-only, must pass


@pytest.mark.parametrize("m", BLOCKED)
def test_write_methods_blocked(m):
    assert is_blocked_method(m)
    with pytest.raises(RpcWriteBlocked):
        assert_read_only(m)


@pytest.mark.parametrize("m", ALLOWED)
def test_read_methods_allowed(m):
    assert not is_blocked_method(m)
    assert_read_only(m)  # no raise


def test_batch_payload_blocks_if_any_write():
    assert_payload_read_only([{"method": "eth_call"}, {"method": "eth_getCode"}])
    with pytest.raises(RpcWriteBlocked):
        assert_payload_read_only(
            [{"method": "eth_call"}, {"method": "eth_sendTransaction"}])


def test_transport_hook_blocks_broadcast_at_client():
    """A guarded client refuses to broadcast even when a caller builds the
    JSON-RPC body directly, and still serves reads."""
    def handler(_req):
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1,
                                         "result": "0x1"})

    async def run():
        c = net.async_client(transport=httpx.MockTransport(handler))
        r = await c.post("https://rpc.example/",
                         json={"method": "eth_getCode", "params": ["0x0"]})
        assert r.status_code == 200
        with pytest.raises(RpcWriteBlocked):
            await c.post("https://rpc.example/",
                         json={"method": "eth_sendRawTransaction",
                               "params": ["0xdead"]})
        await c.aclose()

    asyncio.run(run())


def test_signing_material_env_detection():
    assert signing_material_env({"ALCHEMY_API_KEY": "x",
                                 "WALLET_PUBLIC_KEY": "0xpub"}) == []
    assert signing_material_env({"PRIVATE_KEY": "0xabc"}) == ["PRIVATE_KEY"]
    assert signing_material_env({"DEPLOYER_MNEMONIC": "a b c"}) == \
        ["DEPLOYER_MNEMONIC"]
    # placeholder / empty values are not real material
    assert signing_material_env({"PRIVATE_KEY": "your_private_key"}) == []
    assert signing_material_env({"PRIVATE_KEY": ""}) == []


def test_enforce_read_only_env_raises_on_key():
    enforce_read_only_env({"RPC_URL": "https://x", "ETHERSCAN_API_KEY": "k"})
    with pytest.raises(RpcWriteBlocked):
        enforce_read_only_env({"SEED_PHRASE": "a b c d e"})
