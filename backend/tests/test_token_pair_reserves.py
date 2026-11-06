"""Validator V2 (lane L2): token_pair_reserves (scripts runner).

validate_candidate consumes balances["token_pair_reserves"]
for the mint-value gate, but pair_reserves() only answers
when the contract IS a pair. token_pair_reserves() finds the
token's pair against the wrapped native token through the
chain's known DEX factories, read-only via cast. _cast is
monkeypatched; no network or cast binary is touched.
"""
import importlib.util
import pathlib


def _load_runner():
    path = pathlib.Path(__file__).resolve().parent.parent / \
        "scripts" / "auto_validate.py"
    spec = importlib.util.spec_from_file_location(
        "auto_validate_runner_tpr", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


TOKEN = "0x" + "a" * 40
PAIR = "0x" + "b" * 40
UNI_FACTORY = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
SUSHI_FACTORY = "0xC0AEe478e3658e2610c5F7A4A2E1777cE9e4f2Ac"


def _fake_cast(table):
    """table: {(factory_lower, first_arg_lower): output} for
    getPair; reserves outputs keyed by pair address."""
    def fake(args, timeout=25):
        # args: ["call", "--from", STRANGER, "--rpc-url", rpc,
        #        address, signature, *call_args]
        target = args[5].lower()
        sig = args[6]
        if "getPair" in sig:
            key = (target, args[7].lower())
            out = table.get(key)
            if out is None:
                return "execution reverted", None
            return out, None
        if "getReserves" in sig:
            return table.get(("reserves", target),
                             "execution reverted"), None
        return "execution reverted", None
    return fake


def test_pair_found_first_factory(monkeypatch):
    mod = _load_runner()
    table = {("reserves", PAIR): "1000\n2000\n1700000000\n"}
    for factory, wrapped in mod.DEX_PAIRS["ethereum"][:1]:
        table[(factory.lower(), TOKEN)] = PAIR
        table[(factory.lower(), wrapped.lower())] = PAIR
    monkeypatch.setattr(mod, "_cast", _fake_cast(table))
    out = mod.token_pair_reserves("ethereum", TOKEN)
    assert out is not None
    assert out["pair"] == PAIR
    assert out["factory"] == UNI_FACTORY
    assert out["reserve0"] == 1000
    assert out["reserve1"] == 2000
    assert out["observed_at"]
    assert out["source"]


def test_revert_on_first_factory_moves_to_next(monkeypatch):
    mod = _load_runner()
    table = {("reserves", PAIR): "5\n7\n1700000000\n"}
    # Uniswap getPair reverts (not a factory answer for this
    # token); SushiSwap has the pair.
    wrapped = mod.DEX_PAIRS["ethereum"][1][1]
    table[(SUSHI_FACTORY.lower(), TOKEN)] = PAIR
    table[(SUSHI_FACTORY.lower(), wrapped.lower())] = PAIR
    monkeypatch.setattr(mod, "_cast", _fake_cast(table))
    out = mod.token_pair_reserves("ethereum", TOKEN)
    assert out is not None
    assert out["factory"] == SUSHI_FACTORY
    assert out["reserve0"] == 5


def test_zero_address_everywhere_returns_none(monkeypatch):
    mod = _load_runner()
    zero = "0x" + "0" * 40

    def fake(args, timeout=25):
        if "getPair" in args[6]:
            return zero, None
        return "execution reverted", None
    monkeypatch.setattr(mod, "_cast", fake)
    assert mod.token_pair_reserves("ethereum", TOKEN) is None


def test_bnb_alias_and_unknown_chain(monkeypatch):
    mod = _load_runner()
    monkeypatch.setattr(mod, "_cast", _fake_cast({}))
    assert mod.token_pair_reserves("bnb", TOKEN) is None
    assert mod.token_pair_reserves("solana", TOKEN) is None
