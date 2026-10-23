"""Crypto pack wave 2: exposed node & wallet infrastructure.

Node RPC surfaces the target references or exposes in its own
content: credentialed Bitcoin Core RPC URLs, Electrum servers,
dev nodes (Ganache/Hardhat) bleeding into production, the
deterministic Hardhat test accounts used as if they were real
wallets, RPC URLs with embedded credentials, BTCPay config
artifacts, and non-EVM chain RPC endpoints wave 1's host list
did not carry. Detection only - references and served content,
nothing is connected to or called.
"""
from __future__ import annotations

from .cryptopack_util import PackPlugin


class CpNodeBitcoindRpc(PackPlugin):
    id = "cp_node_bitcoind_rpc"
    label = "Bitcoin Core RPC exposure references"
    description = ("Credentialed bitcoind RPC URLs and bitcoin-cli "
                   "references in served content - the keys to the "
                   "node kingdom if the port is reachable.")
    CATEGORY = "leak"
    SECRET = True
    VALUE_GROUP = 1
    PATTERNS = [
        (r"((?:https?|tcp)://[^:\s/@\"']+:[^@\s\"']+@[^\s\"'<>]+?:"
         r"(?:8332|8333|18332|18443|18444)\b)",
         "bitcoind_rpc_url", "Credentialed bitcoind RPC URL", 92, None),
        (r"(bitcoin-cli\s+(?:-rpcuser|-rpcpassword|-rpcconnect))",
         "bitcoin_cli_ref", "bitcoin-cli credential reference", 80,
         None),
    ]


class CpNodeElectrumServer(PackPlugin):
    id = "cp_node_electrum_server"
    label = "Electrum server references"
    description = ("Electrum server endpoints (electrum://, :50002 "
                   "SSL stratum, ElectrumX) the target's wallet "
                   "infrastructure depends on - a malicious or "
                   "compromised server lies to every wallet using it.")
    VALUE_GROUP = 1
    PATTERNS = [
        (r"(electrum://[^\s\"'<>]+)", "electrum_server",
         "Electrum server URL", 82, None),
        (r"\b([a-z0-9.\-]+\.[a-z]{2,}:5000[12]\b)",
         "electrum_server_port", "Electrum server endpoint", 78, None),
        (r"(ElectrumX|electrumx\.announce|electrum server)",
         "electrum_server_ref", "Electrum server reference", 68, None),
    ]


class CpNodeDevnodeRefs(PackPlugin):
    id = "cp_node_devnode_refs"
    label = "Dev node endpoints in production (Ganache/Hardhat)"
    description = ("Local dev-node endpoints (localhost:8545/7545) "
                   "and Ganache/Hardhat node references shipped to "
                   "production - environment bleed that maps the "
                   "target's dev setup and breaks or exposes flows.")
    VALUE_GROUP = 1
    PATTERNS = [
        (r"((?:https?|wss?)://(?:localhost|127\.0\.0\.1|0\.0\.0\.0):"
         r"(?:8545|7545|9545)\b[^\s\"'<>]*)",
         "devnode_endpoint", "Local dev-node endpoint in production",
         85, None),
        (r"(ganache-cli|ganache\.app|Hardhat Node|hardhat node|"
         r"npx hardhat node)",
         "devnode_ref", "Dev node reference", 70, None),
    ]


# The first five deterministic Hardhat/Anvil accounts. Their private
# keys are published in the Hardhat docs - anyone on earth can spend
# from these addresses, so a production target using one as a real
# wallet (or a user being told to pay one) is a critical finding.
_HARDHAT_ACCOUNTS = (
    "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
    "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
    "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
    "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
    "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
)


class CpNodeHardhatAccounts(PackPlugin):
    id = "cp_node_hardhat_accounts"
    label = "Known Hardhat test accounts in production"
    description = ("The deterministic Hardhat/Anvil test accounts "
                   "(publicly known private keys) appearing in "
                   "production content - test wallets treated as "
                   "real ones; anything sent to them is gone.")
    PATTERNS = [
        (rf"(?i)\b{addr}\b", "hardhat_test_account",
         "Hardhat test account (known private key)", 92, None)
        for addr in _HARDHAT_ACCOUNTS
    ]


class CpNodeRpcCreds(PackPlugin):
    id = "cp_node_rpc_creds"
    label = "RPC URLs with embedded credentials"
    description = ("Web3 RPC URLs carrying userinfo credentials "
                   "(https://user:pass@node...) in served content - "
                   "authenticated node access, leaked.")
    CATEGORY = "leak"
    SECRET = True
    CONTEXT_RE = r"rpc|web3|ethereum|node|evm|json-?rpc"
    VALUE_GROUP = 1
    PATTERNS = [
        (r"((?:https?|wss?)://[^:\s/@\"']{2,}:[^@\s\"']{4,}@"
         r"[^\s\"'<>]{4,})",
         "rpc_url_credentials", "RPC URL with embedded credentials",
         90, None),
    ]


class CpNodeBtcpayConfig(PackPlugin):
    id = "cp_node_btcpay_config"
    label = "BTCPay Server config/backup artifacts"
    description = ("BTCPay Server database and config artifacts "
                   "(BTCPayServer.db, NBXplorer settings, backup "
                   "filenames) referenced in served content - the "
                   "store's payment configuration, and often its "
                   "xpubs, in one file.")
    PATTERNS = [
        (r"\b(BTCPayServer\.db|btcpay-backup[\w.\-]*|"
         r"btcpayserver[\w.\-]*\.conf(?:ig)?)\b",
         "btcpay_artifact", "BTCPay config/backup artifact", 80, None),
        (r"(NBXplorer.{0,60}(?:ConnectionString|postgres|sqlite))",
         "btcpay_nbxplorer_config", "NBXplorer backend config", 78,
         None),
    ]


class CpNodeNearRpc(PackPlugin):
    id = "cp_node_near_rpc"
    label = "NEAR / Avalanche RPC endpoint references"
    description = ("NEAR RPC endpoints and Avalanche C-Chain custom "
                   "RPC paths - chain infrastructure wave 1's host "
                   "inventory did not carry.")
    VALUE_GROUP = 1
    PATTERNS = [
        (r"((?:https?|wss?)://(?:rpc\.mainnet\.near\.org|"
         r"rpc\.testnet\.near\.org|rpc\.ankr\.com/near|"
         r"near\.drpc\.org)[^\s\"'<>]*)",
         "near_rpc_endpoint", "NEAR RPC endpoint", 78, None),
        (r"((?:https?|wss?)://[^\s\"'<>]*?/ext/bc/C/rpc\b[^\s\"'<>]*)",
         "avax_c_rpc", "Avalanche C-Chain RPC path", 75, None),
    ]
