"""Crypto pack: Web3 infrastructure inventory.

What chain infrastructure the target actually wires into its pages:
RPC endpoints, chain IDs, token/NFT contracts in context, DEX router
and bridge references, Solana program IDs, oracle feeds, multisigs,
faucet/testnet leakage, and served contract artifacts. Inventory is
recon gold: it maps the target's real on-chain footprint and the
third parties that footprint depends on.
"""
from __future__ import annotations

from .cryptopack_util import PackPlugin

KNOWN_RPC_HOSTS = (
    "eth.llamarpc.com", "rpc.ankr.com", "ethereum.publicnode.com",
    "polygon.llamarpc.com", "polygon-rpc.com", "arb1.arbitrum.io",
    "mainnet.optimism.io", "mainnet.base.org", "bsc-dataseed.binance.org",
    "avax-p2p.com", "api.avax.network", "rpc.fantom.network",
    "mainnet.infura.io", "rpc.mevblocker.io", "1rpc.io",
    "eth.drpc.org", "polygon.drpc.org", "solana.drpc.org",
    "api.mainnet-beta.solana.com", "rpc.helius.xyz",
    "mainnet.helius-rpc.com", "bsc.publicnode.com",
    "arbitrum.publicnode.com", "base.publicnode.com",
    "blastapi.io", "public.blastapi.io", "nodereal.io",
    "gateway.pokt.network", "rpc.pokt.online",
)


class CpWeb3RpcEndpoints(PackPlugin):
    id = "cp_web3_rpc_endpoints"
    label = "Web3 RPC endpoint inventory"
    description = ("Public/third-party RPC endpoint URLs wired into "
                   "the target's pages and JS, per provider.")
    VALUE_GROUP = 1
    PATTERNS = [
        (r"((?:https?|wss?)://[a-z0-9.\-]*(?:"
         + "|".join(h.replace(".", r"\.") for h in KNOWN_RPC_HOSTS)
         + r")[^\s\"'<>]*)", "rpc_endpoint", "RPC endpoint URL", 75, None),
    ]


class CpWeb3ChainIdRefs(PackPlugin):
    id = "cp_web3_chainid_refs"
    label = "Chain ID references"
    description = ("Chain IDs hardcoded in JS (hex or decimal) - the "
                   "networks the target's Web3 code actually targets, "
                   "including testnets that should not ship to prod.")
    PATTERNS = [
        (r"\bchainId\s*[:=]\s*(0x[0-9a-fA-F]+|\d{1,6})\b", "chain_id_ref",
         "chainId reference", 65, None),
        (r"\bnetworkVersion\s*[:=]\s*[\"']?(\d{1,6})", "chain_id_ref",
         "networkVersion reference", 60, None),
    ]


class CpWeb3TokenContracts(PackPlugin):
    id = "cp_web3_token_contracts"
    label = "Token contract inventory (in context)"
    description = ("0x contract addresses anchored to ERC-20/token "
                   "context (symbol, decimals, transfer ABI) - the "
                   "tokens the target integrates, not random hashes.")
    CONTEXT_RE = (r"erc20|token|symbol|decimals|transfer\(|balanceOf")
    VALUE_GROUP = 1
    PATTERNS = [(r"(0x[0-9a-fA-F]{40})", "token_contract",
                 "Token contract address", 75, None)]


class CpWeb3NftContracts(PackPlugin):
    id = "cp_web3_nft_contracts"
    label = "NFT contract inventory (in context)"
    description = ("Contract addresses anchored to ERC-721/1155, "
                   "minting, or marketplace (OpenSea/Blur) context.")
    CONTEXT_RE = r"erc721|erc1155|nft|mint|opensea|blur\.io"
    VALUE_GROUP = 1
    PATTERNS = [(r"(0x[0-9a-fA-F]{40})", "nft_contract",
                 "NFT contract address", 75, None)]


class CpWeb3DexRouters(PackPlugin):
    id = "cp_web3_dex_routers"
    label = "DEX router references (known addresses)"
    description = ("Canonical DEX router/factory addresses appearing "
                   "in the target's content - which venues its swaps "
                   "route through.")
    PATTERNS = [
        (r"\b0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D\b",
         "dex_router_uniswap_v2", "Uniswap V2 router", 85, None),
        (r"\b0xE592427A0AEce92De3Edee1F18E0157C05861564\b",
         "dex_router_uniswap_v3", "Uniswap V3 SwapRouter", 85, None),
        (r"\b0x10ED43C718714eb63d5aA57B78B54704E256024E\b",
         "dex_router_pancakeswap", "PancakeSwap router", 85, None),
        (r"\b0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F\b",
         "dex_router_sushiswap", "SushiSwap router", 85, None),
        (r"(?i)\b0xa5E0829CaCEd8fFDD4De3c43696c57F7D7A678ff\b",
         "dex_router_quickswap", "QuickSwap router", 80, None),
        (r"\b0x1F98431c8aD98523631AE4a59f267346ea31F984\b",
         "dex_factory_uniswap_v3", "Uniswap V3 factory", 85, None),
    ]


class CpWeb3BridgeRefs(PackPlugin):
    id = "cp_web3_bridge_refs"
    label = "Bridge references"
    description = ("Cross-chain bridge services/contracts the target "
                   "points users at (Across, Hop, Stargate, Synapse, "
                   "Connext, Orbiter) - high-value phishing clones "
                   "cluster around these names.")
    PATTERNS = [
        (r"(?:across\.to|app\.across\.to|AcrossProtocol)",
         "bridge_across", "Across bridge reference", 75, None),
        (r"(?:hop\.exchange|app\.hop\.exchange)", "bridge_hop",
         "Hop bridge reference", 75, None),
        (r"(?:stargate\.finance|Stargate)", "bridge_stargate",
         "Stargate bridge reference", 70, None),
        (r"(?:synapseprotocol\.com|app\.synapseprotocol\.com)",
         "bridge_synapse", "Synapse bridge reference", 75, None),
        (r"(?:connext\.network|bridge\.connext\.network)",
         "bridge_connext", "Connext bridge reference", 75, None),
        (r"(?:orbiter\.finance)", "bridge_orbiter",
         "Orbiter bridge reference", 75, None),
    ]


class CpWeb3SolanaPrograms(PackPlugin):
    id = "cp_web3_solana_programs"
    label = "Solana program references (known IDs)"
    description = ("Canonical Solana program IDs in content - which "
                   "on-chain programs the target's frontend invokes.")
    PATTERNS = [
        (r"\bTokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA\b",
         "solana_program_token", "SPL Token program", 85, None),
        (r"\bATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL\b",
         "solana_program_ata", "Associated Token program", 85, None),
        (r"\bJUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4\b",
         "solana_program_jupiter", "Jupiter aggregator program", 85, None),
        (r"\bwhirLbMiicVdio4qvUfM5KAg6Ct8VwpYzGff3uctyCc\b",
         "solana_program_orca", "Orca Whirlpools program", 85, None),
        (r"\b675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8\b",
         "solana_program_raydium", "Raydium AMM program", 85, None),
        (r"\bmetaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s\b",
         "solana_program_metaplex", "Metaplex program", 85, None),
    ]


class CpWeb3WalletconnectProject(PackPlugin):
    id = "cp_web3_walletconnect_project"
    label = "WalletConnect project ID exposure"
    description = ("WalletConnect/Reown project IDs in JS - they map "
                   "the dapp's wallet traffic to a cloud account and "
                   "are a favorite clone target.")
    VALUE_GROUP = 1
    PATTERNS = [
        (r"(?:projectId|WALLETCONNECT_PROJECT_ID|NEXT_PUBLIC_WC_PROJECT_ID)"
         r"\s*[:=]\s*[\"']([0-9a-f]{32})[\"']",
         "walletconnect_project_id", "WalletConnect project ID", 70, None),
    ]


class CpWeb3Siwe(PackPlugin):
    id = "cp_web3_siwe"
    label = "Sign-In With Ethereum (SIWE) surface"
    description = ("SIWE message templates / sign-in domains in JS - "
                   "the auth surface an attacker must clone to phish "
                   "this target's users.")
    PATTERNS = [
        (r"(?:wants you to sign in with your Ethereum account|"
         r"siwe|Sign-?In With Ethereum|createSiweMessage)",
         "siwe_surface", "SIWE sign-in surface", 70, None),
    ]


class CpWeb3Multisig(PackPlugin):
    id = "cp_web3_multisig"
    label = "Multisig (Safe) references"
    description = ("Safe/Gnosis multisig references: app links, "
                   "contract names, owner/threshold config in JS.")
    PATTERNS = [
        (r"(?:app\.safe\.global|safe\.global|GnosisSafe|Safe\{L2\}|"
         r"multiSend|owners\s*:\s*\[0x)",
         "multisig_ref", "Safe multisig reference", 75, None),
    ]


class CpWeb3OracleRefs(PackPlugin):
    id = "cp_web3_oracle_refs"
    label = "Price oracle references (Chainlink)"
    description = ("Chainlink aggregator/feed references in code - "
                   "the price sources the target's contracts trust.")
    PATTERNS = [
        (r"(?:AggregatorV3Interface|latestRoundData|chainlink)",
         "oracle_ref", "Chainlink oracle reference", 70, None),
    ]


class CpWeb3TestnetFaucets(PackPlugin):
    id = "cp_web3_testnet_faucets"
    label = "Testnet/faucet references in production"
    description = ("Testnet RPCs and faucet URLs referenced by the "
                   "production site - environment bleed that maps the "
                   "target's dev infrastructure.")
    PATTERNS = [
        (r"(?:faucet\.(?:goerli|sepolia|mumbai)|goerlifaucet|"
         r"sepoliafaucet|faucet\.quicknode\.com|"
         r"(?:goerli|sepolia|mumbai)[a-z0-9.\-]*\.(?:infura\.io|"
         r"alchemy\.com|publicnode\.com))",
         "testnet_ref", "Testnet/faucet reference", 70, None),
    ]


class CpWeb3HardhatArtifacts(PackPlugin):
    id = "cp_web3_hardhat_artifacts"
    label = "Served contract artifacts / ABIs"
    description = ("Contract artifacts shipped to the browser: ABI "
                   "arrays, deployed bytecode, contractName fields - "
                   "a full map of the target's contract internals.")
    PATTERNS = [
        (r"(?:\"contractName\"\s*:|\"bytecode\"\s*:\s*\"0x[0-9a-fA-F]{100,}|"
         r"\"abi\"\s*:\s*\[\s*\{\s*\"(?:inputs|type)\"|deployedBytecode)",
         "contract_artifact", "Served contract artifact/ABI", 75, None),
    ]
