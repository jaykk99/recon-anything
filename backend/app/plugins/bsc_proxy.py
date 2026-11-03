"""BSC detectors: proxy & upgradeability (10 plugins).

Dedupe map (outcome per ID, also in the PR body):
- proxy_implementation_uninitialized: (c) shared initializer
  routine restricted to proxy implementations (bundle carries
  proxy/implementation markers, and an _disableInitializers
  constructor lock suppresses it); the access module's
  initializer detector covers non-proxy contracts and is
  suppressed on delegatecall bundles, so the two never
  double-fire on the same contract.
- proxy_storage_collision_detector: (a) NEW - proxy keeps its
  implementation/admin pointer in ordinary slot-ordered storage
  while delegatecalling (custom check).
- proxy_upgrade_authorization_gap: (c) shared gate routine
  restricted to upgrade functions carrying slot-write evidence.
- proxy_delegatecall_selfdestruct: (a) NEW - selfdestruct
  reachable inside a delegatecall compilation (destroys the
  implementation, bricking every proxy on it).
- proxy_beacon_address_manipulation: (b) BSC variant - beacon /
  beacon-setter surface instead of the proxy's own upgrade fn.
- proxy_cloning_initial_state_leak: (a) NEW - EIP-1167 clones
  deployed without an atomic initialize call.
- proxy_shadow_variable_override: (a) NEW - same watched state
  variable declared in proxy and implementation (custom check).
- proxy_function_clashing: (a) NEW - same function name defined
  on proxy and implementation in one compilation (custom).
- proxy_deterministic_deployment_collision: (a) NEW - CREATE2
  salt fully caller-supplied with no deployer binding.
- proxy_transparent_admin_misdirection: (a) NEW - fallback
  delegatecalls with no admin routing anywhere (custom check);
  fixtures keep the upgrade fn gated so the authorization-gap
  detector stays silent and spans never overlap.
"""
from __future__ import annotations

from .bsc_common import DetectorSpec, S, register_family

FAMILY = "proxy"

SPECS = [
    S("proxy_implementation_uninitialized", FAMILY,
      severity="high", outcome="c", fn_re=r"^initialize$|^init$",
      contract_need=(r"implementation|delegatecall|proxy",),
      contract_forbid=(r"_disableInitializers",),
      need_any=(r"\]\s*(\+|-)?=", r"\w+\s*=\s*msg\.sender",
                r"owner\s*="),
      forbid=(r"initializer", r"reinitializer"),
      detail="Implementation uninitialized: this proxy "
             "implementation's initialize() sets state with no "
             "initializer modifier and the implementation never "
             "locks itself with _disableInitializers, so anyone "
             "can initialize the IMPLEMENTATION directly and "
             "seize its owner/admin role (the Parity-class "
             "bug); from there any implementation-side "
             "privileged path is the attacker's."),
    S("proxy_storage_collision_detector", FAMILY,
      severity="high", outcome="a", custom="storage_collision",
      detail="Proxy storage collision: the proxy stores its "
             "implementation/admin pointer in an ordinary state "
             "variable instead of an EIP-1967 namespaced slot, "
             "so the implementation's own slot-0 variables "
             "overwrite the pointer (or the pointer overwrites "
             "implementation state) - the layout collision "
             "EIP-1967 exists to prevent."),
    S("proxy_upgrade_authorization_gap", FAMILY, severity="high",
      outcome="c", fn_re=r"upgrade", public_only=True,
      need_any=(r"sstore", r"implementation\s*=",
                r"_setImplementation|setImplementation\s*\("),
      gated_suppresses=True,
      detail="Upgrade authorization gap: the upgrade function "
             "rewrites the implementation pointer with NO "
             "access gate, so any stranger can point the proxy "
             "at their own implementation and take over every "
             "function and asset behind it."),
    S("proxy_delegatecall_selfdestruct", FAMILY, severity="high",
      outcome="a", scope="contract",
      contract_need=(r"selfdestruct", r"delegatecall"),
      need=(r"selfdestruct\s*\(",),
      detail="Delegatecall selfdestruct: this compilation both "
             "delegatecalls (proxy surface) and contains a "
             "selfdestruct. If the selfdestruct sits in code "
             "executed in the implementation's context, calling "
             "it destroys the implementation and permanently "
             "bricks every proxy delegating to it; in the "
             "proxy's context it destroys the proxy and traps "
             "its assets."),
    S("proxy_beacon_address_manipulation", FAMILY,
      severity="high", outcome="b", public_only=True,
      fn_re=r"setBeacon|setImplementation|upgradeBeacon",
      need_any=(r"beacon\s*=|implementation\s*=",
                r"_setImplementation|setImplementation\s*\("),
      gated_suppresses=True,
      detail="Beacon address manipulation: the function that "
             "sets the beacon (or the beacon's implementation) "
             "has NO access gate, so a stranger can repoint "
             "every beacon proxy at an attacker implementation "
             "in one call - a fleet-wide takeover, not a "
             "single-proxy one."),
    S("proxy_cloning_initial_state_leak", FAMILY,
      severity="medium", outcome="a",
      fn_re=r"clone|createProxy|deployProxy|createClone",
      need_any=(r"\.clone\s*\(", r"create2",
                r"new\s+\w*Proxy|Clones\.clone"),
      forbid=(r"initialize\s*\(", r"init\s*\("),
      detail="Clone initial-state leak: the factory deploys "
             "EIP-1167 minimal-proxy clones WITHOUT calling "
             "initialize in the same transaction, so every "
             "clone sits uninitialized - with its initial "
             "state (owner, config) up for grabs - until "
             "someone initializes it, and a watcher can "
             "front-run the legitimate initialization."),
    S("proxy_shadow_variable_override", FAMILY, severity="medium",
      outcome="a", custom="shadow_var",
      detail="Shadow variable override: the proxy and the "
             "implementation declare the same watched state "
             "variable (owner/admin/implementation/...), so "
             "both write the same storage slot through "
             "delegatecall - each side silently overwrites the "
             "other's value."),
    S("proxy_function_clashing", FAMILY, severity="medium",
      outcome="a", custom="function_clash",
      detail="Function selector clashing: a function name is "
             "defined on BOTH the proxy and the implementation. "
             "Calls hit the proxy's own version (or fall "
             "through) depending on routing the user cannot "
             "see, so the implementation's function of the same "
             "name is shadowed - the transparent-proxy clash "
             "class that admin/function separation exists to "
             "prevent."),
    S("proxy_deterministic_deployment_collision", FAMILY,
      severity="medium", outcome="a",
      fn_re=r"deploy|create",
      need_any=(r"create2", r"\{\s*salt\s*:"),
      forbid=(r"msg\.sender",),
      detail="Deterministic deployment collision: CREATE2 is "
             "used with a fully caller-supplied salt that is "
             "not bound to msg.sender (or any deployer-specific "
             "value), so anyone can pre-compute the deployment "
             "address, squat the deployment, or collide with a "
             "planned deployment of different code at the same "
             "address."),
    S("proxy_transparent_admin_misdirection", FAMILY,
      severity="medium", outcome="a",
      custom="transparent_fallback",
      detail="Transparent admin misdirection: the proxy's "
             "fallback delegatecalls EVERYTHING with no admin "
             "routing (no ifAdmin / admin-caller branch "
             "anywhere in the contract), so admin-function "
             "calls from ordinary users fall through to the "
             "implementation and calls from the admin can "
             "never reach the implementation's own functions "
             "predictably - the proxy is neither transparent "
             "nor admin-separated."),
]

register_family(globals(), SPECS)
