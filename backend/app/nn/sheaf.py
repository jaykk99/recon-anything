"""Sheaf theory + hypergraph signal processing for ReconAnything triage.

A hyperedge is ONE multi-entity event, not a flattened row: a multi-sig
transaction, a shared deployer plus shared commit history plus a DNS
change, an owner transition (contract + old owner + new owner + block +
time), or all the findings on one contract. A pairwise graph can only
say "A relates to B"; a hyperedge says "these N things happened
together", which is the level the cover story of a target lives at.

A sheaf attaches a local data space (a "stalk") to every entity in a
hyperedge: each entity carries its own local facts (owner, code hash,
findings, timestamps) together with the source each fact came from.
A restriction map takes one entity's local data and projects it onto
the shared overlap the hyperedge claims (e.g. "the owner of this
contract at this block", "the token identity this symbol names").
Local sections glue into a global section when every restriction
agrees on every overlap. When they do not agree, the disagreement is
a hole in the target's cover story: the owner says X on-chain but the
implementation says Y, timestamps are inconsistent with the claimed
deploy order, the same owner returns after a renounce that should
have been final.

What a "hole" means operationally: two or more local facts that
cannot all be true at once, with the exact facts named. A hole is
never proof of a vulnerability and never a VERIFIED_REAL verdict.
It is a triage signal: this target's story does not add up, so a
human (or the investigator loop) should look here before trusting
any single finding on it. Detection only, read-only, triage only.

Cohomology, honestly: this module does Cech-style consistency
checking (local sections, restriction maps, gluing obstructions),
not a computation of sheaf cohomology groups. The obstructions it
returns play the role of a first cohomology class: they are the
precise residue that stops local data from gluing. Nothing here
pretends to be H^1 computed over a simplicial complex; if a later
module wants real cohomology it can build it on top of the
restriction maps defined here.

Pure Python stdlib, zero new dependencies, runs on CPU.

Hypergraph-NN integration: the hypergraph-NN branch
(feat/nn-hypergraph, ~/workspace/wt/nn-hypergraph) had no module
written when this was built (checked 2026-11-14), so this module
defines its own hyperedge primitives. The interchange shape is
``to_hypergraph_nn``: every hyperedge serialises to a plain dict
{id, kind, nodes, features, score} that a hypergraph network can
consume as one hyperedge with a consistency feature. When the
hypergraph-NN module lands, the merge point is: import its
Hyperedge type in ``hyperedges.py`` and replace the local
construction, keeping the check registry and restriction maps here.
See backend/docs/nn-sheaf.md.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Sequence, Tuple

# An entity is (kind, key). Keys are strings so hyperedges serialise
# to JSON for the hypergraph-NN interchange. A null/unknown value is
# the literal key "null" -- never a Python None in a key, so that two
# unknowns never silently merge with a real address.
Entity = Tuple[str, str]

NULL_KEY = "null"


def entity_contract(chain: str, address: str) -> Entity:
    return ("contract", "%s:%s" % ((chain or "").lower(),
                                   (address or "").lower()))


def entity_owner(address: Optional[str]) -> Entity:
    if not address:
        return ("owner", NULL_KEY)
    return ("owner", address.lower())


def entity_symbol(symbol: Optional[str]) -> Entity:
    if not symbol:
        return ("symbol", NULL_KEY)
    return ("symbol", str(symbol))


def entity_finding(chain: str, address: str, plugin: str,
                   key: str) -> Entity:
    return ("finding", "%s:%s:%s:%s" % ((chain or "").lower(),
                                        (address or "").lower(),
                                        plugin or "", key or ""))


@dataclass(frozen=True)
class Fact:
    """One local fact: a field, its value, and where it came from.

    The source is what makes an inconsistency actionable: the
    disagreement names the two rows that contradict each other,
    e.g. "transition_events.jsonl#7" vs "transition_events.jsonl#9".
    """
    entity: Entity
    field: str
    value: object
    source: str

    def describe(self) -> str:
        return "%s.%s = %r (%s)" % (
            "%s:%s" % self.entity, self.field, self.value, self.source)


@dataclass
class Stalk:
    """The local data space attached to one entity in a hyperedge."""
    entity: Entity
    facts: Dict[str, Fact] = field(default_factory=dict)

    def get(self, field_name: str, default=None):
        fact = self.facts.get(field_name)
        return default if fact is None else fact.value

    def fact(self, field_name: str) -> Optional[Fact]:
        return self.facts.get(field_name)


@dataclass
class Hyperedge:
    """One multi-entity event with a stalk on every entity."""
    id: str
    kind: str
    entities: FrozenSet[Entity]
    stalks: Dict[Entity, Stalk] = field(default_factory=dict)
    meta: Dict[str, object] = field(default_factory=dict)

    def stalk(self, entity: Entity) -> Optional[Stalk]:
        return self.stalks.get(entity)

    def facts_about(self, field_name: str) -> List[Fact]:
        out = []
        for stalk in self.stalks.values():
            fact = stalk.fact(field_name)
            if fact is not None:
                out.append(fact)
        return out


@dataclass
class CheckResult:
    """One consistency check over a hyperedge."""
    name: str
    passed: bool
    weight: float  # 0 = observation only, reported, never affects score
    detail: str
    facts: List[Fact] = field(default_factory=list)
    multi_entity: bool = False  # needs >=3 entities / cross-edge context


# ---------------------------------------------------------------------------
# Restriction maps
# ---------------------------------------------------------------------------
# A restriction map projects one entity's stalk onto the shared overlap
# the hyperedge claims. Restriction maps are the whole game: a check is
# just "restrict every entity to the overlap and compare".
#
# Overlaps, per hyperedge kind:
#   owner_transition: "owner@after"  -- who owns the contract after
#   finding_cluster:  "target"       -- which (chain, address, function)
#   symbol_cluster:   "token-identity" -- which symbol, owned by whom
#   owner_cluster:    "control"      -- who controls these contracts
#   call_path:        "hop-gate"     -- gated? paused? sourced?

def restrict(edge: Hyperedge, entity: Entity,
             overlap: str) -> Tuple[object, Optional[Fact]]:
    """Restrict one entity's stalk to an overlap. Returns (value, fact).

    Unknown values restrict to None, which means "this entity says
    nothing about the overlap" -- unknown is never treated as a
    disagreement with a known value. Only two known, different values
    disagree.
    """
    stalk = edge.stalk(entity)
    if stalk is None:
        return None, None
    if edge.kind == "owner_transition" and overlap == "owner@after":
        if entity[0] == "contract":
            return stalk.get("owner_after"), stalk.fact("owner_after")
        if entity[0] == "owner":
            # Only the after-owner says anything about "owner after".
            # The before-owner restricts to unknown: it makes no
            # claim about who owns the contract now.
            if stalk.get("role") == "current_owner":
                return entity[1], Fact(
                    entity, "owns", entity[1],
                    stalk.fact("role").source
                    if stalk.fact("role") else edge.id)
            return None, None
        return None, None
    if edge.kind == "finding_cluster" and overlap == "target":
        if entity[0] == "finding":
            return (stalk.get("chain"), stalk.get("address"),
                    stalk.get("function")), stalk.fact("function")
        if entity[0] == "contract":
            return (stalk.get("chain"), stalk.get("address"),
                    None), stalk.fact("address")
        return None, None
    if edge.kind == "symbol_cluster" and overlap == "token-identity":
        if entity[0] == "contract":
            return (stalk.get("symbol"), stalk.get("owner")), \
                stalk.fact("owner")
        if entity[0] == "symbol":
            return (entity[1], None), None
        return None, None
    if edge.kind == "owner_cluster" and overlap == "control":
        if entity[0] == "contract":
            return stalk.get("owner"), stalk.fact("owner")
        if entity[0] == "owner":
            return entity[1], None
        return None, None
    if edge.kind == "call_path" and overlap == "hop-gate":
        if entity[0] == "contract":
            return (stalk.get("function"), stalk.get("gated"),
                    stalk.get("paused")), stalk.fact("gated")
        return None, None
    return None, None


def restrict_all(edge: Hyperedge, overlap: str) -> Dict[Entity, object]:
    """Every entity's restriction to one overlap (unknowns dropped)."""
    out = {}
    for entity in edge.entities:
        value, _fact = restrict(edge, entity, overlap)
        if value is not None:
            out[entity] = value
    return out


# ---------------------------------------------------------------------------
# Consistency checks
# ---------------------------------------------------------------------------
# Each check is a function Hyperedge -> CheckResult. weight 0 means
# observation-only: real data gaps (a missing block, an unreadable
# owner, no verified source) are reported, never scored as
# contradictions. A check fails only when two known facts disagree,
# or one known fact contradicts the hyperedge's own claim.

def _check_noop_transition(edge: Hyperedge) -> CheckResult:
    stalk = edge.stalk(next(e for e in edge.entities
                            if e[0] == "contract"))
    before = stalk.fact("owner_before")
    after = stalk.fact("owner_after")
    passed = before.value != after.value
    return CheckResult(
        name="transition_changes_owner",
        passed=passed,
        weight=2.0,
        detail=("owner changes %r -> %r" % (before.value, after.value)
                if passed else
                "transition records no owner change: %r -> %r"
                % (before.value, after.value)),
        facts=[before, after],
        multi_entity=False)


def _check_null_owner_observed(edge: Hyperedge) -> CheckResult:
    """A null owner read is an observation, not a contradiction.

    One null flip alone proves nothing: the watcher records null
    when owner() cannot be read, which also happens on a real
    renounce. The contradiction only appears at sequence level
    (A -> null -> A), which check_cover catches. So weight 0.
    """
    stalk = edge.stalk(next(e for e in edge.entities
                            if e[0] == "contract"))
    after = stalk.fact("owner_after")
    return CheckResult(
        name="owner_after_null_observed",
        passed=after.value is not None,
        weight=0.0,
        detail=("owner reads null after this transition; single null "
                "is unresolved, not a contradiction (see cover check)"
                if after.value is None else "owner after is known"),
        facts=[after],
        multi_entity=False)


def _check_block_present(edge: Hyperedge) -> CheckResult:
    stalk = edge.stalk(next(e for e in edge.entities
                            if e[0] == "contract"))
    block = stalk.fact("block")
    return CheckResult(
        name="block_present",
        passed=block.value is not None,
        weight=0.0,
        detail=("block number missing for this transition; ordering "
                "against siblings cannot be verified"
                if block.value is None else "block present"),
        facts=[block],
        multi_entity=False)


def _check_target_binds(edge: Hyperedge) -> CheckResult:
    """The validator must bind the same target the finding names.

    A finding says (chain, address, function, kind); the validator's
    own record must carry the same chain/address/kind. If it does
    not, the validation is about a different target than the finding.
    """
    facts = []
    bad = []
    for entity in sorted(edge.entities):
        if entity[0] != "finding":
            continue
        stalk = edge.stalk(entity)
        v_chain = stalk.get("validation_chain")
        v_addr = stalk.get("validation_address")
        v_kind = stalk.get("validation_kind")
        chain = stalk.get("chain")
        addr = stalk.get("address")
        kind = stalk.get("key")
        for field, got, want in (
                ("validation_chain", v_chain, chain),
                ("validation_address", v_addr, addr),
                ("validation_kind", v_kind, kind)):
            fact = stalk.fact(field)
            if fact is not None:
                facts.append(fact)
            if got is not None and want is not None and \
                    str(got).lower() != str(want).lower():
                bad.append((field, got, want))
    return CheckResult(
        name="validation_binds_same_target",
        passed=not bad,
        weight=2.0,
        detail=("validator binds the same target on every finding"
                if not bad else
                "validator target disagrees with finding: %s"
                % (bad,)),
        facts=facts,
        multi_entity=False)


def _check_function_bound(edge: Hyperedge) -> CheckResult:
    """A finding that names a function the validator leaves blank.

    The finding's local story names e.g. withdraw; the validator's
    function field is empty, so the validation never engaged with
    the function the finding is about.
    """
    facts = []
    bad = []
    for entity in sorted(edge.entities):
        if entity[0] != "finding":
            continue
        stalk = edge.stalk(entity)
        fn = stalk.get("function")
        v_fn = stalk.get("validation_function")
        if fn:
            facts.append(stalk.fact("function"))
            if v_fn is not None and v_fn == "":
                bad.append((entity, fn))
    return CheckResult(
        name="validation_binds_function",
        passed=not bad,
        weight=1.0,
        detail=("validator binds the function on every finding"
                if not bad else
                "validator leaves the function blank on %d finding(s)"
                % len(bad)),
        facts=facts,
        multi_entity=False)


def _check_verified_real_needs_live(edge: Hyperedge) -> CheckResult:
    """VERIFIED_REAL with a failed live probe contradicts itself.

    A verified-real verdict is a claim about the live chain. If the
    live probe failed (transport_error), there is no live evidence
    behind the verdict.
    """
    facts = []
    bad = []
    for entity in sorted(edge.entities):
        if entity[0] != "finding":
            continue
        stalk = edge.stalk(entity)
        if stalk.get("verdict") == "VERIFIED_REAL":
            facts.append(stalk.fact("verdict"))
            facts.append(stalk.fact("live_status"))
            if stalk.get("live_status") != "success":
                bad.append(entity)
    return CheckResult(
        name="verified_real_needs_live_probe",
        passed=not bad,
        weight=2.0,
        detail=("no VERIFIED_REAL verdict rests on a failed probe"
                if not bad else
                "VERIFIED_REAL on %d finding(s) with live probe != "
                "success" % len(bad)),
        facts=facts,
        multi_entity=False)


def _check_ungrounded_severity(edge: Hyperedge) -> CheckResult:
    """High severity with no evidence at all: observation, not proof.

    483 of 727 real candidates are high severity with empty
    evidence, a failed probe and no verified source. That is a
    property of this data (the Token Hub row is the exemplar), not
    a per-target contradiction, so weight 0: reported, never scored.
    """
    facts = []
    count = 0
    total = 0
    for entity in sorted(edge.entities):
        if entity[0] != "finding":
            continue
        total += 1
        stalk = edge.stalk(entity)
        if (stalk.get("severity") == "high"
                and not stalk.get("evidence_keys")
                and stalk.get("live_status") == "transport_error"
                and stalk.get("source_missing")):
            count += 1
            facts.append(stalk.fact("severity"))
    return CheckResult(
        name="ungrounded_severity_observed",
        passed=count == 0,
        weight=0.0,
        detail=("%d/%d findings claim high severity with empty "
                "evidence, failed probe and no verified source"
                % (count, total) if count else
                "no ungrounded high-severity findings"),
        facts=facts,
        multi_entity=False)


def _check_symbol_one_owner(edge: Hyperedge) -> CheckResult:
    """One token identity, one owner.

    Every contract in a symbol cluster restricts to (symbol, owner).
    Two known, different owners for the same symbol means the
    "same token" story does not glue. Unknown owners are not
    disagreements.
    """
    restricted = restrict_all(edge, "token-identity")
    owners = {}
    facts = []
    for entity, value in restricted.items():
        if entity[0] != "contract":
            continue
        _symbol, owner = value
        if owner is not None and owner != NULL_KEY:
            owners.setdefault(owner, []).append(entity)
            fact = edge.stalk(entity).fact("owner")
            if fact is not None:
                facts.append(fact)
    passed = len(owners) <= 1
    return CheckResult(
        name="symbol_one_owner",
        passed=passed,
        weight=2.0,
        detail=("all contracts in this symbol cluster agree on one "
                "owner" if passed else
                "symbol claimed by %d different owners: %s"
                % (len(owners), sorted(owners))),
        facts=facts,
        multi_entity=True)


def _check_owner_agrees_with_transitions(edge: Hyperedge) -> CheckResult:
    """Owner-cluster owner vs the transition record: needs 2 sources.

    With a single owner source this check is vacuous by construction
    (the cluster is built from that source) and always passes. It
    only bites when a second, independent owner feed is supplied in
    the contract stalks as "owner_independent". Documented, not
    hidden: a check that cannot fail on one source says so.
    """
    facts = []
    bad = []
    for entity in sorted(edge.entities):
        if entity[0] != "contract":
            continue
        stalk = edge.stalk(entity)
        owner = stalk.get("owner")
        other = stalk.get("owner_independent")
        if owner and other and owner != other:
            bad.append((entity, owner, other))
            facts.append(stalk.fact("owner"))
            facts.append(stalk.fact("owner_independent"))
    return CheckResult(
        name="owner_agrees_with_independent_feed",
        passed=not bad,
        weight=2.0,
        detail=("no independent owner feed disagrees"
                if not bad else
                "independent owner feed disagrees on %d contract(s)"
                % len(bad)),
        facts=facts,
        multi_entity=True)


def _check_call_path_gates(edge: Hyperedge) -> CheckResult:
    """A gated hop into an ungated sink must name the bypass.

    The path's finding kinds must include the gate-bypass kind when
    the hop sequence goes gated -> ungated -> value sink. If the
    path claims the route but never names the bypass, the story is
    missing its own central claim.
    """
    hops = edge.meta.get("hops") or []
    kinds = set(edge.meta.get("finding_kinds") or [])
    gated_then_ungated = False
    for i in range(len(hops) - 1):
        if hops[i].get("gated") and not hops[i + 1].get("gated"):
            gated_then_ungated = True
    facts = []
    contract = next((e for e in edge.entities if e[0] == "contract"),
                    None)
    if contract is not None:
        fact = edge.stalk(contract).fact("gated")
        if fact is not None:
            facts.append(fact)
    passed = (not gated_then_ungated
              or "call_graph_gate_bypass_multihop" in kinds)
    return CheckResult(
        name="call_path_names_gate_bypass",
        passed=passed,
        weight=2.0,
        detail=("path names its gate bypass"
                if passed else
                "gated hop leads to ungated hop but no "
                "call_graph_gate_bypass_multihop finding names it"),
        facts=facts,
        multi_entity=True)


def _check_call_path_paused(edge: Hyperedge) -> CheckResult:
    """A paused middle hop cannot support a candidate-grade path.

    PR #178: paused=true at a middle hop downgrades the path to
    trigger-only. A path presented as candidate while a hop is
    paused contradicts its own grading.
    """
    hops = edge.meta.get("hops") or []
    grade = edge.meta.get("grade")
    paused = [h for h in hops if h.get("paused")]
    facts = []
    for entity in sorted(edge.entities):
        if entity[0] != "contract":
            continue
        fact = edge.stalk(entity).fact("paused")
        if fact is not None and fact.value:
            facts.append(fact)
    passed = not (paused and grade == "candidate")
    return CheckResult(
        name="call_path_paused_not_candidate",
        passed=passed,
        weight=2.0,
        detail=("no paused hop on a candidate-grade path"
                if passed else
                "%d paused hop(s) on a path graded candidate"
                % len(paused)),
        facts=facts,
        multi_entity=True)


def _check_call_path_sourced(edge: Hyperedge) -> CheckResult:
    """A hop without source must be marked degraded, never firm.

    PR #178: a missing middle-hop source degrades the edge. A path
    that presents an unsourced hop as a firm edge over-claims.
    """
    hops = edge.meta.get("hops") or []
    degraded = set(edge.meta.get("degraded_hops") or [])
    bad = []
    for i, hop in enumerate(hops):
        if not hop.get("source_available") and i not in degraded:
            bad.append(i)
    return CheckResult(
        name="call_path_unsourced_hop_degraded",
        passed=not bad,
        weight=1.0,
        detail=("every unsourced hop is marked degraded"
                if not bad else
                "hop(s) %s lack source but are presented as firm"
                % (bad,)),
        facts=[],
        multi_entity=True)


# kind -> checks, in evaluation order.
CHECKS = {
    "owner_transition": [
        _check_noop_transition,
        _check_null_owner_observed,
        _check_block_present,
    ],
    "finding_cluster": [
        _check_target_binds,
        _check_function_bound,
        _check_verified_real_needs_live,
        _check_ungrounded_severity,
    ],
    "symbol_cluster": [_check_symbol_one_owner],
    "owner_cluster": [_check_owner_agrees_with_transitions],
    "call_path": [
        _check_call_path_gates,
        _check_call_path_paused,
        _check_call_path_sourced,
    ],
}

# The overlap each kind's checks restrict onto. Kept explicit so a
# later real-cohomology module can read it off instead of guessing.
OVERLAPS = {
    "owner_transition": "owner@after",
    "finding_cluster": "target",
    "symbol_cluster": "token-identity",
    "owner_cluster": "control",
    "call_path": "hop-gate",
}


# ---------------------------------------------------------------------------
# Consistency score, cover checks, ranking
# ---------------------------------------------------------------------------

def consistency(edge: Hyperedge, pairwise: bool = False):
    """Score one hyperedge. Returns (score, [CheckResult]).

    score = weighted fraction of passing checks (weight > 0 only).
    1.0 means every scored check passed. Weight-0 observations are
    reported in the results but never move the score.

    pairwise=True runs the pairwise-graph baseline: multi-entity
    checks are skipped, so only facts visible from one hyperedge at
    a time can fail. The gap between pairwise and full mode is
    exactly what hyperedges add.
    """
    results = []
    for check in CHECKS.get(edge.kind, []):
        result = check(edge)
        if pairwise and result.multi_entity:
            continue
        results.append(result)
    total = sum(r.weight for r in results)
    if total <= 0:
        return 1.0, results
    passed = sum(r.weight for r in results if r.passed)
    return passed / total, results


@dataclass
class Obstruction:
    """A gluing obstruction: local sections that cannot glue.

    This is the residue that stops a cover from having a global
    section -- the operational analogue of a first cohomology
    class. Each one names the exact facts that disagree.
    """
    kind: str
    contract: Entity
    detail: str
    facts: List[Fact] = field(default_factory=list)


def check_cover(contract: Entity, edges: Sequence[Hyperedge]):
    """Check the cover of one contract across all its hyperedges.

    A single transition hyperedge is always self-consistent (one
    owner flips once). The story only breaks across the cover: the
    time-ordered owner timeline for the contract must chain, blocks
    must not go backwards, and an owner that left via null must not
    silently return. These are the checks a pairwise graph cannot
    run, because no single edge holds the sequence.
    """
    transitions = []
    for edge in edges:
        if edge.kind != "owner_transition":
            continue
        stalk = edge.stalk(contract)
        if stalk is None:
            continue
        transitions.append((stalk.get("detected_at"),
                            stalk.get("block"), edge, stalk))
    transitions.sort(key=lambda t: (str(t[0] or ""),))
    obstructions: List[Obstruction] = []
    if len(transitions) < 2:
        return obstructions

    # s1: null-flip oscillation A -> null -> A. A renounced owner
    # cannot return; the same address coming back after a null read
    # is a read glitch, not a transfer.
    owners = [s.get("owner_after") for _t, _b, _e, s in transitions]
    for i in range(1, len(owners) - 1):
        if (owners[i] is None and owners[i - 1] is not None
                and owners[i - 1] == owners[i + 1]):
            facts = [transitions[i - 1][3].fact("owner_after"),
                     transitions[i][3].fact("owner_after"),
                     transitions[i + 1][3].fact("owner_after")]
            obstructions.append(Obstruction(
                kind="owner_null_flip_oscillation",
                contract=contract,
                detail=("owner %s -> null -> %s: same owner returns "
                        "after a null read; a renounced owner cannot "
                        "return, so this is a read glitch, not a "
                        "transfer" % (owners[i - 1], owners[i + 1])),
                facts=[f for f in facts if f is not None]))

    # s2: block monotonicity. Blocks must not decrease as time moves
    # forward; a decrease means the rows disagree about order.
    prev_block = None
    for _t, block, edge, stalk in transitions:
        if block is None or prev_block is None:
            if block is not None and prev_block is None:
                prev_block = block
            continue
        if block < prev_block:
            obstructions.append(Obstruction(
                kind="block_order_reversal",
                contract=contract,
                detail=("block decreases %s -> %s while detected_at "
                        "moves forward" % (prev_block, block)),
                facts=[f for f in (stalk.fact("block"),)
                       if f is not None]))
            break
        prev_block = block

    # s3: owner continuity. Each row's after-owner must be the next
    # row's before-owner (nulls aside, already covered by s1). A
    # break means a transition is missing or a read disagrees.
    for (_t1, _b1, _e1, s1), (_t2, _b2, _e2, s2) in zip(
            transitions, transitions[1:]):
        after = s1.get("owner_after")
        before = s2.get("owner_before")
        if after is not None and before is not None and after != before:
            obstructions.append(Obstruction(
                kind="owner_continuity_break",
                contract=contract,
                detail=("owner timeline breaks: %r -> %r with no "
                        "transition between them" % (after, before)),
                facts=[f for f in (s1.fact("owner_after"),
                                   s2.fact("owner_before"))
                       if f is not None]))
    return obstructions


def rank_inconsistencies(edges: Sequence[Hyperedge],
                         pairwise: bool = False):
    """Ranked list of inconsistencies, most severe first.

    Each entry names the hyperedge, the failed check, its score,
    and the exact local facts that disagree. Cover obstructions
    (which span hyperedges) come first: they are the holes no
    single hyperedge can see.
    """
    ranked = []
    for edge in edges:
        score, results = consistency(edge, pairwise=pairwise)
        if score >= 1.0:
            continue
        for result in results:
            if result.passed or result.weight <= 0:
                continue
            ranked.append({
                "hyperedge_id": edge.id,
                "kind": edge.kind,
                "score": round(score, 4),
                "check": result.name,
                "weight": result.weight,
                "detail": result.detail,
                "facts": [f.describe() for f in result.facts],
            })
    ranked.sort(key=lambda r: (r["score"], -r["weight"]))
    return ranked


def cover_obstructions(edges: Sequence[Hyperedge]):
    """All gluing obstructions across every covered contract."""
    by_contract: Dict[Entity, List[Hyperedge]] = {}
    for edge in edges:
        for entity in edge.entities:
            if entity[0] == "contract":
                by_contract.setdefault(entity, []).append(edge)
    out = []
    for contract in sorted(by_contract):
        for obs in check_cover(contract, by_contract[contract]):
            out.append({
                "hyperedge_id": "cover:%s:%s" % contract,
                "kind": "cover/" + obs.kind,
                "score": 0.0,
                "check": obs.kind,
                "weight": 2.0,
                "detail": obs.detail,
                "facts": [f.describe() for f in obs.facts],
            })
    return out


# ---------------------------------------------------------------------------
# Interchange with the hypergraph-NN branch
# ---------------------------------------------------------------------------

def to_hypergraph_nn(edge: Hyperedge, pairwise: bool = False):
    """Serialise one hyperedge for the hypergraph-NN branch.

    Shape (the agreed interchange; see docs/nn-sheaf.md):
        {"id", "kind", "nodes": [entity keys], "features": {...},
         "score": consistency}
    nodes are "kind:key" strings; features are plain JSON values the
    network can read as one hyperedge-level feature vector. The
    hypergraph-NN module (feat/nn-hypergraph) consumes this dict
    directly; it does not need to import this module.
    """
    score, results = consistency(edge, pairwise=pairwise)
    failed = [r.name for r in results
              if not r.passed and r.weight > 0]
    observed = [r.name for r in results
                if not r.passed and r.weight == 0]
    return {
        "id": edge.id,
        "kind": edge.kind,
        "nodes": ["%s:%s" % e for e in sorted(edge.entities)],
        "features": {
            "n_entities": len(edge.entities),
            "consistency": round(score, 4),
            "n_failed_checks": len(failed),
            "failed_checks": failed,
            "observations": observed,
        },
        "score": round(score, 4),
    }


def copy_hyperedge(edge: Hyperedge) -> Hyperedge:
    """Deep copy of a hyperedge (stalks and facts), for eval injection."""
    stalks = {}
    for entity, stalk in edge.stalks.items():
        facts = {name: Fact(f.entity, f.field, f.value, f.source)
                 for name, f in stalk.facts.items()}
        stalks[entity] = Stalk(entity, facts)
    return Hyperedge(id=edge.id, kind=edge.kind,
                     entities=frozenset(edge.entities),
                     stalks=stalks, meta=dict(edge.meta))
