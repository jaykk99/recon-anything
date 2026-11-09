"""Deep-scanner throughput fixes: RPC host-health fast-skip, durable
checkpoints under disk pressure, and the single-batch lock.

These address a continuous scan crawling (557s/contract vs ~132s normal):
dead RPC hosts waited on every call, overlapping batches rescanning the
same contract, and checkpoints lost when the disk quota fills so finished
work is redone. Detection logic and the plugin set are untouched.
"""
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# --- 1) RPC host-health fast-skip ---------------------------------------
def test_rpc_order_skips_dead_hosts():
    import app.plugins.contract_chain as cc
    cc._RPC_DEAD_UNTIL.clear()
    urls = ["http://dead", "http://good"]
    cc._rpc_mark_dead("http://dead")
    order = cc._rpc_order(urls)
    assert order[0] == "http://good", "healthy endpoint must be tried first"
    assert "http://dead" in order, "dead host kept as last-resort fallback"
    cc._rpc_mark_alive("http://dead")
    assert "http://dead" not in cc._RPC_DEAD_UNTIL


def test_rpc_all_dead_still_tries_everything():
    import app.plugins.contract_chain as cc
    cc._RPC_DEAD_UNTIL.clear()
    urls = ["http://a", "http://b"]
    cc._rpc_mark_dead("http://a")
    cc._rpc_mark_dead("http://b")
    # even when all are cooling, none are permanently dropped
    assert set(cc._rpc_order(urls)) == set(urls)


# --- 2) Durable checkpoints under disk pressure -------------------------
def _store():
    import app.checkpoints as ckpt
    d = tempfile.mkdtemp()
    return ckpt, ckpt.CheckpointStore(os.path.join(d, "cp.db"))


def test_oversized_result_still_records_done():
    ckpt, st = _store()
    k = ckpt.unit_key("0xabc", "deepscan", {})
    st.begin(k, "0xabc", "deepscan", {})
    big = {"status": "ok", "reason": "r", "findings": ["x" * 100] * 3000}
    st.complete(k, big)
    assert st.is_done(k), "a done unit must never be lost to result size"


def test_lease_blocks_concurrent_rescan():
    ckpt, st = _store()
    k = ckpt.unit_key("0xdef", "deepscan", {})
    assert st.begin(k, "0xdef", "deepscan", {}) is True
    # second worker sees a fresh running lease and must skip
    assert st.begin(k, "0xdef", "deepscan", {}) is False


def test_degraded_store_never_crashes():
    import app.checkpoints as ckpt
    st = ckpt.CheckpointStore.__new__(ckpt.CheckpointStore)
    st.path = "/nonexistent/dir/cannot/create.db"
    import threading
    st._lock = threading.Lock()
    st._mem_done = set()
    st._degraded = True
    st._writes = 0
    k = "k1"
    assert st.begin(k, "t", "m", {}) is True   # runs despite dead disk
    st.complete(k, {"status": "ok"})
    assert st.is_done(k)                        # held in memory
    st.fail("k2", "err")                        # must not raise


# --- 3) Single-batch lock -----------------------------------------------
def test_single_batch_lock_blocks_second():
    import app.batch_scan as bs
    p = os.path.join(tempfile.mkdtemp(), "batch.lock")
    with bs.single_batch_lock(p):
        try:
            with bs.single_batch_lock(p):
                assert False, "second batch should not acquire the lock"
        except bs.BatchAlreadyRunning:
            pass
    # released after the block - a later batch can acquire again
    with bs.single_batch_lock(p):
        pass
