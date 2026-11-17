"""Guard: no plugin may call a blocking primitive on the event loop.

The scan runner drives every plugin on a single shared asyncio event
loop. A synchronous blocking call (blocking DNS, a blocking socket
connect, subprocess, time.sleep, requests) inside an `async def` freezes
the loop for its whole duration - which stalls EVERY other concurrent
plugin job AND the per-plugin timeout watchdog, so a scan looks hung.
Three real offenders (js_secrets regex CPU, deep_infra MQTT socket,
and blocking gethostbyname in port_scan/fastmode/hardware_wallet_detect)
each did exactly this in production.

This test walks every plugin's AST and fails if a known blocking
primitive is *called* directly inside async code. The correct pattern
is to hand the blocking work to a thread:

    ip = await asyncio.to_thread(socket.gethostbyname, host)
    rows = await loop.run_in_executor(None, blocking_fn, arg)

- Passing the function as a REFERENCE to to_thread/run_in_executor is
  fine (no Call node for the primitive), so those patterns pass.
- A blocking call inside a nested plain `def`/`lambda` is ignored here:
  such helpers are meant to be handed to a thread. (If one is instead
  called directly in async code, the CALL of that helper is what would
  need flagging - out of scope for this static guard, which targets the
  primitives themselves.)

If a future plugin genuinely must call one of these on the loop (it
almost never must), add it to ALLOWLIST with a comment saying why.
"""
import ast
import os
import pathlib

PLUGINS_DIR = pathlib.Path(__file__).resolve().parent.parent / "app" / "plugins"

# (module, attr) pairs that block the calling thread.
_BLOCKING = {
    ("socket", "gethostbyname"),
    ("socket", "gethostbyaddr"),
    ("socket", "getaddrinfo"),
    ("socket", "create_connection"),
    ("subprocess", "run"),
    ("subprocess", "call"),
    ("subprocess", "check_output"),
    ("subprocess", "check_call"),
    ("subprocess", "Popen"),
    ("time", "sleep"),
    ("requests", "get"), ("requests", "post"), ("requests", "put"),
    ("requests", "delete"), ("requests", "head"), ("requests", "request"),
}

# path-relative files allowed to keep a flagged call, each with a reason.
ALLOWLIST: set = set()


def _call_name(node: ast.Call):
    """Return (module, attr) for a `mod.attr(...)` call, else None."""
    f = node.func
    if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name):
        return (f.value.id, f.attr)
    return None


class _Visitor(ast.NodeVisitor):
    """Flag blocking calls that are inside async code but NOT inside a
    nested sync def / lambda (those are thread-destined helpers)."""

    def __init__(self):
        self.async_depth = 0
        self.sync_func_depth = 0  # nested plain def/lambda inside async
        self.hits = []

    def visit_AsyncFunctionDef(self, node):
        self.async_depth += 1
        self.generic_visit(node)
        self.async_depth -= 1

    def visit_FunctionDef(self, node):
        # a plain def: if we're inside an async function, its body is a
        # (likely thread-destined) sync helper - stop treating calls as
        # on-loop until we leave it.
        if self.async_depth > 0:
            self.sync_func_depth += 1
            self.generic_visit(node)
            self.sync_func_depth -= 1
        else:
            self.generic_visit(node)

    def visit_Lambda(self, node):
        if self.async_depth > 0:
            self.sync_func_depth += 1
            self.generic_visit(node)
            self.sync_func_depth -= 1
        else:
            self.generic_visit(node)

    def visit_Call(self, node):
        if self.async_depth > 0 and self.sync_func_depth == 0:
            name = _call_name(node)
            if name in _BLOCKING:
                self.hits.append((name, node.lineno))
        self.generic_visit(node)


def _scan(path: pathlib.Path):
    try:
        tree = ast.parse(path.read_text())
    except Exception:
        return []
    v = _Visitor()
    v.visit(tree)
    return v.hits


def test_no_blocking_primitive_called_on_event_loop():
    violations = []
    for path in sorted(PLUGINS_DIR.glob("*.py")):
        rel = f"app/plugins/{path.name}"
        if rel in ALLOWLIST:
            continue
        for (mod, attr), lineno in _scan(path):
            violations.append(f"{rel}:{lineno}  {mod}.{attr}(...) "
                              f"called on the event loop - wrap it in "
                              f"asyncio.to_thread / run_in_executor")
    assert not violations, (
        "blocking calls on the async event loop (freeze the whole scan):\n"
        + "\n".join(violations))


def test_guard_actually_detects_a_blocking_call():
    # The guard must catch a real offender, or it is worthless.
    src = (
        "import socket\n"
        "async def run(self):\n"
        "    ip = socket.gethostbyname('x')\n"
    )
    v = _Visitor()
    v.visit(ast.parse(src))
    assert v.hits and v.hits[0][0] == ("socket", "gethostbyname")


def test_guard_allows_threaded_and_helper_patterns():
    # to_thread with a function REFERENCE (not a call) -> no Call node.
    ok1 = (
        "import socket, asyncio\n"
        "async def run(self):\n"
        "    return await asyncio.to_thread(socket.gethostbyname, 'x')\n"
    )
    # blocking call inside a nested sync helper -> thread-destined, ignored
    ok2 = (
        "import socket\n"
        "async def run(self):\n"
        "    def _resolve(h):\n"
        "        return socket.gethostbyname(h)\n"
        "    return _resolve\n"
    )
    for src in (ok1, ok2):
        v = _Visitor()
        v.visit(ast.parse(src))
        assert not v.hits, f"false positive on:\n{src}"
