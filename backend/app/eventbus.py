"""In-process async event bus for the discovery pipeline.

The Ctx discovery bus (plugins/base.py ctx.shared) is a set of
lists filled in phase 1 and read in phase 2: a consumer only sees
an asset after the producing phase finishes. This bus is the live
half of that design - producers publish an event the moment an
asset is discovered and every subscribed consumer coroutine
receives it immediately, in parallel, while the producing phase
is still running.

Topics (Jay's naming adopted alongside the originals):
- EVENT_TARGET_DISCOVERED  any discovered asset (generic)
- SUBDOMAIN_DISCOVERED     a new subdomain
- ENDPOINT_FOUND           a new endpoint
- FINDING_RECORDED         a finding was persisted

Wiring is deliberately minimal and safe: Ctx.publish() mirrors
each discovery onto the run's bus when one is attached
(runner._get_run_ctx attaches a fresh bus per run), and the job
runner's per-finding fan-out publishes through ctx.publish, so
FINDING_RECORDED rides the same path. Publishing is non-blocking
and never raises into a plugin: a slow consumer's full queue
drops events (counted on the bus) rather than stalling a scan.
"""
from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional

TOPIC_TARGET_DISCOVERED = "EVENT_TARGET_DISCOVERED"
TOPIC_SUBDOMAIN_DISCOVERED = "SUBDOMAIN_DISCOVERED"
TOPIC_ENDPOINT_FOUND = "ENDPOINT_FOUND"
TOPIC_FINDING_RECORDED = "FINDING_RECORDED"
WILDCARD = "*"

# Ctx.publish kind -> topics. Unlisted kinds emit the generic
# EVENT_TARGET_DISCOVERED only; "poc_findings" is the runner's
# per-finding publish, which is a finding, not a discovery.
_KIND_TOPICS: Dict[str, List[str]] = {
    "subdomains": [TOPIC_SUBDOMAIN_DISCOVERED, TOPIC_TARGET_DISCOVERED],
    "endpoints": [TOPIC_ENDPOINT_FOUND, TOPIC_TARGET_DISCOVERED],
    "poc_findings": [TOPIC_FINDING_RECORDED],
}


def topics_for_kind(kind: str) -> List[str]:
    return _KIND_TOPICS.get(kind, [TOPIC_TARGET_DISCOVERED])


class Subscription:
    """One consumer's view of a topic. Async-iterable: `async for
    event in sub` yields {"topic", "payload"} dicts until closed."""

    def __init__(self, bus: "EventBus", topic: str,
                 queue: "asyncio.Queue") -> None:
        self._bus = bus
        self.topic = topic
        self._queue = queue
        self._closed = False

    def __aiter__(self) -> "Subscription":
        return self

    async def __anext__(self) -> Dict[str, Any]:
        if self._closed:
            raise StopAsyncIteration
        item = await self._queue.get()
        if item is None:  # close sentinel
            raise StopAsyncIteration
        return item

    async def get(self) -> Dict[str, Any]:
        return await self.__anext__()

    def aclose(self) -> None:
        if not self._closed:
            self._closed = True
            self._bus._unsubscribe(self)

    async def __aenter__(self) -> "Subscription":
        return self

    async def __aexit__(self, *exc) -> None:
        self.aclose()


class EventBus:
    def __init__(self, maxsize: int = 1000) -> None:
        self._maxsize = maxsize
        self._subs: Dict[str, List[Subscription]] = {}
        self.dropped = 0  # events dropped on full consumer queues
        self.published = 0

    def subscribe(self, topic: str = WILDCARD) -> Subscription:
        sub = Subscription(self, topic, asyncio.Queue(maxsize=self._maxsize))
        self._subs.setdefault(topic, []).append(sub)
        return sub

    def _unsubscribe(self, sub: Subscription) -> None:
        subs = self._subs.get(sub.topic, [])
        if sub in subs:
            subs.remove(sub)
        try:
            sub._queue.put_nowait(None)
        except Exception:
            pass

    def subscriber_count(self, topic: Optional[str] = None) -> int:
        if topic is not None:
            return len(self._subs.get(topic, []))
        return sum(len(v) for v in self._subs.values())

    def publish_nowait(self, topic: str, payload: Any) -> int:
        """Fan out to subscribers of the topic and of '*'.
        Synchronous and non-raising by design: it is called from
        sync code (Ctx.publish) inside plugin execution."""
        self.published += 1
        event = {"topic": topic, "payload": payload}
        delivered = 0
        for t in (topic, WILDCARD):
            for sub in list(self._subs.get(t, [])):
                if sub._closed:
                    continue
                try:
                    sub._queue.put_nowait(event)
                    delivered += 1
                except asyncio.QueueFull:
                    self.dropped += 1
        return delivered

    async def publish(self, topic: str, payload: Any) -> int:
        return self.publish_nowait(topic, payload)
