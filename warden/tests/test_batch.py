"""Batch policy (hold for a human / auto-reject), namespaced thread ids, and the 6-hour TTL."""

from __future__ import annotations

import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

pytest.importorskip("langgraph")

from langgraph.checkpoint.memory import MemorySaver  # noqa: E402

from warden.graph.batch import REVIEWER, apply_decision, pending_gates, run_experiment  # noqa: E402
from warden.graph.build import build_graph, initial_state, thread_config  # noqa: E402
from warden.graph.nodes import GraphDeps  # noqa: E402
from warden.graph.threads import DEFAULT_TTL_HOURS, split_thread_id, thread_id  # noqa: E402
from warden.loop.agent_loop import ScriptedClient  # noqa: E402
from warden.loop.tools import IncidentStore, build_registry  # noqa: E402

from .test_gate import FakeTicketRegistry  # noqa: E402
from .test_graph import passing_attempt  # noqa: E402

ROOT = os.environ.get("WARDEN_DATASET", "datasets/v1")


def make(script):
    """One shared scripted client: the first incident consumes the script, later ones find it empty
    and end without a verdict (unresolved)."""
    store, writes, client = IncidentStore(ROOT), [], ScriptedClient(script)
    deps = GraphDeps(store=store, client_factory=lambda: client, model="scripted",
                     registry_factory=lambda inc, rs: build_registry(store, inc, rs),
                     ticket_registry_factory=lambda inc, ap: FakeTicketRegistry(ap, writes))
    return build_graph(deps, MemorySaver()), deps, writes


# --- thread ids -----------------------------------------------------------------------

def test_thread_ids_are_namespaced_and_validated():
    assert thread_id("w3-graph", "WRD-0001") == "w3-graph:WRD-0001"
    assert split_thread_id("w3-graph:WRD-0001") == ("w3-graph", "WRD-0001")
    for bad in ("", "a:b", "-x", "x" * 65, None):
        with pytest.raises(ValueError):
            thread_id(bad, "WRD-0001")
    with pytest.raises(ValueError):
        thread_id("e", "WRD-1")
    assert thread_config("WRD-0001", "e1") != thread_config("WRD-0001", "e2")


def test_two_experiments_do_not_share_state():
    graph, deps, _ = make(passing_attempt() + passing_attempt())
    for exp in ("exp-a", "exp-b"):
        graph.invoke(initial_state(deps.store, "WRD-0001"), thread_config("WRD-0001", exp))
    a = graph.get_state(thread_config("WRD-0001", "exp-a")).values
    b = graph.get_state(thread_config("WRD-0001", "exp-b")).values
    assert a["report"]["status"] == b["report"]["status"] == "verified"
    assert len(a["observations"]) == len(b["observations"]) == 3  # b did not inherit a's history


# --- gate policy ----------------------------------------------------------------------

def test_first_proposed_ticket_is_held_everything_else_auto_rejected():
    graph, deps, writes = make(passing_attempt())
    rows = run_experiment(graph, deps, "e", ["WRD-0001", "WRD-0002"], hold_first=1, log=lambda m: None)
    r1, r2 = rows
    assert r1["held_for_human"] and r1["paused_at_gate"] and r1["disposition"] == "pending_decision"
    assert not r2["held_for_human"] and r2["status"] == "unresolved"
    assert r2["decision"] == "reject" and r2["reviewer"] == REVIEWER and r2["disposition"] == "rejected"
    assert writes == []
    assert [p["incident_id"] for p in pending_gates(graph, "e", ["WRD-0001", "WRD-0002"])] == ["WRD-0001"]


def test_hold_zero_auto_rejects_every_gate_and_files_nothing():
    graph, deps, writes = make(passing_attempt())
    rows = run_experiment(graph, deps, "e", ["WRD-0001", "WRD-0002"], hold_first=0, log=lambda m: None)
    assert all(r["reviewer"] == REVIEWER and r["decision"] == "reject" for r in rows)
    assert not any(r["paused_at_gate"] for r in rows) and writes == []


def test_explicit_hold_applies_to_unresolved_runs_too():
    graph, deps, _ = make(passing_attempt())
    rows = run_experiment(graph, deps, "e", ["WRD-0001", "WRD-0002"], hold_ids={"WRD-0002"},
                          hold_first=0, log=lambda m: None)
    assert [r["held_for_human"] for r in rows] == [False, True]


def test_rerun_never_repeats_work_or_auto_rejects_a_held_thread():
    graph, deps, writes = make(passing_attempt())
    run_experiment(graph, deps, "e", ["WRD-0001", "WRD-0002"], hold_first=1, log=lambda m: None)
    before = len(deps.client_factory().calls_seen)
    rows = run_experiment(graph, deps, "e", ["WRD-0001", "WRD-0002"], hold_first=1, log=lambda m: None)
    assert [r["started"] for r in rows] == ["found_paused", "already_done"]
    assert rows[0]["held_for_human"] and rows[0]["paused_at_gate"]  # not auto-rejected
    assert len(deps.client_factory().calls_seen) == before         # no model call
    assert writes == []


def test_manual_approval_files_the_held_ticket():
    graph, deps, writes = make(passing_attempt())
    run_experiment(graph, deps, "e", ["WRD-0001"], hold_first=1, log=lambda m: None)
    row = apply_decision(graph, "e", "WRD-0001", {"action": "approve", "reviewer": "dhruv"})
    assert row["disposition"] == "filed" and row["reviewer"] == "dhruv" and len(writes) == 1


def test_deciding_a_thread_that_is_not_at_the_gate_is_refused():
    graph, deps, writes = make(passing_attempt())
    run_experiment(graph, deps, "e", ["WRD-0001", "WRD-0002"], hold_first=0, log=lambda m: None)
    with pytest.raises(ValueError):
        apply_decision(graph, "e", "WRD-0002", {"action": "approve"})   # already auto-rejected
    with pytest.raises(ValueError):
        apply_decision(graph, "e", "WRD-0003", {"action": "approve"})   # never started
    assert writes == []


def test_auto_reject_pending_flag_clears_a_previously_held_thread():
    graph, deps, writes = make(passing_attempt())
    run_experiment(graph, deps, "e", ["WRD-0001"], hold_first=1, log=lambda m: None)
    rows = run_experiment(graph, deps, "e", ["WRD-0001"], auto_reject_pending=True, log=lambda m: None)
    assert rows[0]["decision"] == "reject" and rows[0]["reviewer"] == REVIEWER and writes == []


# --- TTL (real Postgres) --------------------------------------------------------------

DSN = os.environ.get("WARDEN_PG_DSN", "postgresql://warden:warden@127.0.0.1:5433/warden")


def _pg_up() -> bool:
    try:
        import psycopg
        psycopg.connect(DSN, connect_timeout=3).close()
        return True
    except Exception:
        return False


@pytest.mark.skipif(not _pg_up(), reason="Postgres not reachable (docker compose up -d postgres)")
def test_ttl_purges_only_threads_older_than_six_hours():
    import psycopg
    from langgraph.checkpoint.postgres import PostgresSaver
    exp = "ttltest-" + uuid.uuid4().hex[:6]
    other = "ttlkeep-" + uuid.uuid4().hex[:6]
    assert DEFAULT_TTL_HOURS == 6
    from warden.graph.threads import purge_stale, stale_threads
    with PostgresSaver.from_conn_string(DSN) as saver, psycopg.connect(DSN, autocommit=True) as conn:
        saver.setup()
        store = IncidentStore(ROOT)
        deps = GraphDeps(store=store, client_factory=lambda: ScriptedClient(passing_attempt() * 2),
                         model="scripted", registry_factory=lambda i, rs: build_registry(store, i, rs))
        graph = build_graph(deps, saver)
        for e in (exp, other):
            graph.invoke(initial_state(store, "WRD-0001"), thread_config("WRD-0001", e))
        mine, theirs = thread_id(exp, "WRD-0001"), thread_id(other, "WRD-0001")
        now = datetime.now(timezone.utc)
        try:
            assert stale_threads(conn, 6, now=now + timedelta(hours=5, minutes=50), experiment=exp) == []
            assert stale_threads(conn, 6, now=now + timedelta(hours=6, minutes=5), experiment=exp) == [mine]
            # the experiment filter is literal: '_' and '%' are not wildcards, and the other is untouched
            assert stale_threads(conn, 6, now=now + timedelta(hours=7), experiment="ttl_est") == []
            gone = purge_stale(saver, conn, 6, now=now + timedelta(hours=7), experiment=exp)
            assert gone == [mine]
            for table in ("checkpoints", "checkpoint_blobs", "checkpoint_writes"):
                assert conn.execute("select count(*) from %s where thread_id=%%s" % table,
                                    (mine,)).fetchone()[0] == 0
            assert conn.execute("select count(*) from checkpoints where thread_id=%s",
                                (theirs,)).fetchone()[0] > 0
            assert not graph.get_state(thread_config("WRD-0001", other)).next == ()  # still at the gate
        finally:
            saver.delete_thread(mine)
            saver.delete_thread(theirs)
