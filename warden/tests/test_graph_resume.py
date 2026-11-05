"""Kill/resume against a real Postgres checkpointer. Skips when Postgres is not reachable.

    docker compose up -d --wait postgres

The worker runs in a separate process and is killed with TerminateProcess (what `taskkill /F`
does). The ledger file the worker appends to survives the kill and records what really executed.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import uuid

import pytest

pytest.importorskip("langgraph.checkpoint.postgres")
psycopg = pytest.importorskip("psycopg")

DSN = os.environ.get("WARDEN_PG_DSN", "postgresql://warden:warden@127.0.0.1:5433/warden")
WORKER = os.path.join("scripts", "graph_killtest_worker.py")
CALL_COST = (1000 * 1 + 200 * 5) / 1_000_000  # Haiku 4.5 at the fixed worker usage


def _pg_up() -> bool:
    try:
        psycopg.connect(DSN, connect_timeout=3).close()
        return True
    except Exception:
        return False


pytestmark = pytest.mark.skipif(not _pg_up(), reason="Postgres not reachable (docker compose up -d postgres)")


@pytest.fixture
def thread(tmp_path):
    tid = "killtest-%s" % uuid.uuid4().hex[:8]
    yield tid, str(tmp_path / "ledger.jsonl")
    from langgraph.checkpoint.postgres import PostgresSaver
    with PostgresSaver.from_conn_string(DSN) as saver:
        saver.delete_thread(tid)


def spawn(tid, ledger, **opts):
    cmd = [sys.executable, WORKER, "--thread", tid, "--ledger", ledger]
    for k, v in opts.items():
        cmd += ["--" + k.replace("_", "-"), str(v)]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)


def events(ledger):
    if not os.path.exists(ledger):
        return []
    with open(ledger, encoding="utf-8") as fh:
        return [json.loads(line)["ev"] for line in fh if line.strip()]


def wait_for(ledger, pred, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        if pred(events(ledger)):
            return
        time.sleep(0.05)
    raise AssertionError("ledger never reached the kill point: %s" % events(ledger))


def finish(tid, ledger, **opts):
    p = spawn(tid, ledger, **opts)
    out, err = p.communicate(timeout=120)
    assert p.returncode == 0, err[-2000:]
    return json.loads(out.strip().splitlines()[-1])


def test_kill_between_nodes_resumes_without_rerunning_investigate(thread):
    tid, ledger = thread
    p = spawn(tid, ledger, verify_delay=30)
    wait_for(ledger, lambda e: "verify_enter" in e)  # investigate has been checkpointed
    p.kill()
    p.wait(timeout=10)
    assert p.returncode != 0

    res = finish(tid, ledger)
    ev = events(ledger)
    assert "resume:verify" in ev
    assert ev.count("model") == 3, "investigate re-ran after resume: %s" % ev
    assert [e for e in ev if e.startswith("tool:")] == [
        "tool:describe_principal", "tool:get_events", "tool:submit_verdict"]
    assert res["report"]["status"] == "verified"
    assert res["observations"] == 3 and res["verify_attempts"] == 1
    assert res["cost_usd"] == pytest.approx(3 * CALL_COST)


def test_kill_inside_investigate_replays_that_node_only(thread):
    """A node is atomic: killed mid-investigate, nothing from it was checkpointed, so it re-runs
    from its start. State must not double up; the wasted calls are measured, not hidden."""
    tid, ledger = thread
    p = spawn(tid, ledger, model_delay=1.5)
    wait_for(ledger, lambda e: e.count("model") >= 2)
    p.kill()
    p.wait(timeout=10)
    killed_calls = events(ledger).count("model")
    assert killed_calls in (2, 3)

    res = finish(tid, ledger)
    ev = events(ledger)
    assert "resume:investigate" in ev
    assert res["report"]["status"] == "verified"
    assert res["observations"] == 3, "observations duplicated across the kill"
    assert res["verify_attempts"] == 1
    assert res["cost_usd"] == pytest.approx(3 * CALL_COST), "state counts the killed attempt's spend"
    # What really ran: the killed attempt's calls plus a full replay. That waste is the price of
    # node-level checkpointing; it is bounded by one investigate attempt.
    assert ev.count("model") == killed_calls + 3


def test_finished_thread_is_not_rerun(thread):
    tid, ledger = thread
    finish(tid, ledger)
    before = events(ledger)
    res = finish(tid, ledger)
    assert events(ledger)[len(before):] == ["already_done"]
    assert res["report"]["status"] == "verified"
