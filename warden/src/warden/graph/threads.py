"""Thread ids and checkpoint expiry.

A thread id is `<experiment>:<incident>`, so two experiments on the same Postgres never share
checkpointed state: re-running an experiment name resumes it (or reports it finished), and a new
experiment name starts clean. langgraph-checkpoint-postgres 3.2.0 has no TTL, so expiry is done
here: a thread is stale when its newest checkpoint is older than the TTL, and stale threads are
removed with the saver's own `delete_thread`.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

DEFAULT_TTL_HOURS = 6.0
_EXPERIMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")  # no ':' so the split is unambiguous
_INCIDENT = re.compile(r"^WRD-\d{4}$")


def thread_id(experiment: str, incident_id: str) -> str:
    if not _EXPERIMENT.match(experiment or ""):
        raise ValueError("experiment must match %s (no ':'), got %r" % (_EXPERIMENT.pattern, experiment))
    if not _INCIDENT.match(incident_id or ""):
        raise ValueError("bad incident id %r" % (incident_id,))
    return "%s:%s" % (experiment, incident_id)


def split_thread_id(tid: str) -> tuple:
    experiment, _, incident = tid.partition(":")
    return experiment, incident


def stale_threads(conn, ttl_hours: float = DEFAULT_TTL_HOURS, now: Optional[datetime] = None,
                  experiment: Optional[str] = None) -> list:
    """Thread ids whose newest checkpoint is older than the TTL. `conn` is a psycopg connection.
    With `experiment`, only that experiment's threads are considered."""
    if ttl_hours <= 0:
        raise ValueError("ttl_hours must be positive")
    cutoff = (now or datetime.now(timezone.utc)) - timedelta(hours=ttl_hours)
    sql = ("SELECT thread_id FROM checkpoints "
           "{where} GROUP BY thread_id "
           "HAVING max((checkpoint->>'ts')::timestamptz) < %s ORDER BY thread_id")
    params: list = []
    where = ""
    if experiment:
        where = "WHERE thread_id LIKE %s"
        params.append(experiment.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + ":%")
    params.append(cutoff)
    return [r[0] for r in conn.execute(sql.format(where=where), params).fetchall()]


def purge_stale(saver, conn, ttl_hours: float = DEFAULT_TTL_HOURS, now: Optional[datetime] = None,
                experiment: Optional[str] = None) -> list:
    """Delete every stale thread (checkpoints, blobs and writes). Returns the deleted ids.
    A thread paused at the gate counts as stale too: an approval nobody gave in the TTL window
    is dropped, which is the intent."""
    ids = stale_threads(conn, ttl_hours, now, experiment)
    for tid in ids:
        saver.delete_thread(tid)
    return ids
