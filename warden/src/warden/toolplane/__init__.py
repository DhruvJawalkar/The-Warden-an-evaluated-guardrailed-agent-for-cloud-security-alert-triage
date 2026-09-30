"""Week-2 tool plane: FastMCP servers over stdio, plus the client that adapts them to the loop.

Servers are stateless (2026-07-28 posture): every call carries every id it needs, and nothing
is remembered between calls. The only per-process state is a read-only cache of the dataset.
"""
