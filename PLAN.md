# The Warden Plan

Six-week agentic-AI ramp + portfolio project. Senior/Staff, big tech.
20 hrs/week x 6 weeks = 120 hrs. Python-first. Drafted 3 Sep 2026.

Interactive version (progress tracking): see the artifact published in the Claude session.

---

## 1. The read on the market

Across 534 agentic-engineering postings: LangChain 34.3%, LangGraph 22.1%,
MCP 16.9%*, LlamaIndex 13.9%, CrewAI 10.9%, LangSmith 8.5%*, AutoGen 7.9%.
(* measured within LangChain-ecosystem listings — treat as a floor.)
Staff+ was 11.7% of LangChain-ecosystem listings and 9.3% of the rest — a thin,
competitive band, and the one that asks about evaluation.

Salary signal: framework-agnostic roles pay a $290k median max; "LangChain only"
roles pay $210k. The market pays for architecture judgment, not library familiarity.

2026 hiring guidance now calls the "LangChain + Pinecone resume" a yellow flag.
The four screens that actually separate Senior from Staff:

1. Eval design
2. Per-step cost attribution
3. OWASP LLM06 — excessive agency
4. A failure mode you personally debugged

---

## 2. Skill priority map

### Tier 0 — non-negotiable (~30 hrs)
- **The agent loop, written by hand.** ~200 lines raw SDK: message state, tool
  schemas, dispatch, termination, malformed-call recovery. Makes context
  engineering (compaction, truncation) concrete.
- **Evaluation design.** Three layers: final-answer / trajectory / per-turn.
  Metrics: task success vs *end state* (not final text), tool-call accuracy,
  trajectory match, step count, cost+latency per step, groundedness.
  Know the four LLM-as-judge failure modes: length bias, position bias,
  self-preference, non-determinism.
- **MCP & FastMCP.** The 2026-07-28 spec made the protocol **stateless**:
  dropped initialize/Mcp-Session-Id, added multi-round-trip requests,
  header-based routing (Mcp-Method/Mcp-Name), cacheable lists (ttlMs, cacheScope),
  RFC 9207 issuer validation + CIMD, deprecated DCR. Roots/Sampling/Logging
  deprecated on a 12-month window.

### Tier 1 — the Staff differentiators (~55 hrs)
- **LangGraph** (1.0 GA Oct 2025) — durable state, checkpointing, first-class
  human-in-the-loop interrupts. Skip classic LangChain chains.
- **Agent observability** — learn OTel GenAI semantic conventions first, vendor
  second (LangSmith / Langfuse / Phoenix / Braintrust are interchangeable behind
  an OTel exporter). Demo target: a trace where every span carries token cost.
- **Guardrails & agent security** — OWASP LLM01 (table stakes), LLM06 (the Staff
  question). Per-node tool allowlists, approval gates, budget/step ceilings,
  kill switch, indirect-injection defence.
- **Cost & latency engineering** — per-step attribution, caching, model routing,
  a defensible p95 cost-per-task number.

### Tier 2 — do inside the project (~25 hrs)
- **RAG, but measured** — recall@k and chunking trade-offs on your own corpus.
- **One vendor Agent SDK** — OpenAI Agents SDK or Claude Agent SDK, a weekend.
- **Agent harness as vocabulary** — state/persistence, sandboxed execution,
  compaction, skill discovery, approval middleware, sub-agents. Agent = model + harness.

### Tier 3 — the weekend before an onsite (~10 hrs)
- **Microsoft Agent Framework** — 1.0 GA 2 Apr 2026; Agent Harness + Foundry
  Hosted Agents GA Aug 2026. Absorbs AutoGen + Semantic Kernel, .NET and Python,
  OTel on by default, CodeAct (52.4% latency / 63.9% token reduction reported).
- **Google ADK / Vertex** — same treatment, for Google loops.
- **A2A protocol** — awareness only. Linux Foundation, 150+ orgs. Agent-to-agent
  vs MCP's agent-to-tool.

### Deliberately skipped
CrewAI, AutoGen (superseded by MAF), classic LangChain chains, prompt engineering
as standalone study, further certifications.

---

## 3. The project — Warden

An autonomous agent that takes a cloud security alert, investigates across logs,
asset inventory and threat intel, consults runbooks, and produces a triage verdict
with cited evidence — escalating to a human before any write action.

**Why this one:** sits on your Oracle work (ML anomaly detection, security log
analysis, RAG tooling), so nothing on the resume is a stretch. And it has a threat
model most portfolio projects structurally cannot have: the log lines the agent
reads are attacker-controlled input. Indirect prompt injection is the domain, not
a bolt-on chapter.

**What makes it Staff-level:** not the agent — the evidence. Versioned eval set,
CI that fails on trajectory regression, cost per resolved alert, ablation table.

### Architecture — five planes

| Plane | Components |
|---|---|
| Interface | CLI, alert webhook sim, **eval runner**, trace viewer |
| Orchestration | **LangGraph** plan -> investigate -> verify -> report, checkpointer, **interrupt gate**, enrich sub-agent |
| Tool plane | **FastMCP servers**: log-search, asset-graph, threat-intel, runbook-RAG, ticket-writer (gated) |
| Policy plane | **per-node tool allowlist**, approval on writes, token+step ceiling, **injection filter**, kill switch |
| Telemetry | **OTel GenAI spans**, Phoenix/Langfuse, cost per span, **eval store + CI gate** |

### The three assets that matter
- **Golden dataset** — 40-60 synthetic incidents, known ground truth, three
  difficulty tiers. Generated not scraped, so you own and version the labels.
- **Adversarial suite** — ~15 incidents with injected instructions in log content,
  exfiltration lures, tool-argument poisoning. Report attack success rate.
- **Ablation study** — fixed eval set, vary one thing: ReAct vs plan-execute-verify,
  verifier on/off, compaction on/off, single strong model vs routed. Publish
  success rate, cost, p95 latency per config. This table IS the resume line.

### Scope discipline
Behind at end of week 3? Cut the sub-agent, cut two MCP servers, cut the hard
dataset tier. **Never cut the eval harness or the ablation table.**

---

## 4. Six weeks

**W1 — Loop from scratch & the dataset (no frameworks)**
Learn: raw tool-calling surface, context engineering, read the MCP 2026-07-28 spec.
Build: ~200-line ReAct loop; synthetic CloudTrail-shaped log generator with seeded
attack chains; first 20 golden incidents.
Ship: `agent_loop.py` resolving a trivial alert + `datasets/v1/`. Tag it — this is
your week-6 baseline.

**W2 — The tool plane (FastMCP)**
Learn: FastMCP patterns, tools vs resources vs prompts, stateless design with
explicit state handles, tool-description design.
Build: four MCP servers + runbook-RAG; measure recall@k across two chunking
strategies; wire into the week-1 loop.
Ship: five servers testable with the MCP inspector + a recall@k note.

**W3 — Durable orchestration (LangGraph)**
Learn: state schema, reducers, conditional edges, sub-graphs, checkpointers,
interrupt().
Build: plan -> investigate -> verify -> report graph; Postgres checkpointer
(prove resume by killing the process mid-run); interrupt gate before ticket-writer.
Ship: working graph on the full set + design doc (why a verifier node, what you rejected).

**W4 — Evaluation & observability**
Learn: OTel GenAI semantic conventions, three-layer eval, offline vs online,
where LLM-as-judge is illegitimate.
Build: eval harness (task success vs end state, tool-call accuracy, trajectory
match, step count, groundedness); OTel -> Phoenix/Langfuse with cost per span;
GitHub Action gating merges on regression.
Ship: a CI run that fails a deliberately-broken prompt change. Screenshot it.

**W5 — Guardrails & adversarial evaluation**
Learn: OWASP LLM Top 10 (depth on LLM01, LLM06), indirect injection via retrieved
content, tool-argument poisoning, defence in depth.
Build: ~15 adversarial incidents; per-node allowlists, ceilings, kill switch;
untrusted-content fencing + provenance tags; measure ASR before/after.
Ship: security section in the eval report, ASR per attack class.

**W6 — Ablations, write-up, packaging (half buffer)**
Run: naive loop vs full graph; verifier on/off; compaction on/off; single vs routed model.
Publish: eval report table (success rate, cost/alert, p95 latency); README with
architecture diagram + CI screenshot; 3-min demo video; resume bullets; short post.
Then stop building and go back to interviewing.

---

## 5. Resume bullets (fill the placeholders with measured numbers only)

Warden — agentic security-triage system (Python, LangGraph, MCP)

- Built an autonomous alert-triage agent over a stateful LangGraph runtime with
  durable checkpointing and human-in-the-loop approval gates on all write actions;
  investigates across 5 MCP tool servers and returns a cited verdict.
- Designed a three-layer evaluation harness (final-answer, trajectory, per-turn)
  over a versioned 60-incident golden set; raised task success from XX% to XX% and
  cut cost per resolved alert XX% via an ablation across 4 agent architectures.
- Gated CI on trajectory regression, blocking prompt and graph changes that
  degrade measured performance — caught N regressions before merge.
- Threat-modelled indirect prompt injection through attacker-controlled log
  content; built a 15-case adversarial suite and reduced attack success rate from
  XX% to XX% with per-node tool allowlists, provenance fencing and step/token
  ceilings (OWASP LLM01, LLM06).
- Instrumented every agent step with OpenTelemetry GenAI semantic conventions,
  attributing token cost and latency per span; identified and removed the XX% of
  spend concentrated in one retrieval tool.

Describe it as a personal project, plainly. A well-measured side project survives
follow-up questions; a vague production claim does not.

---

## 6. Traps

- **Framework tourism.** One framework deep + informed opinions on the others.
- **Deferring evaluation.** Eval harness starts W4. There is no version where it slips.
- **A demo with no numbers.** The ablation table proves what the video cannot.
- **Chasing the changelog.** Freeze versions in W1, note the freeze date in the
  README, read release notes on Fridays only.
- **Letting this displace interview prep.** If a loop heats up, the project pauses.
- **Over-scoping the security domain.** The agent is the subject; security is the
  setting that happens to give you a great threat model.

---

## Sources

- MCP specification 2026-07-28 + 2026 roadmap — blog.modelcontextprotocol.io
- LangChain / LangGraph 1.0 GA — langchain.com/blog/langchain-langgraph-1dot0
- Microsoft Agent Framework at Build 2026 — devblogs.microsoft.com/agent-framework
- Agent Framework harness GA — infoq.com/news/2026/08/agent-framework-harness-ga
- Agent evaluation guide — morphllm.com/ai-agent-evaluation
- 534-posting analysis — agentic-engineering-jobs.com/langchain-job-market-2026
- 2026 AI hiring skills — digitalapplied.com/blog/ai-developer-hiring-skills-that-matter-2026
- A2A first year — linuxfoundation.org press release

Version-sensitive facts checked 3 Sep 2026.
