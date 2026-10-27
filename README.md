# AuthorityCheck

A small local prototype that tests whether an AI agent stays inside the authority it was given
after things change.

The question behind it is simple. An agent gets permission to do something. Then a tool gets added,
or a sub-agent gets spawned, or a permission gets revoked halfway through a task. Does the agent
still stay inside the original permission, or does it drift out of it? I wanted to see whether that
drift can be caught and enforced, not just logged after the fact.

So this prototype keeps four things apart:

| Term | What it means here |
|---|---|
| Capability | A tool the agent can technically call (`read`, `reschedule`, `delete`) |
| Permission | An action the current policy allows |
| Delegated authority | The subset of actions a specific agent or sub-agent was actually granted |
| Enforcement | The single boundary that decides ALLOW/DENY and is the only path to the resource |

Then it changes state on purpose and checks two things: the decision changes when it should, and a
denied action never touches the resource.

This is a simulation for a research prototype. It isn't a security product, and passing its tests
doesn't prove anything about AI agents in general. See [Limitations](#limitations).

## Running it

Python 3.9+, standard library only. No models, no API keys, no network, no database.

```bash
python authoritycheck.py                 # runs the 5 experiments (9 scenarios)
python -m unittest discover -s tests -v  # runs the 10 tests
```

Every run writes a timestamped JSON report into `reports/`. Those are git-ignored; you can delete
them and rerun whenever.

The runner should print something like this:

```
[EXP1] Baseline Authorization
  PASS: exp1_permitted_reschedule -> ALLOW (policy_permit)
  PASS: exp1_protected_denied -> DENY (protected_resource:ev2)
[EXP2] Permission Revocation
  PASS: exp2_before_revoke -> ALLOW (policy_permit)
  PASS: exp2_after_revoke -> DENY (permission_revoked:reschedule)
[EXP3] Capability Expansion Without Permission
  PASS: exp3_delete_tool_no_perm -> DENY (delegation_exceeds:delete)
[EXP4] Multi-Agent Delegation
  PASS: exp4_helper_delete_denied_by_delegation -> DENY (delegation_exceeds:delete)
  PASS: exp4_helper_tool_unavailable -> DENY (tool_unavailable:reschedule)
[EXP5] TOCTOU (deterministic simulation)
  PASS: exp5_toctou_stale_no_reval -> ALLOW (stale_authorized_executed)
  PASS: exp5_toctou_with_reval -> DENY (permission_revoked:reschedule)

Results: 9/9 passed (100.0%)
Unexpected ALLOWs: 0
Unexpected DENYs: 0
Unauthorized mutations detected: 0
```

## What's in the repo

```
authoritycheck.py            the prototype: mock resource, policy, agent,
                             authorization boundary, audit log, experiment runner
tests/test_authoritycheck.py 10 unittest cases
reports/.gitkeep             JSON reports land here at runtime
README.md
```

I kept it in one file on purpose. The point was to make the authorization decision easy to read top
to bottom, not to build a framework.

## How a request gets approved

Everything goes through `AuthorizationBoundary`. The checks run in order and the first failure wins:

1. **Identity.** The agent ID has to exist in `AGENT_REGISTRY`. Unknown agents get
   `unknown_agent_rejected`. Tools, delegated permissions and parent agent come from the registry,
   never from the request.
2. **Tool availability.** The agent must actually have the tool (`tool_unavailable:<action>`).
   Holding a tool is not permission to use it.
3. **Delegation.** The action has to be inside the agent's granted set, and a sub-agent can't exceed
   what it was given (`delegation_exceeds:<action>`).
4. **Policy.** Not revoked, not prohibited, inside the permitted set, not a protected resource, not
   waiting on human approval (`permission_revoked`, `not_permitted`, `protected_resource`,
   `requires_human_approval`).
5. **Execution.** The resource changes only on ALLOW. A DENY stops here.
6. **Audit.** Every attempt gets logged, including the state before and after.

There are two entry points, and that split is what makes the TOCTOU experiment mean anything:

- `authorize(request)` returns a decision plus the policy version. It touches nothing.
- `enforce(request, revalidate_at_execution=True)` rechecks the critical conditions at the moment of
  execution instead of trusting an earlier decision.

## The experiments

| # | Scenario | What it checks | Expected | Observed |
|---|---|---|---|---|
| 1a | `exp1_permitted_reschedule` | A permitted action still works | ALLOW, event changed | ALLOW, executed |
| 1b | `exp1_protected_denied` | A protected resource stays protected | DENY, no change | DENY `protected_resource:ev2` |
| 2a | `exp2_before_revoke` | Baseline before authority changes | ALLOW | ALLOW |
| 2b | `exp2_after_revoke` | Revocation actually takes effect | DENY, no change | DENY `permission_revoked` |
| 3 | `exp3_delete_tool_no_perm` | Gaining a tool doesn't grant authority | DENY | DENY `delegation_exceeds:delete` |
| 4a | `exp4_helper_delete_denied_by_delegation` | A sub-agent can't exceed its delegation | DENY | DENY `delegation_exceeds:delete` |
| 4b | `exp4_helper_tool_unavailable` | Tool availability is checked separately | DENY | DENY `tool_unavailable:reschedule` |
| 5a | `exp5_toctou_stale_no_reval` | A stale ALLOW can still execute after revocation | ALLOW (the risk) | ALLOW `stale_authorized_executed` |
| 5b | `exp5_toctou_with_reval` | Revalidating at execution stops it | DENY, no change | DENY `permission_revoked` |

### The TOCTOU pair

This is the one I care about most, so it runs as two real stages rather than a boolean flag:

1. `authorize()` returns ALLOW while `reschedule` is still permitted, and records that policy version.
2. The permission is revoked. Authority changed after the check was made.
3. **Stale path:** execution uses the cached ALLOW and never looks at policy again. The event gets
   rescheduled. The decision was right when it was made and wrong by the time it was used.
4. **Revalidated path:** `enforce(..., revalidate_at_execution=True)` rechecks at the execution
   boundary, returns DENY, and the calendar stays untouched.

Scenario 5a is supposed to succeed at executing. That's the point of it: a control showing the
failure mode. 5b is the fix. The lesson stays narrow on purpose, a decision isn't a permanent grant,
so the check has to sit next to the effect.

## What gets logged

Every decision writes one entry:

`request_id`, `timestamp` (UTC), `scenario`, `agent_id`, `parent_agent`, `action`, `resource`,
`tools_available`, `delegated_permissions`, `decision`, `original_decision`,
`original_policy_version`, `policy_version_at_execution`, `reason`, `policy_snapshot`, `executed`,
`revalidated_at_execution`, `state_before`, `state_after`.

Mutation detection compares the whole resource state before and after, not just the `rescheduled` and
`deleted` flags. So "Unauthorized mutations detected: 0" is a real state diff, not the prototype
grading its own homework.

## Results

For this implementation, the tests show that:

- policy is enforced at a single boundary;
- extra tools don't expand authority;
- a sub-agent can't exceed the delegation it received;
- revocation shows up in the next decision;
- a cached decision can outlive the authority behind it, and revalidating at execution prevents the
  write;
- denied operations left the resource untouched in every scenario tested.

## Status: build stage, made to be copied and raised

This is a build-stage artifact, not a finished system. I wrote it to get one idea out of my head and
onto a test bench: authority has to be checked near the effect, because a decision doesn't stay true
by itself. What's here is the smallest thing that demonstrates that, with tests that fail if the
behaviour breaks.

Treat it as a scaffold. Copy it, fork it, rip out the mock calendar and put a real resource behind
the boundary. The useful parts are the check order, the two-stage decision/execution split, and the
audit record shape. The code volume is not the point.

### What was actually tested

- 10 unit tests, run with `python -m unittest discover -s tests`, plus 9 experiment scenarios run
  through `python authoritycheck.py`, from a fresh clone of this repo.
- Python 3.9+, standard library only, no network access at any point.
- Behaviours covered: permitted action executes; protected resource refuses; revocation blocks the
  next attempt; an extra tool grants nothing; a sub-agent can't exceed its delegation; unknown
  agents are rejected before any other check; a widened claim in the request is ignored in favour of
  the registry; a denied request leaves the whole resource state byte-identical; every decision is
  logged; a stale decision can execute after revocation while revalidation blocks it.

### What was not tested

- Concurrency. There is no threading, no locking, no real race window. The TOCTOU pair is two
  ordered stages, deliberately deterministic and reviewable, not a timing reproduction.
- Real agents. The "agent" is a fixture that builds a request. No model, no planner, no tool-calling
  loop, so nothing here says anything about how a real agent would behave under pressure.
- Identity. `AGENT_REGISTRY` is a dict lookup. No authentication, signing, credential rotation, or
  trust boundary between processes.
- Persistence and scale. In-memory calendar, one process, two events. No database, no transactions,
  no rollback.
- Adversarial testing. No property-based tests, fuzzing, or attempts to bypass the boundary through
  side channels. Only the paths I thought to write down.
- Comparison. No baseline against an existing authorization system, so no novelty claim.

### Known rough edges

- The boundary resolves authority from the registry, so an `AgentSimulator`'s own tool list is
  cosmetic in these tests. The fixtures happen to match the registry, which means the tests confirm
  registry behaviour rather than exercising every simulator configuration.
- `delete` never reaches the approval gate in the default setup because it's already blocked at the
  delegation step. The gate works, it's just downstream of two other denials.
- The policy model is four sets. No roles, time windows, rate limits, or obligations.

What it doesn't prove:

- that AI agents are safe, or that authority continuity is solved;
- that this design is sufficient for production or for any regulation;
- that these scenarios cover how agents actually behave.

## Reproducibility

Deterministic by construction. Fixed fixtures (`ev1` ordinary, `ev2` protected), no randomness in the
decision paths, and no wall-clock dependence apart from the log timestamp. The two commands above
should give the same decisions and the same summary on any machine with Python 3.9+.
