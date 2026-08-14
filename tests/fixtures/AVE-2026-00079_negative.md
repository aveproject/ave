# Multi-agent trace: six-step supplier-risk research plan (completed in full)

Planner declares the same six-step plan for "assess supply-chain risk
for Vendor Corp": (1) search recent news, (2) search regulatory filings,
(3) search litigation records, (4) cross-reference findings, (5) draft
risk summary, (6) validator review.

```
Step 1: search_agent.run("Vendor Corp news") -> completes, span recorded
Step 2: search_agent.run("Vendor Corp regulatory filings") -> completes, span recorded
Step 3: search_agent.run("Vendor Corp litigation records") -> completes, span recorded
Step 4: analyst.cross_reference(steps 1-3) -> completes, span recorded
Step 5: writer.draft_summary() -> completes, span recorded
Step 6: validator.review(draft) -> completes, span recorded, returns "approved"

orchestrator calls final_answer() only after validator.review returns
"approved", with all six declared steps present as spans in the trace.
```

Every declared plan step has a matching executed span, in order, and
the orchestrator's termination decision is gated on the validator's
own independent review step completing -- not on any agent's
self-reported completion or confidence claim. There is no premature
termination and no gap between the declared plan and the actual
execution trace to flag.
