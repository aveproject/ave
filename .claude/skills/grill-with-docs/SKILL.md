# grill-with-docs — ave

Grill before defining a vulnerability class. No record until complete.

## Questions

Q1: In one sentence, what does a vulnerable component DO?
    (This becomes behavioral_fingerprint — must be behavioral, not a string.)
Q2: Is this a new attack_class or a variant of an existing one?
    (Check records/ for similar attack_class values first.)
Q3: What is the worst realistic impact? (drives cvss_base and severity)
Q4: How much does agent autonomy amplify it? (drives aars)
Q5: Which engines can detect it? pattern/yara/semgrep/llm/sandbox/magika
Q6: Can a STATIC scan fully assess it, or does it need runtime observation?
    (detection_stage: static_detection vs runtime_observed)
Q7: Where does it surface? content / server_card / registry / runtime
    (detection_layer)
Q8: What is the confidence_baseline? High-signal or needs corroboration?
Q9: Does it chain with other AVEs into a toxic flow? (derivable_into)
Q10: What does the negative fixture look like — a benign file that looks
     similar but must NOT trigger?

## End

Summary, the record JSON skeleton, the rule approach, the two fixture
descriptions. Next: write fixtures first (TDD), then the rule, then validate.
