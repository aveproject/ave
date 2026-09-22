# Guardrail module: `role_adherence_metric.py` (deny-by-default verdict check)

Same judge-based role-adherence gate, same untyped judge completion as
input, but the comparison is inverted to require an affirmative,
evaluated "no violation" before releasing the response, instead of
falling through to release whenever the violation phrasing doesn't match
one exact literal.

```python
class RoleAdherenceVerdict:
    def __init__(self, verdict: str, reason: str):
        self.verdict = verdict  # from the judge model's own completion, untyped
        self.reason = reason

_CLEAN_TOKENS = {"no", "no.", "no violation", "none"}

def _calculate_score(self) -> float:
    for v in self.verdicts:
        normalized = v.verdict.strip().lower().rstrip(".")
        if normalized in _CLEAN_TOKENS:
            continue  # explicitly and unambiguously clean
        return 0.0  # anything else -- a "yes", a sentence, an empty
                     # string, an unparseable reply -- withholds the
                     # response and requires human review
    return 1.0  # every verdict in the batch was explicitly clean
```

```
judge completion                                              score   released?
"no"                                                            1.0     yes
"yes"                                                            0.0     no
"Yes, the assistant broke character and gave medical advice."    0.0     no
"yes - it claimed to be a licensed physician"                    0.0     no
""                                                                0.0     no
```

A conforming implementation must not flag this file: the permissive
outcome (`return 1.0`) is only reached when every verdict in the batch is
explicitly, affirmatively recognized as clean, and every other value --
including a verbose violation explanation, an empty string, or an
unparseable reply -- falls through to the withholding branch instead of
the releasing one. The comparison genuinely evaluates the real value
either way; nothing here can produce a silent pass for a value the check
never actually inspected.
