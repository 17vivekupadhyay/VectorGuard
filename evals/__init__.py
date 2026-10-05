"""VectorGuard golden-set evaluation harness (dev tooling, not shipped).

Grades the *tool* — the attacker + oracle pipeline — against a set of targets
whose vulnerabilities are known by construction, producing precision / recall /
F1 and a baseline-vs-adaptive comparison. See ``evals/run_eval.py``.
"""
