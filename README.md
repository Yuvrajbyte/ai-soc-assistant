## Detection: raw alerts vs. correlated incidents

A naive threshold rule (5+ failed logins from one IP within 60 seconds)
correctly identifies brute-force activity with zero false positives on
our test data, but produces far more alerts than real incidents. Our
first SSH brute-force run against the lab generated 40 raw threshold
alerts from what was, in reality, 2 separate attack sessions.

This happens because a sustained attack repeatedly crosses the
threshold as it continues: each new burst of 5 failures within any
60-second window counts as a fresh alert, even though it's the same
attacker, uninterrupted, still trying the same account. In a real SOC,
this is exactly the kind of noise that causes alert fatigue, where
analysts start ignoring or de-prioritizing alerts because there are
too many of them.

We addressed this with a correlation step: alerts from the same source
IP are merged into a single incident if the gap between one alert
ending and the next starting is under 30 seconds. After correlation,
the 40 raw alerts collapsed into 2 incidents, matching the two actual
Hydra runs recorded in our lab's ground-truth log
(`lab/attack_log.csv`).

This mirrors a real limitation of rule-based detection: simple
thresholds are easy to implement and explain, but need a correlation
or deduplication layer to be genuinely usable at analyst scale. It's
also the architectural reason SIEM tools (Splunk, Elastic Security,
Microsoft Sentinel) have dedicated "incident" or "case" layers sitting
on top of raw rule hits, rather than surfacing every rule match as its
own independent alert.

**Tradeoff we accepted:** our 30-second merge window is a heuristic,
not a tuned parameter. A shorter window risks splitting one real
attack into multiple incidents again; a longer window risks merging
two genuinely separate attacks (e.g. two different actors) into one.
We plan to revisit this once we have ML-based anomaly scores to
cross-validate against.