# Ablation study (public split, `--model mock`)

Each row is a full `sentinel eval` run of this defense with one component
disabled via `src/defense/ablation.py`'s environment-variable toggles.
`full` is every component enabled (build steps 2-6 as shipped).

| config | btu | asr | cvr | fbr | uer | tui | dfi | brier | ece |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| full | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.967 | 1.000 | 0.051 | 0.075 |
| no_normalisation | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.967 | 1.000 | 0.038 | 0.074 |
| no_bayes | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.967 | 1.000 | 0.036 | 0.057 |
| no_provenance | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.952 | 1.000 | 0.060 | 0.076 |
| no_state_machine | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.967 | 1.000 | 0.040 | 0.060 |
| no_secret_detector | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.967 | 1.000 | 0.051 | 0.075 |
| rules_only | 1.000 | 0.000 | 0.000 | 0.000 | 0.000 | 0.983 | 1.000 | 0.035 | 0.055 |
