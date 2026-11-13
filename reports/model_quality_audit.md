# Preserved model quality audit

The model is a research artifact and must not determine definitive verdicts alone.

Model SHA-256: `dd0075c1d6bc715da1f0fac7dcb4f20d4e6ef912646ec72a751adf48eefcf987`

[Source label documentation](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset)

| Source class | Rows | Empty path | Root slash | www prefix |
| --- | ---: | ---: | ---: | ---: |
| phishing | 100945 | 40.1387% | 32.6623% | 41.3532% |
| legitimate | 134850 | 100.0% | 0.0% | 100.0% |

Train/test domain overlap: **2789** domains.

Fixed sample seed: 42. Model score threshold: 0.85.

| Diagnostic | Rows | Flagged phishing | Mean model score |
| --- | ---: | ---: | ---: |
| legitimate_original | 2000 | 0 | 0.004866 |
| legitimate_root_slash | 2000 | 1786 | 0.932731 |
| phishing_original | 2000 | 1987 | 0.993817 |
| phishing_root_slash_removed | 2000 | 1978 | 0.988686 |

- These are diagnostics of the preserved split, not independent deployment accuracy estimates.
- All legitimate source examples share www and empty-path formatting, allowing a spurious shortcut.
- Removing root slashes can reduce false positives while also hiding genuine phishing examples; it is not a general accuracy fix.
- Independent, representative legitimate hosts and paths and current phishing examples are needed before deployment validation.
