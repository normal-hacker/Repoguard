# Health Scoring Engine

RepoGuard calculates a transparent, deterministic health score from **0 to 100** and assigns a letter grade (`A` to `F`).

---

## 1. Category Weights

| Category | Default Weight |
|---|:---:|
| **Security** | 25% |
| **Code Quality** | 25% |
| **Documentation** | 15% |
| **Dependencies** | 15% |
| **Testing** | 10% |
| **CI/CD** | 10% |

Weights can be adjusted in `.repoguard.yml` or `pyproject.toml` (sum must equal 1.0).

---

## 2. Deduction Points by Severity

Each category starts with **100 points**. Penalties are deducted based on unique finding severities:

| Severity | Deduction |
|---|:---:|
| **Critical** | -25 points |
| **High** | -15 points |
| **Medium** | -8 points |
| **Low** | -3 points |
| **Info** | 0 points |

Category scores are clamped to $[0.0, 100.0]$.

---

## 3. Letter Grade Scale

- **A**: 90.0 – 100.0 (Exceptional maintenance hygiene)
- **B**: 80.0 – 89.9 (Strong maintenance)
- **C**: 70.0 – 79.9 (Acceptable; improvements recommended)
- **D**: 60.0 – 69.9 (Substandard maintenance)
- **F**: < 60.0 (High risk; critical deficiencies detected)

---

## 4. Transparency & Disclaimer

> **Disclaimer**: The RepoGuard Health Score is an automated project-maintenance and hygiene indicator evaluating documentation, dependencies, testing, security, code quality, and CI/CD best practices. It is **NOT** a guarantee or warranty of security or vulnerability-free software.
