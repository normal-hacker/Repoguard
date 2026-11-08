# Configuration Guide

RepoGuard can be customized using `.repoguard.yml`, `.repoguard.json`, or `pyproject.toml`.

---

## Initialize Default Configuration

```bash
repoguard config init
```

This generates `.repoguard.yml` in your current directory:

```yaml
version: 1

scoring_weights:
  documentation: 0.15
  code_quality: 0.25
  security: 0.25
  dependencies: 0.15
  testing: 0.10
  cicd: 0.10

thresholds:
  min_score: 70.0
  fail_on_severity: high

network:
  enabled: true
  timeout_seconds: 10.0
  max_retries: 2

code_quality:
  max_file_lines: 500
  max_function_lines: 50
  max_cyclomatic_complexity: 10
  max_function_arguments: 6

exclusions:
  - "legacy/*"
  - "vendor/*"
```

---

## Configuration via pyproject.toml

You can also place configuration inside `pyproject.toml`:

```toml
[tool.repoguard]
version = 1
exclusions = ["dist/*", "tests/fixtures/*"]

[tool.repoguard.scoring_weights]
documentation = 0.20
code_quality = 0.20
security = 0.25
dependencies = 0.15
testing = 0.10
cicd = 0.10

[tool.repoguard.thresholds]
min_score = 80.0
fail_on_severity = "high"
```
