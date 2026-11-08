# GitHub Actions Integration

RepoGuard provides an official GitHub Action for automated repository health verification in CI/CD.

---

## Example Workflow

Create `.github/workflows/repoguard.yml`:

```yaml
name: RepoGuard Health Scan

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  repoguard:
    name: Repository Health Scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Run RepoGuard Action
        uses: repoguard/repoguard@v1
        with:
          min-score: "75"
          fail-on: "high"
          no-network: "false"
```

---

## Action Inputs

| Input | Description | Default |
|---|---|---|
| `path` | Path to repository | `.` |
| `min-score` | Minimum overall health score (0-100) | `70` |
| `fail-on` | Fail if findings meet/exceed severity | `high` |
| `no-network` | Disable external network lookups | `false` |
| `output-json` | Output JSON report filename | `repoguard-report.json` |
| `output-markdown` | Output Markdown summary filename | `repoguard-summary.md` |

---

## Features

- **GitHub Step Summary**: Automatically renders Markdown health table in workflow summary.
- **Pull Request Annotations**: Emits inline GitHub Actions error and warning annotations.
- **Workflow Artifacts**: Uploads machine-readable JSON reports for audit retention.
