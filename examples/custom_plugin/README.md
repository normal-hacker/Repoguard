# RepoGuard Docker Analyzer Plugin (Example)

An example third-party plugin for [RepoGuard](https://github.com/repoguard/repoguard) demonstrating how to author, package, register, test, and distribute custom analyzers.

---

## 1. How the Plugin Architecture Works

RepoGuard uses Python entry points (`repoguard.plugins`) to register third-party analyzers without modifying RepoGuard core code.

Every plugin subclasses `BaseAnalyzer` from `repoguard.plugins.base`:

```python
from repoguard.plugins.base import BaseAnalyzer
from repoguard.core.findings import Category, Finding, Severity


class DockerAnalyzer(BaseAnalyzer):
    name = "docker"
    description = "Inspects Dockerfiles for container security antipatterns"
    category = Category.CUSTOM
    version = "0.1.0"

    def analyze(self, context: ScanContext) -> list[Finding]:
        findings = []
        # Your custom logic using context.files, context.read_file(), etc.
        return findings
```

---

## 2. Packaging and Registration

In your plugin's `pyproject.toml`, expose the entry point under the `repoguard.plugins` group:

```toml
[project]
name = "repoguard-docker-plugin"
version = "0.1.0"
dependencies = [
    "repoguard>=0.1.0",
]

[project.entry-points."repoguard.plugins"]
docker = "repoguard_docker_analyzer.analyzer:DockerAnalyzer"
```

---

## 3. Local Installation

To install your plugin in development mode:

```bash
cd examples/custom_plugin
pip install -e .
```

Verify that RepoGuard discovers your plugin:

```bash
repoguard plugins list
```

You will see:
```text
┏━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Plugin Name       ┃ Version      ┃ Description                                                            ┃
┡━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ docker            │ 0.1.0        │ Inspects Dockerfiles for unpinned base images, root user execution...  │
└───────────────────┴──────────────┴────────────────────────────────────────────────────────────────────────┘
```

Inspect plugin metadata:

```bash
repoguard plugins info docker
```

---

## 4. Execution

Run a scan against any repository containing a Dockerfile:

```bash
repoguard scan .
```

Your plugin runs alongside built-in analyzers with full error-isolation guarantees and results appear in the terminal, JSON, and Markdown reports.

---

## 5. Testing

Test your plugin using standard `pytest`:

```python
from repoguard.core.context import ScanContext
from repoguard_docker_analyzer.analyzer import DockerAnalyzer


def test_docker_analyzer(tmp_path):
    df = tmp_path / "Dockerfile"
    df.write_text("FROM node:latest\n")

    ctx = ScanContext(repo_root=tmp_path)
    findings = DockerAnalyzer().analyze(ctx)
    assert any(f.id == "DOCK001" for f in findings)
```

---

## 6. Distribution

To distribute your plugin to the community:

1. Build wheel and source distributions:
   ```bash
   pip install build
   python -m build
   ```
2. Publish to PyPI:
   ```bash
   twine upload dist/*
   ```
3. End users can then install it simply with:
   ```bash
   pip install repoguard-docker-plugin
   ```
   RepoGuard will automatically discover it on the next run!
