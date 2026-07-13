# Releasing `bw-fetcher-py`

Users install: `pip install bw-fetcher-py` from **PyPI**.

## Local dev (no CI)

```powershell
.\scripts\build_cpp_windows.ps1
python python\scripts\stage_binaries.py
pip install -e python
```

---

## GitHub (`.github/workflows/release.yml`)

| Item | Value |
|------|--------|
| Trigger | `git push` tag `v*` |
| Secret | `PYPI_API_TOKEN` in repo Settings → Secrets |
| Jobs | `build-linux`, `build-windows`, `release` |

```bash
git tag v0.2.0
git push origin v0.2.0
```

Also creates a **GitHub Release** with zip/tar.gz + wheels.

---

## GitLab (`.gitlab/ci/bw-fetcher-py-release.yml`)

Separate file and **different job names** from GitHub:

| GitLab job | Purpose |
|------------|---------|
| `bw-fetcher-cpp-linux` | Build `BW-Fetcher-linux64` + `.tar.gz` |
| `bw-fetcher-py-wheel-linux` | manylinux `.whl` |
| `bw-fetcher-cpp-windows` | Windows exe + `.zip` (manual, needs `windows` runner) |
| `bw-fetcher-py-wheel-windows` | Windows `.whl` (manual) |
| `bw-fetcher-py-pypi-publish` | Upload wheels to PyPI |
| `bw-fetcher-gitlab-release` | GitLab Release page (optional) |

**Setup**

1. Push repo to GitLab
2. **Settings → CI/CD → Variables** → add `PYPI_API_TOKEN` (masked, protected)
3. Tag and push:

```bash
git tag v0.2.0
git push origin v0.2.0
```

4. Pipeline runs on tag; Windows jobs are **manual** unless you have a Windows runner

**Optional:** Run pipeline from **CI/CD → Run pipeline** (rules allow `web` source for testing without a tag).

---

## PyPI account checklist

1. [pypi.org](https://pypi.org) account created
2. API token at [pypi.org/manage/account/token/](https://pypi.org/manage/account/token/)
3. Token added to **GitHub** and/or **GitLab** CI variables as `PYPI_API_TOKEN`
4. Bump `version` in `python/pyproject.toml`
5. Push tag `v0.2.0` matching that version
6. After green pipeline: `pip install bw-fetcher-py` works publicly

First upload registers the project name `bw-fetcher-py` on PyPI.
