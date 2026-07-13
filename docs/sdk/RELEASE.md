# `tokendna-sdk` — release process

## TL;DR

```bash
bin/bump_sdk_version.py 0.2.0 --tag
git push && git push --tags
```

The `release-pypi` workflow takes it from there: builds wheel + sdist,
guards that the tag matches both `pyproject.toml` and `tokendna_sdk/__init__.py`,
publishes to PyPI via OIDC trusted publishing.

## One-time setup (still needed before the first release)

The publish workflow uses **PyPI OIDC trusted publishing** instead of a long-lived API token, so the only durable secret is the binding between this repository and the PyPI project record. Two steps:

1. **Claim the project name on PyPI.** Sign in at <https://pypi.org/manage/projects/> and either upload an initial version manually or, if `tokendna-sdk` doesn't exist yet, create it via `python3 -m build` + `twine upload` once. (The CI guard catches "tag/version mismatch" but it can't claim a name on your behalf.)

2. **Add the trusted publisher binding** at <https://pypi.org/manage/project/tokendna-sdk/settings/publishing/>:
   - **Owner**: `Bobcatsfan33`
   - **Repository name**: `TokenDNA`
   - **Workflow filename**: `release-pypi.yml`
   - **Environment name**: `pypi`

3. **Create the `pypi` environment** in this repo: Settings → Environments → New environment → name it `pypi`. Optionally set required reviewers (yourself) so a release can't fire without an explicit approval click.

After that, every release is just:

```bash
bin/bump_sdk_version.py <new-version> --tag
git push && git push --tags
# go approve the deployment in the Actions tab
```

## What the workflow guards against

- **Version drift**: pyproject, `__init__.py`, and the pushed tag must all agree (`v0.2.0` ↔ `version = "0.2.0"` ↔ `__version__ = "0.2.0"`). The bump script keeps them in sync; CI rejects the publish if anything diverges.
- **Unsigned releases**: OIDC trusted publishing means PyPI verifies the GitHub workflow identity directly; there's no long-lived token to leak.
- **Accidental main pushes**: the workflow fires only on tag pushes (`v*`), not on every commit to main.

## Backout

Releases are **immutable on PyPI** — you can yank a version (hides it from `pip install` resolution) but you cannot delete or overwrite it. To ship a fix:

```bash
bin/bump_sdk_version.py 0.2.1 --tag    # always go forward
git push && git push --tags
```

## Local sanity check before tagging

```bash
python3 -m pip install --upgrade build twine
python3 -m build --wheel --sdist
python3 -m twine check dist/*
```

A successful local build produces `dist/tokendna_sdk-<v>-py3-none-any.whl` + `dist/tokendna_sdk-<v>.tar.gz` and `twine check` reports `PASSED` on both.

## Verifying a published release

```bash
pip install --upgrade tokendna-sdk
python3 -c "import tokendna_sdk; print(tokendna_sdk.__version__)"
tokendna --help
```
