# Releasing `tokendna-sdk` to PyPI

This is the operator playbook for cutting a new SDK release. The TokenDNA
backend service is _not_ released via PyPI; only the `tokendna_sdk/` package
defined by `pyproject.toml` is shipped.

---

## 1. Prerequisites (one-time setup)

* PyPI account with maintainer access to `tokendna-sdk`.
* TestPyPI account (https://test.pypi.org/) for staging.
* API tokens stored as repo secrets:
  * `PYPI_API_TOKEN`
  * `TESTPYPI_API_TOKEN`
* Local toolchain:
  ```bash
  python3 -m pip install --upgrade build twine
  ```

---

## 2. Cut a release

### 2.1 Pick the version

Follow SemVer. Bump the version field in `pyproject.toml` and prepend a
new section to `CHANGELOG.md` with the release date.

```bash
git switch -c release/sdk-0.2.0
# edit pyproject.toml: version = "0.2.0"
# edit CHANGELOG.md: move [Unreleased] to [0.2.0] - YYYY-MM-DD
git commit -am "chore(sdk): bump tokendna-sdk to 0.2.0"
git push -u origin release/sdk-0.2.0
```

Open a PR; require an SDK reviewer's sign-off before merging.

### 2.2 Build artifacts

```bash
rm -rf dist/ build/ *.egg-info
python3 -m build --sdist --wheel
ls dist/
# tokendna_sdk-0.2.0-py3-none-any.whl
# tokendna_sdk-0.2.0.tar.gz
```

### 2.3 Stage on TestPyPI

```bash
python3 -m twine upload --repository testpypi dist/*
python3 -m pip install --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ tokendna-sdk==0.2.0
python3 -c "import tokendna_sdk; print(tokendna_sdk.__version__)"
```

Smoke test:

```bash
tokendna --help
tokendna verify  # against a staging API key
```

### 2.4 Release to PyPI

```bash
python3 -m twine upload dist/*
```

Verify https://pypi.org/project/tokendna-sdk/ shows the new version.

### 2.5 Tag & GitHub release

```bash
git tag -a sdk-v0.2.0 -m "tokendna-sdk 0.2.0"
git push origin sdk-v0.2.0
gh release create sdk-v0.2.0 \
  --title "tokendna-sdk 0.2.0" \
  --notes-file - <<EOF
$(awk '/^## \[0\.2\.0\]/,/^## \[/{print}' CHANGELOG.md | sed '$d')
EOF
```

---

## 3. After release

* Update the docs site code samples to the new version.
* If the release contained a security fix, post to the security advisory
  feed and notify enrolled tenants via the threat-sharing network.
* Reset `[Unreleased]` in `CHANGELOG.md` for the next cycle.

---

## 4. Yanking a bad release

If a release ships with a regression:

1. `python3 -m twine yank tokendna-sdk==X.Y.Z --reason "<short>"`
2. Cut a patch release immediately — do not edit the yanked version in place.
3. File a postmortem and link it from `CHANGELOG.md`.
