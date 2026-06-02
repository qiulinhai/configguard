# Release process

This document is for **maintainers**, not users. It describes how to cut a new ConfigGuard release.

## One-time setup

### 1. PyPI trusted publishing

ConfigGuard publishes via [PyPI Trusted Publishing](https://docs.pypi.org/trusted-publishers/) — no API token is stored in GitHub. Configure it once on PyPI's side:

1. Go to https://pypi.org/manage/account/publishing/
2. Click "Add a new pending publisher"
3. Fill in:
   - **PyPI project name:** `configguard`
   - **Owner:** `qiulinhai`
   - **Repository name:** `configguard`
   - **Workflow filename:** `publish.yml`
   - **Environment name:** `pypi` (must match the `environment:` block in `.github/workflows/publish.yml`)
4. Click "Add"

You do **not** need to do this for TestPyPI if you only publish to production PyPI.

### 2. GitHub `pypi` environment

The publish workflow references a `pypi` environment. Create it:

1. Go to https://github.com/qiulinhai/configguard/settings/environments
2. Click "New environment" → name it `pypi`
3. (Optional) Add a protection rule: "Required reviewers" with yourself listed, so an accidental tag push can't immediately publish.
4. Save

## Cutting a release

```bash
# 1. Make sure main is green
git checkout main
git pull
pytest  # locally

# 2. Bump the version
#    - pyproject.toml: [project] version = "X.Y.Z"
#    - CHANGELOG.md: move "Unreleased" entry to "X.Y.Z (YYYY-MM-DD)"

# 3. Commit, push
git add pyproject.toml CHANGELOG.md
git commit -m "chore(release): vX.Y.Z"
git push

# 4. Tag the commit
git tag -a vX.Y.Z -m "vX.Y.Z"
git push origin vX.Y.Z

# 5. Create a GitHub Release
#    Go to https://github.com/qiulinhai/configguard/releases/new
#    - Choose tag vX.Y.Z
#    - Title: "ConfigGuard vX.Y.Z"
#    - Body: copy from CHANGELOG.md
#    - Publish
#    → The publish.yml workflow fires automatically and uploads to PyPI.
```

## Verifying the publish

After the release is published, confirm on https://pypi.org/project/configguard/ that the new version appears. The wheel and sdist should be downloadable.

```bash
# In a fresh venv:
pip install --upgrade configguard
configguard --version
```

## Rollback

You can't delete a PyPI release, but you can yank it (hide from `pip install`):

1. Go to https://pypi.org/manage/project/configguard/releases/
2. Click the version → "Yank"

A yanked release is still installable with `pip install configguard==X.Y.Z` (useful for testing) but is hidden from default resolution.
