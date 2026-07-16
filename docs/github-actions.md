# GitHub Actions CI/CD

**Status:** Infra Phase 11 — workflow files written, statically tested
(78 tests, `tests/github_actions/`), and validated locally (all commands
the workflows run were reproduced directly on this machine — lock check,
frozen sync, full test suite, Ruff, mypy, both Compose renders, all three
Docker image builds). **The workflows have not yet run on GitHub** — per
this phase's own explicit instruction, no branch was created and nothing
was committed or pushed. See §27 for the exact remaining steps.
**Date:** 2026-07-16
**Files:** [`.github/workflows/ci.yml`](../.github/workflows/ci.yml),
[`.github/workflows/docker-publish.yml`](../.github/workflows/docker-publish.yml),
[`tests/github_actions/test_workflows.py`](../tests/github_actions/test_workflows.py)

---

## 1. Purpose

Two first-party GitHub Actions workflows validate every pull request and
push, and publish the project's three Docker images
(`apex`/`apex-kali`/`apex-vpn`) to the GitHub Container Registry (GHCR) on
trusted events only. Neither workflow ever contacts HTB, starts a real
VPN tunnel, or executes a live APEX engagement — both are pure build/test/
publish automation over this repository's own source, Dockerfiles, and
Compose configuration.

---

## 2. Workflow files

| File | Purpose |
|---|---|
| `.github/workflows/ci.yml` | Validates every PR and default-branch push: lock check, frozen dependency install, full test suite, Ruff, mypy, both Compose renders, all three images built (never pushed). |
| `.github/workflows/docker-publish.yml` | Re-validates from scratch, then builds and pushes all three images to GHCR — only on default-branch pushes, `v*` tags, or manual dispatch. |

Both live directly under `.github/workflows/` at the repository root —
the **only** first-party workflow location. Four vendored third-party
corpora under `Knowledge/` (`GTFOBins`, `LOLBAS`, `PayloadsAllTheThings`,
`SecLists`) each ship their own, unrelated `.github/workflows/` directory
as part of their upstream project — these are never read, referenced, or
treated as project workflows by anything in this repository (statically
enforced: `tests/github_actions/test_workflows.py::TestWorkflowExistence::test_vendored_workflow_files_are_not_project_workflows`).

---

## 3. CI triggers

```yaml
on:
  pull_request:
  push:
    branches:
      - main
  workflow_dispatch:
```

The repository's actual default branch was inspected (`git symbolic-ref
refs/remotes/origin/HEAD` → `refs/remotes/origin/main`) before writing
this — `main` is not a guess. `pull_request` (bare, no `types:` filter)
covers PRs against any base branch; `push` is scoped to `main` only, so
CI does not re-run redundantly for every push to every feature branch
(that's what the `pull_request` trigger on the PR itself already covers).

---

## 4. Publishing triggers

```yaml
on:
  push:
    branches:
      - main
    tags:
      - "v*"
  workflow_dispatch:
```

**Never** `pull_request` or `pull_request_target` — publishing only ever
runs for events that require write access to the repository (a push to
`main`, or a tag push), which by GitHub's own trust model excludes
arbitrary fork pull requests. `pull_request_target` is explicitly never
used anywhere in either workflow (statically enforced).

---

## 5. Validation jobs

Both workflows run substantively the same validation:

| Job | File | Steps |
|---|---|---|
| `validate` | `ci.yml` | checkout → Python 3.11 → uv → lock check → frozen sync → pytest → Ruff → mypy |
| `compose-validate` | `ci.yml` | checkout → render default Compose config → render HTB Compose config → confirm no VPN device/profile exists |
| `build-images` | `ci.yml` | checkout → Buildx → build each of the 3 images, `push: false` |
| `validate` | `docker-publish.yml` | the same Python + Compose validation as `ci.yml`'s two jobs, combined into one self-contained job |
| `build-and-push` | `docker-publish.yml` | checkout → lowercase owner → Buildx → GHCR login → metadata → build **and push** each of the 3 images |

`docker-publish.yml`'s `validate` job is a full, independent copy of the
same checks — it does not assume `ci.yml` already ran for this exact
commit (a `workflow_dispatch` or tag push may have no associated `ci.yml`
run at all). `build-and-push` declares `needs: [validate]`, so publishing
is structurally impossible without this job passing first — not merely
relying on branch protection rules.

---

## 6. Python and uv setup

```yaml
- uses: actions/setup-python@ece7cb06caefa5fff74198d8649806c4678c61a1 # v6.3.0
  with:
    python-version: "3.11"

- uses: astral-sh/setup-uv@11f9893b081a58869d3b5fccaea48c9e9e46f990 # v8.3.2
  with:
    version: "0.11.28"
    enable-cache: true
```

`3.11` matches `.python-version`, `[project].requires-python` in
`pyproject.toml`, and the exact interpreter baked into every project
Dockerfile. `0.11.28` matches the exact `uv` version pinned as a build
stage in `docker/apex/Dockerfile`/`docker/kali/Dockerfile`
(`ghcr.io/astral-sh/uv:0.11.28`, digest-pinned) and is the version
actually installed on the machine this phase's local validation ran on
(`uv --version` → `0.11.28`). `enable-cache: true` uses `setup-uv`'s own
built-in GitHub Actions cache integration (keyed by `uv.lock`'s hash) —
no separate `actions/cache` step was needed.

---

## 7. Test, Ruff, and mypy commands

```bash
uv lock --check
uv sync --frozen --all-groups
uv run pytest -q
uv run ruff check .
uv run mypy
```

Identical to the commands documented in README.md's own "Development
environment (uv)" section and required by every prior Infra Phase's local
validation — never a reduced-scope subset, never `--no-verify`-style
shortcuts. `uv run mypy` (bare, no path argument) is used deliberately —
`uv run mypy .` is documented (CLAUDE.md, README.md) to walk the vendored
`Knowledge/` corpus and fail on a pre-existing, unrelated module-name
collision; a dedicated test
(`TestPythonValidation::test_mypy_is_never_invoked_with_a_bare_dot_path`)
statically enforces that `uv run mypy .` never appears in either
workflow.

---

## 8. Compose validation

```bash
# Default topology — no VPN profile needed:
APEX_TOOL_SERVICE_TOKEN=ci-disposable-token \
  docker compose config > /tmp/compose-default.rendered.yml

# HTB override — interpolation only, no real profile:
APEX_TOOL_SERVICE_TOKEN=ci-disposable-token \
APEX_HTB_OVPN_PATH=./secrets/ci-placeholder.ovpn \
  docker compose -f compose.yaml -f compose.htb.yaml --profile htb \
  config > /tmp/compose-htb.rendered.yml
```

`docker compose config` is pure YAML interpolation/validation — it never
starts a container, never creates `/dev/net/tun`, never contacts HTB, and
never checks that `APEX_HTB_OVPN_PATH` actually points at a real file
(only `up`/`run` would attempt to mount it). No dummy `.ovpn` file is
created anywhere in either workflow. Both renders are redirected to a
temp file, never printed to the job log — defense in depth even though
only disposable placeholder values are ever used. `ci.yml`'s
`compose-validate` job additionally asserts `/dev/net/tun` and the
placeholder profile path do not exist on the runner after rendering, as
an explicit, positive proof that nothing VPN-related was started.

Docker and the Compose v2 plugin are pre-installed on GitHub's
`ubuntu-latest` hosted runners — no extra setup step is needed just to
run `docker compose config`.

---

## 9. Image matrix

```yaml
strategy:
  matrix:
    include:
      - image: apex
        dockerfile: docker/apex/Dockerfile
      - image: apex-kali
        dockerfile: docker/kali/Dockerfile
      - image: apex-vpn
        dockerfile: docker/vpn/Dockerfile
```

Present, identically, in both `ci.yml` (`build-images`, `push: false`)
and `docker-publish.yml` (`build-and-push`, `push: true`). Build context
is the repository root (`context: .`) for all three — every Dockerfile's
own documented build command already uses the repo root (`docker build -f
docker/apex/Dockerfile .`, etc.), and each Dockerfile's `.dockerignore`-
scoped `COPY` instructions are already narrow/selective, so a wider
context does not leak anything unintended into any image (this was
already true and verified in Infra Phases 5/6/10; unchanged here).

---

## 10. Image names

```text
ghcr.io/<repository_owner, lowercased>/apex
ghcr.io/<repository_owner, lowercased>/apex-kali
ghcr.io/<repository_owner, lowercased>/apex-vpn
```

The owner segment is derived at run time from `github.repository_owner`
— never a hardcoded personal username — and explicitly lowercased (GHCR
requires lowercase image names; this repository's actual owner login,
`RownakDiganta`, is mixed-case):

```yaml
- name: Compute lowercase image owner
  id: owner
  env:
    OWNER: ${{ github.repository_owner }}
  run: echo "owner=${OWNER,,}" >> "$GITHUB_OUTPUT"
```

Uses bash's own `${VAR,,}` lowercase parameter expansion — no `eval`, no
backticks, no unsafe shell evaluation of untrusted input.
`github.repository_owner` is a trusted workflow-context value (GitHub
account/org names are restricted to alphanumerics and hyphens by GitHub's
own naming rules), routed through `env:` rather than interpolated
directly into the shell script, matching GitHub's own recommended
script-injection-avoidance pattern.

---

## 11. GHCR authentication

```yaml
- uses: docker/login-action@af1e73f918a031802d376d3c8bbc3fe56130a9b0 # v4.4.0
  with:
    registry: ghcr.io
    username: ${{ github.actor }}
    password: ${{ secrets.GITHUB_TOKEN }}
```

Only present in `docker-publish.yml` — statically enforced
(`TestPublishing::test_login_action_only_in_publish_workflow`) that
`docker/login-action` never appears in `ci.yml` at all. Uses the
GitHub-provided, automatically-rotated `secrets.GITHUB_TOKEN` — no
manually generated Personal Access Token was created or required; nothing
in either workflow references any `secrets.*` context value other than
`GITHUB_TOKEN` (statically enforced:
`TestSecretSafety::test_secrets_context_only_used_for_github_token`). The
token is never echoed, printed, or written to a file anywhere in either
workflow.

---

## 12. Workflow permissions

```yaml
# ci.yml (workflow-level; no job overrides it upward)
permissions:
  contents: read

# docker-publish.yml (workflow-level)
permissions:
  contents: read
  packages: write
```

`docker-publish.yml`'s own `validate` job additionally narrows itself to
`contents: read` only (a job-level `permissions:` block replaces the
workflow-level one for that job) — it never touches GHCR, so it never
carries `packages: write` even though the workflow as a whole is granted
it for the later `build-and-push` job. Neither workflow ever uses
`permissions: write-all`, and no job in `ci.yml` overrides the
workflow-level `contents: read` with anything broader.

---

## 13. Pull-request security

For every pull request (including from forks), `ci.yml`:

- Runs all Python validation (lock, sync, pytest, Ruff, mypy).
- Renders both Compose configurations (never starts anything).
- Builds all three images with `push: false` — nothing is ever uploaded
  anywhere.
- Never runs `docker/login-action` — no GHCR authentication step exists
  in this workflow at all.
- Never carries `packages: write` — the workflow-level permission block
  is `contents: read` only, full stop.
- Never accesses `secrets.GITHUB_TOKEN` (or any other secret) — no step
  in `ci.yml` references `secrets.*` anywhere.
- Never starts the HTB VPN, never creates `/dev/net/tun`, never contacts
  a target.

This means a malicious or compromised pull request — including one from
an untrusted fork, which GitHub always runs with read-only, no-secret
permissions for the ordinary `pull_request` trigger — cannot exfiltrate
the GHCR-publishing token, push an image, or reach any credential,
because the workflow triggered for that PR structurally has none of
those capabilities available to it.

---

## 14. Default-branch publishing

A push to `main` triggers `docker-publish.yml`: `validate` runs the full
suite again, then (only if it passes) `build-and-push` builds and
publishes all three images tagged `latest` (via
`type=raw,value=latest,enable={{is_default_branch}}` — `metadata-action`'s
own built-in "is this the repository's default branch" check) and
`sha-<short-commit-sha>`.

---

## 15. Version-tag publishing

Pushing a tag matching `v*` (e.g. `v1.2.3`) triggers the same workflow.
`is_default_branch` is false for a tag ref, so `latest` is **not**
reassigned by a tag push — only the semantic-version tag family plus the
SHA tag are published (see §16). This is a deliberate design choice: a
maintainer may tag a historical release after `main` has already moved
on, and unconditionally moving `latest` to match every tag push would be
surprising in that case. If this project later wants tag pushes to also
update `latest`, that is a one-line change to the `metadata-action`
`tags:` input's `enable=` condition — not attempted in this phase to keep
the two triggers' behavior exactly matching this phase's own task brief.

---

## 16. Tag strategy

| Trigger | Tags published |
|---|---|
| Push to `main` | `latest`, `sha-<short-sha>` |
| Push tag `v1.2.3` | `1.2.3`, `v1.2.3`, `1.2`, `1`, `sha-<short-sha>` |

```yaml
tags: |
  type=raw,value=latest,enable={{is_default_branch}}
  type=sha,format=short,prefix=sha-
  type=semver,pattern={{version}}
  type=semver,pattern=v{{version}}
  type=semver,pattern={{major}}.{{minor}}
  type=semver,pattern={{major}}
```

`type=sha` is unconditional (always produced, on both triggers) —
`docker/metadata-action`'s own default behavior for this rule already
uses the short commit SHA, giving an immutable, traceable tag for every
published image regardless of which trigger produced it. Neither
workflow ever publishes an arbitrary feature-branch name as a tag —
publishing only ever runs for `main`/`v*` in the first place (§4).

---

## 17. OCI labels

```yaml
labels: |
  org.opencontainers.image.title=${{ matrix.image }}
  org.opencontainers.image.description=${{ matrix.description }}
```

`docker/metadata-action` automatically derives and applies the standard
OCI label set from repository/workflow metadata — `org.opencontainers.
image.source` (repository URL), `.revision` (the exact commit SHA being
built), `.created` (build timestamp), and `.version` (the matched
tag/semver value) are all populated by the action itself with no
additional configuration. `.title`/`.description` are explicitly
overridden per matrix entry above, since the action's own default
(derived from the single GitHub repository's name/description) would
otherwise apply the identical, non-differentiated label to all three
distinct images. No version number is invented — every value traces back
to real workflow/repository metadata (the triggering ref, the commit
SHA, or the matrix entry's own static description string).

---

## 18. Cache strategy

```yaml
cache-from: type=gha,scope=${{ matrix.image }}
cache-to: type=gha,mode=max,scope=${{ matrix.image }}
```

GitHub Actions' own BuildKit cache backend (`type=gha`), scoped by
`matrix.image` — `apex`, `apex-kali`, and `apex-vpn` each get a distinct,
non-overlapping cache scope, so one image's layers can never evict or
overwrite another's cache entries (statically enforced:
`TestCache::test_cache_scope_is_parameterized_by_matrix_image`). The same
scope names are used in both `ci.yml` and `docker-publish.yml` for the
same image, so a PR's validation build and a later `main`-branch publish
build can share and reuse each other's cache — faster builds on both
sides, deliberately, at no security cost (the GHA cache backend is scoped
to this repository and does not cross repository boundaries).

---

## 19. Provenance and SBOM

```yaml
provenance: true
sbom: true
```

Enabled **only** in `docker-publish.yml`'s `build-and-push` job — a
pushed image is what these BuildKit attestations attach to (as OCI
referrer manifests alongside the image), so enabling them for `ci.yml`'s
`push: false` validation-only builds would have no meaningful target to
attach to. `docker/setup-buildx-action` installs the `docker-container`
Buildx driver by default, which is what both attestation types require;
GHCR supports OCI referrers, so no further registry-side configuration
is needed.

**Reproducibility caveat, stated explicitly and accurately:** neither
attestation asserts that the Kali image's `apt-get install` step is fully
reproducible. `docker/kali/Dockerfile` pins the base image by content
digest and this repository commits the exact `RUN apt-get install ...`
instruction, but Kali's rolling-release repository has no dated
package-snapshot mechanism — the specific package *versions* `apt-get`
resolves at build time can still differ between two builds run on
different days, even from the identical committed Dockerfile and base
digest (this is a pre-existing, already-documented limitation — see
`docker/kali/Dockerfile`'s own "DOCUMENTED LIMITATION" comment and
`docs/kali-container.md` "Base image"). The SBOM generated for that image
accurately reflects whatever was actually installed for that specific
build, not a guaranteed-identical set across rebuilds.

---

## 20. Manual dispatch

Both workflows support `workflow_dispatch:` with no required inputs —
either can be triggered by hand from the Actions tab (subject to normal
repository write-access requirements to trigger a dispatch at all).
Dispatching `docker-publish.yml` manually runs against whichever
branch/tag is selected in the dispatch UI (defaulting to the default
branch); `metadata-action`'s `is_default_branch`/semver-pattern logic
resolves normally against whatever ref was actually selected — no special
handling was added or needed for the manual-dispatch case.

---

## 21. Package visibility

**Not yet verified — no package has been published.** GHCR packages
default to the same visibility as the repository they're associated with
the *first* time they're published, but this can be changed independently
per-package afterward via the package's own Settings page on GitHub. This
document does not claim any visibility setting until a real publish has
happened and the setting has been checked on GitHub — see §27.

---

## 22. GitHub repository settings

Two settings should be confirmed once workflows are pushed (not
verifiable from this local environment):

1. **Actions permissions** — Settings → Actions → General → "Workflow
   permissions" should allow the default `GITHUB_TOKEN` read access at
   minimum; this project's workflows only ever request `contents: read`
   (CI) or `contents: read` + `packages: write` (publish) explicitly via
   each workflow's own `permissions:` block, so the repository-wide
   default can safely remain at its most restrictive setting — the
   per-workflow block is what actually governs each run's token scope.
2. **Package write access** — the very first `docker/login-action` +
   push from `GITHUB_TOKEN` will create each GHCR package automatically;
   no manual "create package" step is required beforehand.

---

## 23. Permission troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `docker-publish.yml` fails at `docker/login-action` with a 403/denied error | Repository's Settings → Actions → General → Workflow permissions is set to "Read repository contents permission" *and* the organization/repository has an additional policy blocking package writes | Check Settings → Actions → General; the workflow's own `permissions: packages: write` block should be sufficient on a normal repository, but an organization-level policy can still override it |
| Push succeeds but the package doesn't appear under the *user's* profile | GHCR associates a package with the *repository* by default, not a user profile | Check the repository's own Packages tab (right sidebar on the GitHub repo page), not a personal profile |
| `docker-publish.yml` runs but `build-and-push` is skipped | `validate` job failed — publishing has a hard `needs: [validate]` dependency and does not run otherwise | Check the `validate` job's logs first |

---

## 24. What CI does not do

- Does not run a live APEX engagement (`--confirm-live` never appears
  anywhere in either workflow).
- Does not start the HTB VPN profile, does not create `/dev/net/tun`,
  does not contact HTB in any way.
- Does not read a real `.env` file (only inline, disposable `env:`
  key/value pairs — `ci-disposable-token`, never a real secret).
- Does not read, copy, or reference a real `.ovpn` profile (only the
  interpolation placeholder `./secrets/ci-placeholder.ovpn`, which is
  never created as a file).
- Does not publish an image from a pull request, from a fork, or from
  any branch other than the default branch (plus `v*` tags).
- Does not mount the Docker socket into any project container.
- Does not run any container `privileged: true` or with host networking.
- Does not perform HTB exploitation diagnosis, deterministic Meow/Cap
  workflow testing, or any target-specific logic — entirely out of scope
  for this phase (CLAUDE.md §13.8/§13.9's standing prohibition, unchanged).

---

## 25. HTB and VPN exclusions

Both Compose-validation steps render configuration only — `docker compose
config`, never `up`. `ci.yml`'s `compose-validate` job explicitly asserts
`/dev/net/tun` does not exist and the placeholder `.ovpn` path was never
created, as positive proof rather than merely omitting the `up` command.
Neither workflow file contains a real HTB target IP, a real HTB route
CIDR beyond the already-public, documented `10.129.0.0/16` lab range
constant, or any machine-specific value — statically enforced by
`TestSecretSafety::test_no_htb_target_ip` and
`TestComposeValidation::test_no_target_ip_literal_anywhere`.

---

## 26. Local validation limitations

Every command either workflow runs was reproduced directly on the
development machine as part of this phase's own local validation (§ below
in the phase completion report) — but GitHub-hosted execution differs in
ways local reproduction cannot fully capture: GitHub's actual runner
image/toolchain versions, real GHCR authentication and package creation,
real BuildKit GHA-cache-backend behavior across separate job
invocations, and real multi-job `needs:` dependency scheduling. Local
`docker build`/`docker compose config` runs prove the underlying commands
work; they do not prove the workflow YAML itself is free of a syntax or
context-reference error that only GitHub's own workflow parser would
catch. See §27 for what remains to be verified by an actual push.

---

## 27. First-run manual validation

Exact remaining steps, none of which this phase performed (no commit, no
push, no branch created, per this phase's own explicit instruction):

1. Review the diff (`git status --short`, `git diff`).
2. Commit the new/changed files.
3. Push to a branch (or directly to `main`, per this project's normal
   workflow) and open a pull request if using one.
4. Open the repository's **Actions** tab on GitHub and confirm `ci.yml`
   appears and runs for the push/PR.
5. Confirm all `ci.yml` jobs (`validate`, `compose-validate`,
   `build-images` × 3) pass.
6. Merge (or push directly) to `main` and confirm `docker-publish.yml`
   runs and its `validate` + `build-and-push` × 3 jobs all pass.
7. Open the repository's **Packages** tab (or
   `https://github.com/users/<owner>/packages/container/package/apex`,
   substituting the real owner and each of the three image names) and
   confirm all three images (`apex`, `apex-kali`, `apex-vpn`) exist with
   the expected `latest`/`sha-*` tags.
8. Check each package's own Settings page to confirm/set the intended
   visibility (public vs. private) — do not assume a default.
9. Optionally test a manual pull: `docker pull
   ghcr.io/<owner>/apex:latest` from a machine with no special
   credentials, to confirm the intended visibility actually behaves as
   expected.
10. Push a `v0.0.1`-style test tag (or the project's real first version
    tag) and confirm the semver tag family (`v0.0.1`, `0.0.1`, `0.0`, `0`)
    plus a SHA tag are published correctly.

Until these steps are performed, this phase remains **code complete, not
GitHub-run-validated** — see the phase completion report for the exact
verdict.
