# Running the benchmark

## Requirements

| Component | Needed for | Notes |
|---|---|---|
| Python ≥ 3.10, `git` | everything | `pip install -e .` installs the only dependency (PyYAML) |
| Docker (or Podman with a `docker` shim) | `cbomkit`, `cdxgen` (default launcher) | images are pulled by release tag; set `docker.pull_policy` |
| Node.js ≥ 24 | `cdxgen` with `--launcher local` | installed into `~/.cache/orchestrator/cdxgen` via npm |
| ~1 GB disk, Python venv | `cryptobom-forge` | the CodeQL bundle (CLI + query packs) is downloaded once into `~/.cache/orchestrator/cryptobom-forge/codeql/<version>` |
| `GITHUB_TOKEN` (optional) | version resolution | lifts the unauthenticated API limit; without it `git ls-remote` is used, which needs no token |

CBOMkit has no local launcher: its jar depends on packages published on GitHub Packages, so the
release image is the reproducible artefact.

## Commands

```bash
orchestrator init                     # write orchestrator.yaml + tools.d/
orchestrator baseline sync|cases|info
orchestrator tools list|show <tool>|resolve [tool…]|install [tool…] [--pin tool=version] [--launcher …]
orchestrator run [--tool T]… [--case C]… [--pin tool=version]… [--launcher docker|local]
                 [--offline] [--skip-install] [--run-id ID] [--fail-fast] [--no-evaluate]
                 [--baseline-ref REF] [--baseline-repo URL|PATH]
orchestrator evaluate <run> [--baseline PATH]     # (re)score raw outputs; e.g. after a baseline update
orchestrator report <run> [--format md|json]
orchestrator export twocbom|priors <run> [--out FILE] [--tool T]…
orchestrator reconcile <run> --tool-a A --tool-b B [--category "k=v;k=v"] [--attribute NAME]
                       [--value-a V] [--value-b V] [--json]
orchestrator runs list | runs diff <run1> <run2>
orchestrator normalize <cbom.json> [--verbose]     # see how a file is lifted to the detection model
```

`<run>` is a run id, a run directory, or a `scorecard.json`/`priors.json` path.

## Typical sessions

Newest versions of everything, nightly:

```bash
orchestrator -v run            # resolves, pulls/installs, scans 5 cases × 3 tools, evaluates, exports
```

Reproduce a previous run's versions:

```bash
jq '.tools | map_values(.tag // .version)' results/20261105-213000/manifest.json
orchestrator run --pin cbomkit=v2.3.0 --pin cdxgen=v13.6.0 --pin cryptobom-forge=1.1.0 --pin codeql=codeql-bundle-v2.27.4
```

The baseline changed (new scenario, corrected ground truth): re-score without re-running tools:

```bash
orchestrator baseline sync
orchestrator evaluate 20261105-213000 --baseline .orchestrator/baseline
```

Only one tool, only Java, keep the workspaces for debugging:

```bash
orchestrator run --tool cbomkit --case Java --run-id cbomkit-java --skip-install   # with results.keep_workspaces: true
```

## How each built-in tool is run

* **cbomkit** — `ghcr.io/cbomkit/cbomkit-action:<version>` with `GITHUB_WORKSPACE=/github/workspace`
  (the case copy), `CBOMKIT_LANGUAGES=<java|python|go|csharp>`, `CBOMKIT_JAVA_REQUIRE_BUILD=false`,
  `CBOMKIT_OUTPUT_DIR=/github/workspace/cbom`; output `cbom/cbom.json`.  TypeScript is not supported
  by the Sonar Cryptography plugin and is recorded as `unsupported`.
* **cdxgen** — `ghcr.io/cyclonedx/cdxgen:<tag>` with
  `-t <python|java|go|js|dotnet> --include-crypto --evidence --deep --spec-version 1.6` (what the
  `cbom` alias sets, pinned to the 1.6 schema so `cryptographic-asset` components validate against
  the corpus' spec version); output `cbom.cdxgen.json`.
* **cryptobom-forge** — CodeQL bundle (CLI + query packs) → `codeql database create`
  (`--build-mode=none` for Java/C#) → `codeql database analyze` with the cryptography inventory
  queries (`experimental/cryptography/inventory/new_models` for Python,
  `experimental/quantum/InventorySlices` for Java; other languages have no inventory queries in the
  CodeQL repository and are `unsupported` until you add a `queries:` entry) → `cryptobom generate`.
  The forge is installed into a venv from its GitHub tag; its CycloneDX fork is installed over HTTPS
  because the forge's own metadata pins it with a `git+ssh` URL.

Edit `orchestrator/data/tools/<tool>.yaml` (or override it in `tools.d/`) to change flags, images or
queries; `orchestrator tools show <tool>` prints the effective spec.

## Configuration reference

`orchestrator init` writes a fully commented `orchestrator.yaml`; the defaults are in
`orchestrator/config.py`.  Relative paths are resolved against the directory containing the file.

## Troubleshooting

* **`docker pull … unavailable`** — the release tag has no image yet (a tag was pushed before the
  image build finished).  `fallback_tag` in the spec (`edge`/`latest`) is used automatically and
  noted in the manifest; pin to the previous version if you need exact reproducibility.
* **Root-owned output files** — containers run with `--user $(id -u):$(id -g)` by default
  (`docker.user: current`).  Set `docker.user: image` if an image refuses to run unprivileged.
* **GitHub API rate limit** — resolution falls back to `git ls-remote`; set `GITHUB_TOKEN` to use
  release metadata (pre-releases are excluded either way unless `github.allow_prerelease`).
* **CodeQL `database create` fails for Java/C#** — buildless extraction needs a recent CodeQL
  (≥ 2.16 for Java, ≥ 2.17 for C#); the bundle resolver always picks the newest.  For Go the
  extractor needs a Go toolchain on `PATH`.
* **A tool produced output but the run is `failed`** — see `logs/<tool>/<case>.log`; a non-JSON file
  or a missing output path are the usual causes.  `orchestrator normalize <file>` shows how a file is
  interpreted.
* **A language directory is missing from the run** — `baseline.include_cases`/`exclude_cases`, or
  the directory has no `ground-truth.json`.
