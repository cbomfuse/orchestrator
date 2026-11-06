# Adding a CBOM generator

Most tools need one YAML file.  Put it in `tools.d/<id>.yaml` and add the id to `tools.enabled`.

## The spec

```yaml
id: mytool                              # unique; used in results, 2CBOM tools.json, --tool
name: My Tool
repo: https://github.com/org/mytool     # where versions are resolved from
description: one line for the report
adapter: orchestrator.tools.generic:CommandToolAdapter   # default; see "pipeline tools" below

versioning:
  strategy: release        # release (latest GitHub release, else highest tag) | tag | branch | fixed
  branch: main             # for strategy: branch
  tag_pattern: null        # regex a tag must match (e.g. "^v" or "^codeql-bundle-v")
  allow_prerelease: false

launcher: docker           # default launcher; `--launcher local` or tools.default_launcher override it

docker:
  image: ghcr.io/org/mytool:{tag}       # placeholders below
  fallback_tag: latest                  # used when the resolved tag has no image
  mount: /src                           # where the case workspace is mounted
  workdir: /src
  user: current                         # current | image | "uid:gid"
  entrypoint: null
  network: null                         # e.g. "none" to forbid network access
  env: {MYTOOL_LANG: "{language}"}
  args: ["scan", "-o", "{output_container}", "{mount}"]
  extra_args: []                        # extra `docker run` flags
  mounts: {}                            # extra host:container mounts

local:
  install:                              # run once per resolved version, in {cache}
    - ["pip", "install", "--target", "{cache}/site", "mytool=={version}"]
  check: ["mytool", "--version"]        # recorded in the manifest
  command: ["mytool", "scan", "-o", "{output}", "{workdir}"]
  env: {}
  cwd: null                             # defaults to the workspace

output: mytool-cbom.json   # relative to the workspace; glob allowed (largest match wins)
format: auto               # auto | cyclonedx | ibm-cbom (auto-detection is reliable)

languages:                 # corpus language (or case directory name) -> value of {language}
  Python: python
  Java: {value: java, env: {MYTOOL_BUILD: "false"}, args: [...]}   # per-language overrides allowed
  Go: go
  TypeScript: typescript
  C#: csharp               # unlisted languages run as "unsupported" (recorded, not failed)

timeout_seconds: 1800

twocbom:                   # copied into the exported tools.json
  aliases: [mytool, my tool, org/mytool]
  detection_method: static-source   # static-source | static-binary | dynamic | manual | unknown
```

### Placeholders

| Placeholder | Value |
|---|---|
| `{version}` | tag without the leading `v`/prefix (`2.3.0`); for branches `main@<sha12>` |
| `{tag}` | the tag as resolved (`v2.3.0`) |
| `{commit}` | commit SHA |
| `{workdir}` | host path of the case copy |
| `{mount}` | container mount path (docker) / `{workdir}` (local) |
| `{output}` | host path of the expected output file |
| `{output_container}` | the output path as seen inside the container |
| `{language}` | the per-language value; other per-language keys as `{language_<key>}` |
| `{case}`, `{language_name}`, `{source_file}` | case id, corpus language, main source file |
| `{cache}` | `.orchestrator/cache/<id>` |
| `{home}`, `{platform}`, `{uid}`, `{gid}` | host facts |

### What the orchestrator does with it

1. `resolve` — newest version from `repo` according to `versioning` (or a pin), recorded with the
   commit SHA.
2. `install` — Docker: pull the rendered image (or the fallback), record digest and id, read OCI
   version labels.  Local: run the install steps in `{cache}`, then the `check` command.
3. `run` — per case: copy the case directory to a workspace, render env/args, execute (with the
   timeout), locate the output, copy it to `raw/<id>/<case>/`, classify the status.
4. Evaluation reads the output with the auto-detecting normaliser, so any CycloneDX 1.5–1.7 or IBM
   1.4-cbom-1.0 document works.  Tool names found in `metadata.tools` are added to the 2CBOM aliases.

## Pipeline tools (Python adapters)

When a tool needs several steps or custom version bookkeeping, subclass `ToolAdapter`
(`orchestrator/tools/base.py`) and point `adapter:` at it:

```python
from orchestrator.tools.base import ToolAdapter, ToolRunResult, ToolVersion

class MyPipelineAdapter(ToolAdapter):
    def resolve(self, pin=None) -> ToolVersion: ...     # may record sub-tool versions in .components
    def install(self, version, log_path=None) -> None: ...
    def run(self, case, workdir, version, out_dir, log_path) -> ToolRunResult: ...
```

`run` must return a `ToolRunResult` with `status` (`ok | empty | failed | timeout | unsupported`),
`output_path` (the CBOM copied into `out_dir`), `exit_code`, `duration_seconds`, `log_path`,
`command` and `notes`.  `orchestrator/tools/cryptobom_forge.py` is a complete example (CodeQL bundle
download, database creation, query selection per language, SARIF → CBOM), and
`orchestrator/tools/oracle.py` a minimal one.

## Checklist for a new tool

- [ ] `orchestrator tools show <id>` prints the spec and `orchestrator tools resolve <id>` finds a version.
- [ ] `orchestrator run --tool <id> --case Python --run-id try` produces `raw/<id>/Python/…`.
- [ ] `orchestrator normalize results/try/raw/<id>/Python/<file>` shows detections with asset types and
      occurrences; if names are not recognised, extend `normalize/lexicon.py` (one atom per spelling).
- [ ] The report's coverage row shows `ok` for the languages the tool supports.
