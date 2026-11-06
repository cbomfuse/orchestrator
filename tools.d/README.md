# tools.d — your own tool specs

Drop one YAML file per CBOM generator here.  A file whose `id` matches a built-in
(`cbomkit`, `cdxgen`, `cryptobom-forge`, `oracle`, `oracle-noisy`) overrides it, so copying a
built-in from `orchestrator/data/tools/` and editing it is the easiest way to change how a tool is
run.  Files ending in `.disabled` or containing `disabled: true` are ignored.

See `docs/adding-a-tool.md` for the format and `example-tool.yaml.disabled` for a template.
