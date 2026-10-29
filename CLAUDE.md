# vandam - agent instructions

vandam is a Linux server security agent: `vandamd` (`agent/`), the `vandam` CLI (`cli/`), the
detection rules (`rules/`) and the RASP integrations (`integrations/`). It builds on
[vandam-core](https://github.com/kinnector/vandam-core), the kernel engine, expected as a sibling
checkout (`../vandam-core`, built with `cmake -B build`; `KINNECTOR_CORE_DIR` /
`KINNECTOR_CORE_LIB_DIR` override). See `README.md` for what it does and how to build it.

## Safety

`vandamd` loads BPF LSM programs that can refuse exec, open, chmod and signals system-wide. Never
run it, or a test that attaches enforcement, on a machine you depend on: use a VM. Loading BPF
(verification only) is harmless; attaching is not. Tests that need root are marked as such; the
default `cargo test` runs without it.

## The kernel event stream

vandam-core writes fixed-size frames on a stream socket. `agent/src/types.rs` mirrors
`vandam-core/include/kinnector/telemetry.h` exactly: header, union size and every detail struct.
`agent/build.rs` reads the sizes that header `static_assert`s and the build fails when they differ,
so a vandam-core ABI change breaks the build instead of misframing every event at run time. Read
event numbers through `TelemetryHeader::event_type()`, never straight into the enum: vandam-core
sends numbers this agent has no arm for.

## Rules are data, not code

Service signatures, match lists and policies live in `rules/` as JSON and are read through one
source (`agent/src/rules/source.rs`): the repo folder in a debug build, a signed bundle held in
memory in a release build. Do not hardcode match lists or classification tables in source; add
them to `rules/` and read them through `agent/src/rules/`. A release build reads no rules folder.

## Shared kernel object

vandam-core's BPF object serves more than one product, gated by `deployment_mode` (`MODE_WARDEN`
is vandam's). The pin directory `/sys/fs/bpf/warden/` and the `MODE_WARDEN` name are part of that
shared ABI: they keep their names.

## Tests

`cargo test` at the workspace root. `agent/tests/test_signatures_podman.rs` starts containers
with podman and skips itself unless run as root; `agent/tests/test_cloud_rules_live.rs` needs a
running rules server and is `#[ignore]`. The integrations have their own build steps (`phpize` for PHP, Maven for the
Java agent).
