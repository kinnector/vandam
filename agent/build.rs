use std::path::PathBuf;

fn main() {
    // vandam-core (the Linux engine) is a sibling checkout of this repo
    // (<workspace>/vandam/agent -> <workspace>/vandam-core), built with `cmake -B build`;
    // KINNECTOR_CORE_DIR points at another checkout, KINNECTOR_CORE_LIB_DIR at another build of it.
    let manifest = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let core = std::env::var("KINNECTOR_CORE_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| manifest.join("../../vandam-core"));
    println!("cargo:rerun-if-env-changed=KINNECTOR_CORE_DIR");
    let lib_dir = std::env::var("KINNECTOR_CORE_LIB_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|_| core.join("build/lib"));
    println!("cargo:rerun-if-env-changed=KINNECTOR_CORE_LIB_DIR");
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    // Link against the static archive of kinnector-core and all of its dependencies dynamically
    println!("cargo:rustc-link-lib=static=kinnector-core");
    println!("cargo:rustc-link-lib=dylib=stdc++");
    println!("cargo:rustc-link-lib=dylib=bpf");
    println!("cargo:rustc-link-lib=dylib=elf");
    println!("cargo:rustc-link-lib=dylib=z");
    println!("cargo:rustc-link-lib=dylib=zstd");

    // Rebuild if the library changes
    println!("cargo:rerun-if-changed={}", lib_dir.join("libkinnector-core.a").display());

    core_abi(&core.join("include/kinnector/telemetry.h"));

    // Compile gRPC proto
    tonic_build::compile_protos("proto/vandam.proto").unwrap();
    // The deep-audit agentic loop's own gRPC service (from vandam); see
    // proto/audit.proto's doc comment for why it is separate from vandam.proto.
    tonic_build::compile_protos("proto/audit.proto").unwrap();
}

/// Reads the frame sizes core's telemetry.h asserts (`static_assert(sizeof(TelemetryHeader) ==
/// N, ...)` and the same for `TelemetryEvent`) into `$OUT_DIR/core_abi.rs`, which `types.rs`
/// checks its own mirror against: a core ABI change then fails this build instead of misframing
/// the telemetry stream at run time.
fn core_abi(header: &PathBuf) {
    println!("cargo:rerun-if-changed={}", header.display());
    let text = std::fs::read_to_string(header)
        .unwrap_or_else(|e| panic!("cannot read core's {}: {}", header.display(), e));
    let asserted = |ty: &str| -> usize {
        let needle = format!("static_assert(sizeof({}) ==", ty);
        let at = text
            .find(&needle)
            .unwrap_or_else(|| panic!("{} asserts no sizeof({})", header.display(), ty));
        text[at + needle.len()..]
            .trim_start()
            .split(|c: char| !c.is_ascii_digit())
            .next()
            .and_then(|n| n.parse().ok())
            .unwrap_or_else(|| panic!("cannot read sizeof({}) from {}", ty, header.display()))
    };
    let out = PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("core_abi.rs");
    std::fs::write(
        out,
        format!(
            "pub const CORE_HEADER_SIZE: usize = {};\npub const CORE_EVENT_SIZE: usize = {};\n",
            asserted("TelemetryHeader"),
            asserted("TelemetryEvent")
        ),
    )
    .unwrap();
}
