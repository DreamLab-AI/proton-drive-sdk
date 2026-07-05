//! Build-time protobuf code generation for the cross-language wire types.
//!
//! The `.proto` file lives in the upstream C# reference tree
//! (`reference/client/cs/src/protos/`) and is the source of truth for the wire
//! format used by the C#/Kotlin/Swift implementations. Upstream merged the
//! former two-file layout (`proton.sdk.proto` imported by
//! `proton.drive.sdk.proto`) into this single file, entirely under
//! `package proton.drive.sdk;` (see `reference/VENDORED.md`). It declares
//! `edition = "2023"` (protobuf editions), which
//! creates two constraints this script handles:
//!
//! 1. Parsing editions needs a modern `protoc` (>= v27). To keep the build
//!    hermetic with no system dependency, `protoc-bin-vendored` supplies a
//!    bundled `protoc` (libprotoc 31.x). protoc compiles the protos to a
//!    `FileDescriptorSet`.
//! 2. `prost-build` (0.14) does not yet understand the `editions` syntax value
//!    and panics on it. The editions features used here (file-level
//!    `utf8_validation = NONE`, default explicit presence) carry no field-level
//!    presence overrides — every singular field is a plain `LABEL_OPTIONAL`
//!    with no `proto3_optional` marker — so the descriptor is wire- and
//!    codegen-equivalent to proto3. We therefore relabel the editions files as
//!    `proto3` in the descriptor set before handing it to `prost-build`:
//!    singular scalars generate as plain fields, singular messages as
//!    `Option<_>`, repeated as `Vec<_>`, matching the intended semantics.
//!
//! Build scripts run outside the crate's runtime lint gate, so the loud
//! `expect`/`panic` failures below are intentional: a missing or malformed
//! proto source must fail the build immediately and visibly. The workspace
//! `deny`s `panic`/`expect_used`/`unwrap_used` for runtime code, but those bans
//! are about the shipped library — a build script *should* abort loudly, so we
//! opt this target (and only this target) out of those three lints.

#![allow(clippy::expect_used, clippy::unwrap_used, clippy::panic)]

use std::path::Path;

use prost::Message;
use prost_types::FileDescriptorSet;

const PROTO_INCLUDE: &str = "../../../reference/client/cs/src/protos";
const PROTO_FILES: [&str; 1] = ["proton.drive.sdk.proto"];

fn main() {
    let include = Path::new(PROTO_INCLUDE);

    // Fail loudly and clearly if the shared proto sources are absent. They are
    // present in this checkout; an absence means the layout has shifted and the
    // include path needs revisiting.
    if !include.is_dir() {
        panic!(
            "proto include directory not found: {} (resolved from crate dir {}). \
             The cross-language wire `.proto` source is expected at \
             `reference/client/cs/src/protos` relative to the repository root.",
            include.display(),
            env!("CARGO_MANIFEST_DIR"),
        );
    }

    let mut proto_paths = Vec::with_capacity(PROTO_FILES.len());
    for file in PROTO_FILES {
        let path = include.join(file);
        if !path.is_file() {
            panic!(
                "required proto source missing: {} — expected under {}",
                path.display(),
                include.display(),
            );
        }
        // Re-run codegen whenever a proto source changes.
        println!("cargo:rerun-if-changed={}", path.display());
        proto_paths.push(path);
    }
    println!("cargo:rerun-if-changed={}", include.display());
    println!("cargo:rerun-if-changed=build.rs");

    let protoc = protoc_bin_vendored::protoc_bin_path()
        .expect("protoc-bin-vendored did not provide a protoc binary for this platform");

    // Compile to a self-contained FileDescriptorSet. `--include_imports` pulls
    // in the well-known types (timestamp/any) so prost-build can resolve every
    // referenced type without a separate include path.
    let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR is set for build scripts by cargo");
    let fds_path = Path::new(&out_dir).join("proton_drive_wire.fds");

    let mut cmd = std::process::Command::new(&protoc);
    cmd.arg("--proto_path")
        .arg(include)
        .arg("--include_imports")
        .arg("--descriptor_set_out")
        .arg(&fds_path);
    for path in &proto_paths {
        cmd.arg(path);
    }
    let status = cmd
        .status()
        .expect("failed to spawn the vendored protoc binary");
    assert!(status.success(), "protoc exited with failure: {status}");

    let fds_bytes = std::fs::read(&fds_path).expect("failed to read protoc descriptor set output");
    let mut fds = FileDescriptorSet::decode(fds_bytes.as_slice())
        .expect("failed to decode FileDescriptorSet");

    // prost-build 0.14 rejects the `editions` syntax value; relabel the
    // editions files as proto3 (see module docs for why this is safe here).
    // prost-types 0.14 has no `edition` field, so the editions enum decodes as
    // an ignored unknown field — only `syntax` needs rewriting.
    for file in &mut fds.file {
        if file.syntax.as_deref() == Some("editions") {
            file.syntax = Some("proto3".to_owned());
        }
    }

    prost_build::Config::new()
        .compile_fds(fds)
        .expect("prost-build failed to generate Rust from the Proton Drive wire descriptors");
}
