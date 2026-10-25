use sha2::{Digest, Sha256};
use std::{
    fs,
    path::{Path, PathBuf},
};

fn walk(root: &Path, path: &Path, files: &mut Vec<String>) {
    for entry in fs::read_dir(path).expect("Rust source directory") {
        let path = entry.expect("Rust source entry").path();
        let meta = fs::symlink_metadata(&path).expect("Rust source metadata");
        assert!(
            !meta.file_type().is_symlink(),
            "Build source contains a symlink"
        );
        if meta.is_dir() {
            walk(root, &path, files);
        } else if matches!(
            path.extension().and_then(|s| s.to_str()),
            Some("rs" | "toml" | "cmake" | "json")
        ) {
            files.push(
                path.strip_prefix(root)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}
fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap())
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    let mut files = vec![
        "Cargo.toml".to_owned(),
        "Cargo.lock".to_owned(),
        "tools/build_rust.ps1".to_owned(),
        "tools/package_rust.ps1".to_owned(),
        "tools/package_rust_linux.sh".to_owned(),
    ];
    walk(&root, &root.join("rust"), &mut files);
    files.sort();
    files.dedup();
    let mut digest = Sha256::new();
    for file in &files {
        let path = root.join(file);
        println!("cargo:rerun-if-changed={}", path.display());
        digest.update(file.as_bytes());
        digest.update([0]);
        digest.update(format!("{:x}", Sha256::digest(fs::read(path).unwrap())).as_bytes());
        digest.update(b"\n");
    }
    println!(
        "cargo:rustc-env=EMUMEE_BUILD_SOURCE_SHA256={:x}",
        digest.finalize()
    );
    println!("cargo:rustc-env=EMUMEE_BUILD_SOURCE_FILES={}", files.len());
}
