use crate::manifest::{self, Manifest, MANIFEST_VERSION};
use crate::VerifyArgs;
use flate2::read::GzDecoder;
use std::path::{Path, PathBuf};

use super::package::{DB_ASSET, DEMO_ASSET};

/// Re-verify a dist/ directory the way a client install must: asset checksums,
/// per-file hashes, recomputed snapshot_id, format/version sanity.
pub fn cmd_verify(args: &VerifyArgs) {
    let dist = PathBuf::from(&args.dist);
    let mut failures = 0usize;

    let manifest_path = dist.join("manifest.json");
    let m: Manifest = match std::fs::read_to_string(&manifest_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
    {
        Some(m) => m,
        None => {
            eprintln!("[verify] FAIL: missing or malformed {}", manifest_path.display());
            std::process::exit(1);
        }
    };

    if m.manifest_version != MANIFEST_VERSION {
        eprintln!(
            "[verify] FAIL: manifest_version {} != supported {}",
            m.manifest_version, MANIFEST_VERSION
        );
        failures += 1;
    }

    // ── Asset checksums (sha256sum -c equivalent) ──
    for asset in [DB_ASSET, DEMO_ASSET] {
        let path = dist.join(asset);
        if !path.exists() {
            if asset == DEMO_ASSET && m.demo_blob.is_none() {
                continue;
            }
            eprintln!("[verify] FAIL: missing asset {}", asset);
            failures += 1;
            continue;
        }
        match check_asset_sha(&path) {
            Ok(true) => eprintln!("[verify] OK: {} checksum", asset),
            Ok(false) => {
                eprintln!("[verify] FAIL: {} checksum mismatch", asset);
                failures += 1;
            }
            Err(e) => {
                eprintln!("[verify] FAIL: {}: {}", asset, e);
                failures += 1;
            }
        }
    }

    // ── Unpack db tarball, verify per-file hashes + snapshot_id ──
    let tmp = match tempdir_in(&dist) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("[verify] FAIL: cannot create temp dir: {}", e);
            std::process::exit(1);
        }
    };
    if let Err(e) = untar_gz(&dist.join(DB_ASSET), &tmp) {
        eprintln!("[verify] FAIL: unpack {}: {}", DB_ASSET, e);
        let _ = std::fs::remove_dir_all(&tmp);
        std::process::exit(1);
    }

    for (name, entry) in &m.files {
        let path = tmp.join(name);
        if !path.exists() {
            eprintln!("[verify] FAIL: {} listed in manifest but absent from tarball", name);
            failures += 1;
            continue;
        }
        match manifest::sha256_file(&path) {
            Ok((sha, bytes)) if sha == entry.sha256 && bytes == entry.bytes => {}
            Ok(_) => {
                eprintln!("[verify] FAIL: {} hash/size mismatch", name);
                failures += 1;
            }
            Err(e) => {
                eprintln!("[verify] FAIL: {}: {}", name, e);
                failures += 1;
            }
        }
    }
    eprintln!("[verify] OK: {} file hashes checked", m.files.len());

    match manifest::snapshot_id(&tmp) {
        Ok(sid) if sid == m.snapshot_id => eprintln!("[verify] OK: snapshot_id matches"),
        Ok(sid) => {
            eprintln!(
                "[verify] FAIL: snapshot_id mismatch (manifest {}, computed {})",
                m.snapshot_id, sid
            );
            failures += 1;
        }
        Err(e) => {
            eprintln!("[verify] FAIL: snapshot_id: {}", e);
            failures += 1;
        }
    }

    let _ = std::fs::remove_dir_all(&tmp);

    if failures > 0 {
        eprintln!("[verify] FAILED with {} error(s)", failures);
        std::process::exit(1);
    }
    eprintln!(
        "[verify] PASS — snapshot {} ({} nodes, {} edges, engine {})",
        m.snapshot_id, m.node_count, m.edge_count, m.engine_rev
    );
}

fn check_asset_sha(asset: &Path) -> std::io::Result<bool> {
    let sha_file = asset.with_file_name(format!(
        "{}.sha256",
        asset.file_name().unwrap().to_str().unwrap()
    ));
    let expected = std::fs::read_to_string(&sha_file)?;
    let expected = expected.split_whitespace().next().unwrap_or("");
    let (actual, _) = manifest::sha256_file(asset)?;
    Ok(actual == expected)
}

fn untar_gz(asset: &Path, dst: &Path) -> std::io::Result<()> {
    let file = std::fs::File::open(asset)?;
    let mut archive = tar::Archive::new(GzDecoder::new(file));
    archive.unpack(dst)
}

/// Minimal unique temp dir under `base` (no extra deps; not for concurrent use).
fn tempdir_in(base: &Path) -> std::io::Result<PathBuf> {
    let pid = std::process::id();
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let dir = base.join(format!(".verify-{pid}-{nanos}"));
    std::fs::create_dir_all(&dir)?;
    Ok(dir)
}
