use crate::manifest::{
    self, DemoBlob, FileEntry, Manifest, MANIFEST_VERSION, SEMANTIC_FILES, SIDECAR_FILES,
};
use crate::{PackageArgs, ENGINE_REV};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub const DB_ASSET: &str = "vulngraph-db.tar.gz";
pub const DEMO_ASSET: &str = "vulngraph-demo.tar.gz";

pub fn cmd_package(args: &PackageArgs) {
    let db_dir = PathBuf::from(&args.db);
    let demo_blob = PathBuf::from(&args.demo_blob);
    let out_dir = PathBuf::from(&args.out);

    if !db_dir.is_dir() {
        eprintln!("[package] ERROR: db dir not found: {}", db_dir.display());
        std::process::exit(1);
    }
    std::fs::create_dir_all(&out_dir).expect("create out dir");

    // ── Hash every shipped db file ────────────────
    let mut files: BTreeMap<String, FileEntry> = BTreeMap::new();
    for name in SEMANTIC_FILES.iter().chain(SIDECAR_FILES) {
        let path = db_dir.join(name);
        if !path.exists() {
            eprintln!("[package] WARN: {} missing from db dir", name);
            continue;
        }
        let (sha256, bytes) = manifest::sha256_file(&path).expect("hash db file");
        files.insert(name.to_string(), FileEntry { bytes, sha256 });
    }
    let snapshot_id = manifest::snapshot_id(&db_dir).expect("snapshot_id");
    eprintln!("[package] snapshot_id: {}", snapshot_id);

    // ── Read meta.json + freshness.json ───────────
    let meta: serde_json::Value = read_json(&db_dir.join("meta.json")).unwrap_or_default();
    let freshness: serde_json::Value = read_json(&db_dir.join("freshness.json")).unwrap_or_default();
    let created_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    // ── Db tarball: files at archive root ─────────
    let db_asset = out_dir.join(DB_ASSET);
    tar_gz(&db_asset, files.keys().map(|n| (db_dir.join(n), n.clone())));
    write_sha256(&db_asset);
    eprintln!(
        "[package] {} ({:.1} MB)",
        db_asset.display(),
        size_mb(&db_asset)
    );

    // ── Demo tarball: blob + blob.gz + version.json ──
    let demo = if demo_blob.exists() {
        let gz_path = demo_blob.with_extension("bin.gz");
        gzip_file(&demo_blob, &gz_path);
        let version_json = demo_blob.parent().unwrap().join("version.json");
        let mut entries = vec![
            (demo_blob.clone(), "vulngraph.bin".to_string()),
            (gz_path.clone(), "vulngraph.bin.gz".to_string()),
        ];
        if version_json.exists() {
            entries.push((version_json, "version.json".to_string()));
        } else {
            eprintln!("[package] WARN: version.json missing next to demo blob");
        }
        let demo_asset = out_dir.join(DEMO_ASSET);
        tar_gz(&demo_asset, entries.into_iter());
        write_sha256(&demo_asset);
        eprintln!(
            "[package] {} ({:.1} MB)",
            demo_asset.display(),
            size_mb(&demo_asset)
        );

        let (sha256, bytes) = manifest::sha256_file(&demo_blob).expect("hash demo blob");
        Some(DemoBlob {
            file: "vulngraph.bin".to_string(),
            bytes,
            sha256,
            vgdb_version: 3,
        })
    } else {
        eprintln!(
            "[package] WARN: demo blob not found at {} — skipping demo asset",
            demo_blob.display()
        );
        None
    };

    // ── Manifest ──────────────────────────────────
    let m = Manifest {
        manifest_version: MANIFEST_VERSION,
        snapshot_id,
        format_version: meta.get("version").and_then(|v| v.as_u64()).unwrap_or(0),
        engine_rev: ENGINE_REV.to_string(),
        created_at: manifest::iso8601_utc(created_secs),
        node_count: meta.get("node_count").and_then(|v| v.as_u64()).unwrap_or(0),
        edge_count: meta.get("edge_count").and_then(|v| v.as_u64()).unwrap_or(0),
        files,
        sources: freshness
            .get("sources")
            .cloned()
            .unwrap_or(serde_json::Value::Null),
        demo_blob: demo,
    };
    let manifest_path = out_dir.join("manifest.json");
    std::fs::write(&manifest_path, serde_json::to_string_pretty(&m).unwrap())
        .expect("write manifest");
    eprintln!("[package] {}", manifest_path.display());
    eprintln!("[package] done — dist ready at {}", out_dir.display());
}

fn read_json(path: &Path) -> Option<serde_json::Value> {
    serde_json::from_str(&std::fs::read_to_string(path).ok()?).ok()
}

fn tar_gz(out: &Path, entries: impl Iterator<Item = (PathBuf, String)>) {
    let file = std::fs::File::create(out).expect("create tarball");
    let enc = GzEncoder::new(file, Compression::default());
    let mut tar = tar::Builder::new(enc);
    for (path, name) in entries {
        tar.append_path_with_name(&path, &name)
            .unwrap_or_else(|e| panic!("tar {}: {}", path.display(), e));
    }
    tar.into_inner()
        .expect("finish tar")
        .finish()
        .expect("finish gzip");
}

fn gzip_file(src: &Path, dst: &Path) {
    let mut input = std::fs::File::open(src).expect("open blob");
    let out = std::fs::File::create(dst).expect("create blob.gz");
    let mut enc = GzEncoder::new(out, Compression::best());
    std::io::copy(&mut input, &mut enc).expect("gzip blob");
    enc.finish().expect("finish blob.gz");
}

/// Write `<asset>.sha256` in `sha256sum -c` format (name relative to dist/).
fn write_sha256(asset: &Path) {
    let (hash, _) = manifest::sha256_file(asset).expect("hash asset");
    let name = asset.file_name().unwrap().to_str().unwrap();
    std::fs::write(
        asset.with_file_name(format!("{name}.sha256")),
        format!("{hash}  {name}\n"),
    )
    .expect("write sha256");
}

fn size_mb(path: &Path) -> f64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0) as f64 / 1_048_576.0
}
