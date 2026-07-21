use clap::{Args, Parser, Subcommand};

pub mod builder;
pub mod commands;
pub mod ingest;
pub mod manifest;

/// Engine revision this pipeline is pinned to. Must match the
/// `vulngraph-engine` git tag in Cargo.toml — bump both together.
pub const ENGINE_REV: &str = "engine-v0.1.0";

/// VulnGraph data pipeline — ingest sources, build the graph, package releases.
///
/// This binary never serves queries. It produces the graph database that the
/// vulngraph serve side installs from published data releases.
#[derive(Parser)]
#[command(name = "vulngraph-data")]
#[command(version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Build graph database from downloaded data sources
    Build(BuildArgs),

    /// Export single binary blob for the WASM demo
    ExportDemo(ExportDemoArgs),

    /// Package a built database + demo blob into a release dist/ directory
    Package(PackageArgs),

    /// Verify a dist/ directory against its manifest (mirrors client install rules)
    Verify(VerifyArgs),

    /// List package external IDs from a built database (for deps.dev fetch)
    ListPackages(ListPackagesArgs),
}

#[derive(Args)]
pub struct BuildArgs {
    /// Path to downloaded data sources
    #[arg(long, default_value = "./research/downloads")]
    pub sources: String,

    /// Output directory for the graph database
    #[arg(long, default_value = "./builds/vulngraph.db")]
    pub output: String,
}

#[derive(Args)]
pub struct ExportDemoArgs {
    /// Path to the graph database directory
    #[arg(long, env = "VULNGRAPH_DB", default_value = "./builds/vulngraph.db")]
    pub db: String,

    /// Output path for the binary blob
    #[arg(long, default_value = "./builds/vulngraph.bin")]
    pub output: String,
}

#[derive(Args)]
pub struct PackageArgs {
    /// Path to the built graph database directory
    #[arg(long, default_value = "./builds/vulngraph.db")]
    pub db: String,

    /// Path to the exported demo blob (version.json must sit next to it)
    #[arg(long, default_value = "./builds/vulngraph.bin")]
    pub demo_blob: String,

    /// Output directory for release assets
    #[arg(long, default_value = "./dist")]
    pub out: String,
}

#[derive(Args)]
pub struct VerifyArgs {
    /// dist/ directory containing release assets + manifest.json
    #[arg(long, default_value = "./dist")]
    pub dist: String,
}

#[derive(Args)]
pub struct ListPackagesArgs {
    /// Path to the graph database directory
    #[arg(long, env = "VULNGRAPH_DB", default_value = "./builds/vulngraph.db")]
    pub db: String,

    /// Filter by ecosystem prefix (npm, PyPI, Maven, Go, crates.io, NuGet)
    #[arg(long, short)]
    pub ecosystem: Option<String>,

    /// Maximum results
    #[arg(long, short, default_value = "20000")]
    pub limit: usize,
}

fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Build(args) => commands::build::cmd_build(&args),
        Commands::ExportDemo(args) => commands::export_demo::cmd_export_demo(&args.db.clone(), &args),
        Commands::Package(args) => commands::package::cmd_package(&args),
        Commands::Verify(args) => commands::verify::cmd_verify(&args),
        Commands::ListPackages(args) => commands::list_packages::cmd_list_packages(&args),
    }
}
