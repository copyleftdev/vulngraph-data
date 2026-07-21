default:
    @just --list

# Build the pipeline binary in release mode
build:
    cargo build --release

# Run tests
test:
    cargo test

# Full refresh: pull sources + build + package
refresh:
    ./scripts/refresh.sh

# Rebuild from existing sources (skip pulls)
rebuild:
    ./scripts/refresh.sh --rebuild-only

# Package the current build into dist/
package: build
    ./target/release/vulngraph-data package \
        --db ./builds/vulngraph.db \
        --demo-blob ./builds/vulngraph.bin \
        --out ./dist

# Verify dist/ against its manifest
verify:
    ./target/release/vulngraph-data verify --dist ./dist

# Publish dist/ as a data-YYYYMMDD GitHub Release
publish:
    ./scripts/publish.sh
