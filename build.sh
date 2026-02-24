#!/usr/bin/env bash
set -euo pipefail

echo "Building WASM package..."
wasm-pack build --target web --release --out-dir www/pkg

echo ""
echo "Building CLI tool..."
cargo build --bin pdfcrypt --release

echo ""
echo "Done!"
echo ""
echo "CLI tool: ./target/release/pdfcrypt"
echo "  pdfcrypt lock   <in.pdf> <out.pdf> --user-password <pw> [--owner-password <pw>]"
echo "  pdfcrypt unlock <in.pdf> <out.pdf> --password <pw>"
echo ""
echo "Web app: serve the www/ directory, for example:"
echo "  python3 -m http.server 8080 -d www"
echo "  Then open http://localhost:8080"
