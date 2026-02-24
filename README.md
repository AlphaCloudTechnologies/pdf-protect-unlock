# PDF Protect & Unlock

A client-side web application for adding and removing PDF password protection.
Built with Rust (compiled to WebAssembly) and vanilla HTML/CSS/JS.

**All processing happens locally in your browser — your files never leave your machine.**

## Features

- **Unlock PDF** — Remove password protection from an encrypted PDF
- **Protect PDF** — Add password protection (128-bit RC4 encryption) to a PDF
- Drag-and-drop file upload
- Modern, responsive dark UI

## Prerequisites

- [Rust](https://rustup.rs/) with the `wasm32-unknown-unknown` target
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)

```bash
rustup target add wasm32-unknown-unknown
cargo install wasm-pack
```

## Build

```bash
chmod +x build.sh
./build.sh
```

## Run

Serve the `www/` directory with any HTTP server (WASM requires HTTP, not `file://`):

```bash
python3 -m http.server 8080 -d www
```

Then open [http://localhost:8080](http://localhost:8080).

## Encryption Details

- Uses the PDF Standard Security Handler (V=2, R=3)
- 128-bit RC4 encryption
- Compatible with all major PDF readers (Adobe Acrobat, Preview, Chrome, Firefox, etc.)

## Limitations

- Only supports RC4 encryption (V=1/V=2, R=2/R=3). AES-encrypted PDFs (V=4/V=5) are not currently supported.
- Very large PDFs may be slow to process in the browser due to WebAssembly memory constraints.
