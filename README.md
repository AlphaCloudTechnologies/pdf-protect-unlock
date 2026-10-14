# PDF Protect & Unlock

A client-side web application for adding and removing PDF password protection.
Built with Rust (compiled to WebAssembly) and vanilla HTML/CSS/JS.

**All processing happens locally in your browser — your files never leave your machine.**

## Features

- **Unlock PDF** — Remove password protection from an encrypted PDF: RC4 (40–128 bit),
  AES-128 or AES-256. A PDF with only an owner password (it opens freely but
  restricts printing or editing) unlocks with no password at all
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

**Protect** writes the PDF Standard Security Handler (V=2, R=3) with 128-bit RC4
encryption, which every major PDF reader opens (Adobe Acrobat, Preview, Chrome,
Firefox, etc.).

**Unlock** reads every revision of the Standard Security Handler:

| /V | /R | Encryption |
| --- | --- | --- |
| 1, 2 | 2, 3 | RC4, 40–128 bit |
| 4 | 4 | AES-128 (AESV2) or RC4-128 crypt filters |
| 5 | 5 | AES-256, Adobe's deprecated extension level 3 |
| 5 | 6 | AES-256 (PDF 2.0), what current Acrobat writes |

Objects are decrypted as lopdf reads them, before it unpacks object streams, so
files that keep their objects in compressed object streams (most PDFs written
since PDF 1.5) come through whole. The unlocked file is written with a classic
cross-reference table.

## Limitations

- The password must be known. Nothing here recovers or bypasses one.
- PDFs encrypted to a digital certificate (the public-key security handler)
  are refused, since there is no password to enter.
- Passwords for AES-256 files are used as UTF-8 without SASLprep normalization,
  which only matters for unusual Unicode passwords.
- Very large PDFs may be slow to process in the browser due to WebAssembly memory constraints.

## Tests

`./test.sh` builds the CLI, generates PDFs with Ghostscript, ps2pdf,
ImageMagick, qpdf, pdftk, mutool and LibreOffice, and checks lock and unlock
against those tools. Unlocked output must pass `qpdf --check` with no
warnings, no longer be encrypted, and have the same text as the original.
