# VROLL CLI

VROLL is a small, auditable command-line utility for encrypting and decrypting
folders as `.vroll` archives. It uses the PyCA `cryptography` package with
AES-256-GCM for authenticated encryption and PBKDF2-HMAC-SHA256 for key
derivation.

---

## Highlights

- Interactive workflow for encrypting a folder or decrypting an existing
  `.vroll` file.
- Authenticated encryption with AES-256-GCM and 200k PBKDF2 iterations.
- Stream-based processing (1 MiB chunks) to handle large inputs.
- Deterministic ZIP creation (sorted entries) for reproducible archives.
- Safe extraction that blocks zip-slip path traversal attempts.
- Output files and directories are deduplicated automatically to avoid
  accidental overwrites.

---

## Requirements

- Python 3.8 or newer.
- The `cryptography` package (`pip install cryptography`).

Creating a virtual environment is recommended:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install --upgrade pip
pip install cryptography
```

---

## Usage

Run the tool from the repository root:

```powershell
python .\main.py
```

### Encrypt a folder

1. Choose `1`, `e`, or `encrypt`.
2. Provide the folder path to archive.
3. Enter and confirm a passphrase.
4. The script creates a timestamped ZIP, encrypts it, and stores a `.vroll`
   file next to the original folder. Temporary artifacts are removed
   automatically.

### Decrypt a `.vroll`

1. Choose `2`, `d`, or `decrypt`.
2. Provide the path to the `.vroll` file.
3. Enter the passphrase.
4. The script writes a ZIP archive in the current working directory and
   extracts it into `<name>_decrypted`, adding numeric suffixes when needed.

---

## File Format

Each `.vroll` file is a single self-contained binary blob:

1. 5 bytes: ASCII magic `VROLL`
2. 1 byte: format version (`0x01`)
3. 16 bytes: PBKDF2 salt
4. 12 bytes: AES-GCM nonce
5. N bytes: ciphertext
6. 16 bytes: GCM authentication tag

Key derivation uses PBKDF2-HMAC-SHA256 with 200,000 iterations and a 32-byte
output key.

---

## Troubleshooting

- **Missing dependency** – Run `pip install cryptography`.
- **Authentication failed** – The passphrase is wrong or the file is corrupted.
  The decrypted ZIP is removed when this happens.
- **Unsafe path detected** – The archive contains files that would extract
  outside the chosen directory. Inspect the source archive before retrying.

---

## Development Notes

- Core functionality lives in `main.py`.
- The script is intentionally interactive; automation wrappers can call
  `encrypt_file` / `decrypt_file` directly.
- Exclude local virtual environments, build artifacts, and test fixtures when
  publishing to GitHub (see `.gitignore`).

---

## License

Add a license that matches your organisation's needs (e.g., MIT, Apache-2.0).
