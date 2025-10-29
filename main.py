#!/usr/bin/env python3
"""
main.py - Encrypt and decrypt .vroll archives using PyCA cryptography.

Modes (case insensitive):
  1 / e / encrypt   -> Zip folder -> Encrypt -> Save .vroll inside folder
  2 / d / decrypt   -> Decrypt .vroll -> .zip in CWD
                     -> Extract to ./<name>_decrypted[/N]

Format (single file, no sidecar):
  [5B MAGIC 'VROLL'][1B VERSION=0x01][16B SALT][12B NONCE]
  [CIPHERTEXT...][16B GCM TAG]

Key derivation: PBKDF2-HMAC-SHA256 (200k iterations) -> 32-byte AES key
Authenticated encryption: AES-256-GCM
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unicodedata
import zipfile
from getpass import getpass
from pathlib import Path

# --- Third-party (install: pip install cryptography) ---
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.exceptions import InvalidTag
except ModuleNotFoundError:
    sys.exit(
        "[error] Missing dependency: 'cryptography'\n"
        "   Install it with:\n"
        "     pip install cryptography\n"
    )

# ------------------------- Constants / Format ------------------------------

MAGIC = b"VROLL"        # 5 bytes
VERSION = 0x01          # 1 byte
PBKDF2_ITERS = 200_000
KEY_LEN = 32            # 256-bit
SALT_LEN = 16
NONCE_LEN = 12          # GCM standard recommended length
TAG_LEN = 16
CHUNK_SIZE = 1024 * 1024  # 1 MiB chunks for streaming
HEADER_LEN = len(MAGIC) + 1 + SALT_LEN + NONCE_LEN

ENCRYPT_ALIASES = {"1", "e", "encrypt"}
DECRYPT_ALIASES = {"2", "d", "decrypt"}

# ------------------------------ Logging -----------------------------------


def log(msg: str) -> None:
    """Write a console message and flush immediately."""
    print(msg, flush=True)


# ------------------------------ Helpers -----------------------------------


def normalize_passphrase(raw: str) -> str:
    """
    Normalize a user-supplied passphrase across platforms and locales.

    Args:
        raw: Raw passphrase string as entered by the user.

    Returns:
        A normalized and trimmed passphrase suitable for key derivation.
    """
    return unicodedata.normalize("NFKC", raw).strip()



def path_is_relative_to(path: Path, base: Path) -> bool:
    """
    Determine whether *path* is located within *base*.

    Uses pathlib.Path.is_relative_to when available (Py>=3.9).
    Falls back to a relative_to try/except for older Python versions.
    """
    try:
        # Python 3.9+
        return path.is_relative_to(base)  # type: ignore[attr-defined]
    except AttributeError:
        try:
            path.relative_to(base)
        except ValueError:
            return False
        return True



def ensure_unique_file_path(path: Path) -> Path:
    """
    Return a non-conflicting file path by appending (N) if needed.

    Args:
        path: Target file path.

    Returns:
        Either the original path (if unused) or a suffixed variant.
    """
    candidate = path
    counter = 1
    while candidate.exists():
        stem = path.stem
        suffix = path.suffix
        candidate = path.with_name(f"{stem}({counter}){suffix}")
        counter += 1
    return candidate



def ensure_unique_directory_path(path: Path) -> Path:
    """
    Return a non-conflicting directory path by appending _N as needed.

    Args:
        path: Target directory path.

    Returns:
        Either the original path (if unused) or a suffixed variant.
    """
    candidate = path
    counter = 1
    while candidate.exists():
        candidate = path.parent / f"{path.name}_{counter}"
        counter += 1
    return candidate


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte AES key from the passphrase using PBKDF2-HMAC-SHA256.

    Args:
        passphrase: Human supplied passphrase.
        salt: Cryptographically random salt associated with the ciphertext.

    Returns:
        A 32-byte key ready for AES-256 operations.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def safe_extract_zip(zip_path: Path, dest_dir: Path) -> None:
    """
    Extract a ZIP archive while protecting against path traversal attacks.

    Args:
        zip_path: The ZIP archive produced during encryption.
        dest_dir: Destination directory where files are extracted.

    Raises:
        SystemExit: If the archive contains unsafe paths (zip-slip attempt).
    """
    log(f"[extract] Target directory: {dest_dir}")
    dest_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        base = dest_dir.resolve()
        for info in zf.infolist():
            target = (dest_dir / info.filename).resolve()
            if not path_is_relative_to(target, base):
                sys.exit("Unsafe path detected in archive; aborting extraction.")
        zf.extractall(dest_dir)
    log("[extract] Completed successfully.")


# ------------------------------ Zip Build ---------------------------------


def make_zip(src: Path, tmp_dir: Path) -> Path:
    """
    Create a ZIP archive of the source directory inside a temporary location.

    Args:
        src: Directory whose contents should be archived.
        tmp_dir: Temporary directory used to stage the intermediate ZIP file.

    Returns:
        Path to the created ZIP archive.
    """
    timestamp = time.strftime("%Y%m%d-%H%M%S")
    zip_path = tmp_dir / f"{src.name}-{timestamp}.zip"
    log(f"[zip] Creating archive: {zip_path.name}")
    with zipfile.ZipFile(
        zip_path,
        mode="w",
        compression=zipfile.ZIP_DEFLATED,
        compresslevel=9,
    ) as zf:
        for root, dirs, files in os.walk(src):
            dirs.sort()
            rpath = Path(root)
            for fn in sorted(files):
                fpath = rpath / fn
                arcname = fpath.relative_to(src)
                zf.write(fpath, arcname)
    log(f"[zip] Archive created: {zip_path.name}")
    return zip_path


# --------------------------- Encrypt / Decrypt -----------------------------


def encrypt_file(plain_path: Path, out_vroll: Path, passphrase: str) -> None:
    """
    Encrypt a ZIP archive into the .vroll container format.

    Args:
        plain_path: Path to the ZIP archive produced from the source directory.
        out_vroll: Destination path for the encrypted .vroll file.
        passphrase: Normalized passphrase supplied by the user.
    """
    log("[encrypt] Starting AES-256-GCM encryption.")
    salt = os.urandom(SALT_LEN)
    key = derive_key(passphrase, salt)
    nonce = os.urandom(NONCE_LEN)

    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce),
    ).encryptor()

    with out_vroll.open("wb") as out_f:
        # Header: MAGIC | VERSION | SALT | NONCE
        out_f.write(MAGIC)
        out_f.write(bytes([VERSION]))
        out_f.write(salt)
        out_f.write(nonce)

        # Ciphertext streaming
        with plain_path.open("rb") as in_f:
            while True:
                chunk = in_f.read(CHUNK_SIZE)
                if not chunk:
                    break
                ct = encryptor.update(chunk)
                if ct:
                    out_f.write(ct)

        # Finalize + write tag
        out_f.write(encryptor.finalize())
        out_f.write(encryptor.tag)

    log(f"[encrypt] Output written: {out_vroll}")


def decrypt_file(in_vroll: Path, out_zip: Path, passphrase: str) -> None:
    """
    Decrypt a .vroll file back into its ZIP archive representation.

    Args:
        in_vroll: Path to the encrypted .vroll file.
        out_zip: Destination where the decrypted ZIP should be written.
        passphrase: Normalized passphrase supplied by the user.

    Raises:
        SystemExit: If the input does not conform to the expected format.
    """
    log("[decrypt] Starting AES-256-GCM decryption.")

    filesize = in_vroll.stat().st_size
    if filesize < HEADER_LEN + TAG_LEN:
        sys.exit("File too small to be a valid .vroll.")

    with in_vroll.open("rb") as f:
        magic = f.read(len(MAGIC))
        if len(magic) != len(MAGIC) or magic != MAGIC:
            sys.exit("Invalid file header (magic mismatch).")

        version_raw = f.read(1)
        if len(version_raw) != 1:
            sys.exit("Missing .vroll version byte.")
        version = version_raw[0]
        if version != VERSION:
            sys.exit(f"Unsupported .vroll version: {version}.")

        salt = f.read(SALT_LEN)
        if len(salt) != SALT_LEN:
            sys.exit("Incomplete salt in header.")

        nonce = f.read(NONCE_LEN)
        if len(nonce) != NONCE_LEN:
            sys.exit("Incomplete nonce in header.")

        # Remaining bytes: ciphertext...tag
        remaining = f.read()

    if len(remaining) < TAG_LEN:
        sys.exit("Missing authentication tag.")
    ciphertext = remaining[:-TAG_LEN]
    tag = remaining[-TAG_LEN:]

    key = derive_key(passphrase, salt)
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(nonce, tag),
    ).decryptor()

    # Stream-decrypt to file
    auth_failed = False
    with out_zip.open("wb") as out_f:
        # Process in chunks from ciphertext bytes
        start = 0
        total = len(ciphertext)
        while start < total:
            end = min(start + CHUNK_SIZE, total)
            pt = decryptor.update(ciphertext[start:end])
            if pt:
                out_f.write(pt)
            start = end

        try:
            final_chunk = decryptor.finalize()
        except InvalidTag:
            auth_failed = True
            final_chunk = b""

        if final_chunk:
            out_f.write(final_chunk)

    if auth_failed:
        if out_zip.exists():
            try:
                out_zip.unlink()
            except OSError as err:
                log(f"[warn] Could not remove partial output {out_zip}: {err}")
        sys.exit(
            "Authentication failed. Passphrase may be incorrect or data is corrupted."
        )

    log(f"[decrypt] ZIP written: {out_zip}")


# ------------------------------- Flows ------------------------------------


def prompt_mode() -> str:
    """
    Prompt the user for the desired operation mode.

    Returns:
        The string literal 'encrypt' or 'decrypt'.

    Raises:
        SystemExit: If the provided choice is not recognized.
    """
    log(
        "\nSelect mode:\n"
        "  [1] Encrypt   (e / encrypt)\n"
        "  [2] Decrypt   (d / decrypt)\n"
    )
    choice = input("Choice: ").strip().lower()
    if choice in ENCRYPT_ALIASES:
        return "encrypt"
    if choice in DECRYPT_ALIASES:
        return "decrypt"
    sys.exit("Invalid choice. Use 1/e/encrypt or 2/d/decrypt.")


def run_encrypt() -> None:
    """
    Execute the interactive encryption flow.

    The user is prompted for a source directory and passphrase,
    resulting in a .vroll file placed alongside the original folder.
    """
    folder_str = input("Folder to encrypt: ").strip()
    src_dir = Path(folder_str).expanduser().resolve()
    log(f"[encrypt] Source directory: {src_dir}")
    if not src_dir.exists():
        sys.exit("Path does not exist.")
    if not src_dir.is_dir():
        sys.exit("Path is not a directory.")

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)
        zip_path = make_zip(src_dir, tmp_dir)
        vroll_path = src_dir / (zip_path.stem + ".vroll")
        vroll_path = ensure_unique_file_path(vroll_path)

        pw1 = normalize_passphrase(getpass("Enter encryption passphrase: "))
        pw2 = normalize_passphrase(getpass("Re-enter passphrase: "))
        if not pw1 or pw1 != pw2:
            sys.exit("Passphrases did not match or were empty.")

        encrypt_file(zip_path, vroll_path, pw1)

    log("[encrypt] Temporary artifacts removed.")
    log("\nEncryption complete.")
    log(f"[encrypt] Output: {vroll_path}")
    log("[encrypt] AES-GCM provides confidentiality and tamper detection.")


def run_decrypt() -> None:
    """
    Execute the interactive decryption flow.

    The user is prompted for a .vroll file and passphrase. The resulting
    ZIP is saved in the current working directory and extracted to a
    sibling folder with a _decrypted suffix.
    """
    vroll_str = input("Enter .vroll file path to decrypt: ").strip()
    vroll_path = Path(vroll_str).expanduser().resolve()
    log(f"[decrypt] Input file: {vroll_path}")
    if not vroll_path.exists() or not vroll_path.is_file():
        sys.exit(".vroll file not found.")

    cwd = Path.cwd()
    out_zip = cwd / f"{vroll_path.stem}.zip"
    out_zip = ensure_unique_file_path(out_zip)

    pw = normalize_passphrase(getpass("Enter decryption passphrase: "))
    if not pw:
        sys.exit("Empty passphrase not allowed.")

    decrypt_file(vroll_path, out_zip, pw)

    dest = cwd / f"{vroll_path.stem}_decrypted"
    dest = ensure_unique_directory_path(dest)

    safe_extract_zip(out_zip, dest)

    log("\nDecryption complete.")
    log(f"[decrypt] Extracted folder: {dest}")
    log(f"[decrypt] Decrypted ZIP retained: {out_zip}")
    log("[decrypt] Integrity verified.")


def main() -> None:
    """Entry point for the .vroll encrypt/decrypt command line tool."""
    log("main.py - Encrypt/Decrypt .vroll (PyCA cryptography)")
    operation = prompt_mode()
    if operation == "encrypt":
        run_encrypt()
    else:
        run_decrypt()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nAborted by user.")
