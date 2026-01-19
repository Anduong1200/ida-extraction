#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
IDA Export Packager v1.0
========================
Creates a tamper-evident archive of IDA exports with manifest and signature.

Features:
- tar.gz archive with structured layout
- SHA256 file hashes in manifest
- Ed25519 signature (optional, requires PyNaCl)
- Provenance metadata

Usage:
    python package_export.py <functions.json> [--output package.tar.gz]
    python package_export.py <functions.json> --sign --keyfile mykey.pem

Output structure:
    package.tar.gz/
    ├── manifest.json
    ├── data/
    │   ├── functions.json
    │   └── (additional files)
    ├── provenance.json
    └── signature.sig (if signed)
"""

import argparse
import hashlib
import json
import os
import sys
import tarfile
import tempfile
import time
import uuid
from io import BytesIO

# Optional: PyNaCl for Ed25519 signing
try:
    from nacl.signing import SigningKey, VerifyKey
    from nacl.encoding import HexEncoder
    NACL_AVAILABLE = True
except ImportError:
    NACL_AVAILABLE = False


class PackageConfig:
    """Packager configuration."""
    FORMAT_VERSION = "1.0.0"
    PACKAGE_SUFFIX = ".ida_export.tar.gz"


def compute_sha256(filepath):
    """Compute SHA256 hash of file."""
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(1 << 20)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def compute_sha256_bytes(data):
    """Compute SHA256 hash of bytes."""
    return hashlib.sha256(data).hexdigest()


def generate_keypair():
    """Generate Ed25519 keypair and return (private_hex, public_hex)."""
    if not NACL_AVAILABLE:
        print("[!] PyNaCl not available. Install with: pip install pynacl")
        return None, None
    
    signing_key = SigningKey.generate()
    private_hex = signing_key.encode(encoder=HexEncoder).decode()
    public_hex = signing_key.verify_key.encode(encoder=HexEncoder).decode()
    
    return private_hex, public_hex


def sign_data(data, private_key_hex):
    """Sign data with Ed25519 private key."""
    if not NACL_AVAILABLE:
        return None
    
    signing_key = SigningKey(private_key_hex.encode(), encoder=HexEncoder)
    signed = signing_key.sign(data.encode() if isinstance(data, str) else data)
    return signed.signature.hex()


def load_or_generate_key(keyfile=None):
    """Load existing key or generate new one."""
    if keyfile and os.path.exists(keyfile):
        with open(keyfile, "r") as f:
            data = json.load(f)
            return data.get("private_key"), data.get("public_key")
    
    # Generate new keypair
    private_hex, public_hex = generate_keypair()
    
    if private_hex and keyfile:
        with open(keyfile, "w") as f:
            json.dump({
                "private_key": private_hex,
                "public_key": public_hex,
                "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            }, f, indent=2)
        print(f"[+] Generated new keypair saved to: {keyfile}")
    
    return private_hex, public_hex


def create_manifest(files_info, public_key_fingerprint=None):
    """Create manifest.json content."""
    manifest = {
        "format_version": PackageConfig.FORMAT_VERSION,
        "package_id": str(uuid.uuid4()),
        "created_by": {
            "tool": "ida-json-packager",
            "version": PackageConfig.FORMAT_VERSION
        },
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": files_info
    }
    
    if public_key_fingerprint:
        manifest["signing"] = {
            "algorithm": "ed25519",
            "public_key_fingerprint": public_key_fingerprint
        }
    
    return manifest


def create_provenance(input_files):
    """Create provenance.json content."""
    import getpass
    import platform
    
    return {
        "extraction": {
            "tool": "ida-json-exporter",
            "input_files": [os.path.basename(f) for f in input_files],
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        },
        "environment": {
            "user": getpass.getuser(),
            "hostname": platform.node(),
            "os": f"{platform.system()} {platform.release()}",
            "python": platform.python_version()
        },
        "notes": ""
    }


def package_export(input_files, output_path, sign=False, keyfile=None):
    """Create packaged archive from input files."""
    if not input_files:
        print("[!] No input files specified")
        return None
    
    # Validate input files
    for f in input_files:
        if not os.path.exists(f):
            print(f"[!] File not found: {f}")
            return None
    
    print(f"[*] Packaging {len(input_files)} file(s)...")
    
    # Build file info list
    files_info = []
    for filepath in input_files:
        info = {
            "filename": f"data/{os.path.basename(filepath)}",
            "size": os.path.getsize(filepath),
            "sha256": compute_sha256(filepath),
            "mime_type": "application/json"
        }
        files_info.append(info)
    
    # Handle signing
    private_key = None
    public_key = None
    public_fingerprint = None
    
    if sign:
        if not NACL_AVAILABLE:
            print("[!] Signing requested but PyNaCl not available")
            print("[!] Install with: pip install pynacl")
            print("[!] Continuing without signature...")
        else:
            kf = keyfile or "ida_export_key.json"
            private_key, public_key = load_or_generate_key(kf)
            if public_key:
                public_fingerprint = compute_sha256_bytes(public_key.encode())[:16]
    
    # Create manifest
    manifest = create_manifest(files_info, public_fingerprint)
    manifest_json = json.dumps(manifest, indent=2)
    
    # Create provenance
    provenance = create_provenance(input_files)
    provenance_json = json.dumps(provenance, indent=2)
    
    # Create signature if key available
    signature = None
    if private_key:
        # Sign manifest content
        signature = sign_data(manifest_json, private_key)
        print(f"[+] Package signed with key fingerprint: {public_fingerprint}")
    
    # Create tar.gz archive
    with tarfile.open(output_path, "w:gz") as tar:
        # Add manifest
        manifest_bytes = manifest_json.encode("utf-8")
        manifest_info = tarfile.TarInfo(name="manifest.json")
        manifest_info.size = len(manifest_bytes)
        tar.addfile(manifest_info, BytesIO(manifest_bytes))
        
        # Add provenance
        prov_bytes = provenance_json.encode("utf-8")
        prov_info = tarfile.TarInfo(name="provenance.json")
        prov_info.size = len(prov_bytes)
        tar.addfile(prov_info, BytesIO(prov_bytes))
        
        # Add data files
        for filepath in input_files:
            arcname = f"data/{os.path.basename(filepath)}"
            tar.add(filepath, arcname=arcname)
        
        # Add signature if present
        if signature:
            sig_bytes = signature.encode("utf-8")
            sig_info = tarfile.TarInfo(name="signature.sig")
            sig_info.size = len(sig_bytes)
            tar.addfile(sig_info, BytesIO(sig_bytes))
    
    output_size = os.path.getsize(output_path) / 1024
    print(f"[+] Package created: {output_path} ({output_size:.1f} KB)")
    
    return output_path


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Package IDA JSON exports into a tamper-evident archive"
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Input JSON/NDJSON files to package"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output archive path (default: auto-generated)"
    )
    parser.add_argument(
        "--sign",
        action="store_true",
        help="Sign the package with Ed25519 (requires PyNaCl)"
    )
    parser.add_argument(
        "--keyfile",
        help="Path to signing key file (JSON, will be created if missing)"
    )
    
    args = parser.parse_args()
    
    # Generate default output name
    if not args.output:
        base = os.path.splitext(os.path.basename(args.files[0]))[0]
        timestamp = time.strftime("%Y%m%d", time.gmtime())
        args.output = f"{base}-{timestamp}{PackageConfig.PACKAGE_SUFFIX}"
    
    result = package_export(
        args.files,
        args.output,
        sign=args.sign,
        keyfile=args.keyfile
    )
    
    if result:
        print(f"\n[+] Success! Package ready: {result}")
        sys.exit(0)
    else:
        print("\n[!] Packaging failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
