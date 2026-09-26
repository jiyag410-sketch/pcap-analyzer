"""
hashing.py
Computes forensic hashes for uploaded PCAP files.
"""

import hashlib


def calculate_hashes(file_path: str):
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "MD5": md5.hexdigest(),
        "SHA1": sha1.hexdigest(),
        "SHA256": sha256.hexdigest(),
    }