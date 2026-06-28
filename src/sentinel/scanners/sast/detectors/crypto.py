import ast
import re
from typing import List, Dict, Any, Optional


def detect_insecure_crypto(tree: Optional[ast.AST], source: str, filename: str) -> List[Dict[str, Any]]:
    """Detect insecure cryptographic algorithms."""
    findings = []

    crypto_patterns = [
        (r"hashlib\.md5\s*\(", "MD5 is collision-prone and insecure for cryptography"),
        (r"hashlib\.sha1\s*\(", "SHA1 is collision-prone and insecure for cryptography"),
        (r"hashlib\.sha0\s*\(", "SHA0 is deprecated and insecure"),
        (r"DES\.new\s*\(", "DES is insecure (56-bit key)"),
        (r"ARC2\.new\s*\(", "RC2 is insecure"),
        (r"PKCS1_v1_5", "PKCS#1 v1.5 is vulnerable to Bleichenbacher attacks"),
        (r"Crypto\.Cipher\.ARC4", "RC4 is broken and insecure"),
        (r"ssl\.wrap_socket\s*\(.*?ssl_version\s*=\s*ssl\.PROTOCOL_SSLv", "SSLv2/v3 is insecure"),
    ]

    for pattern, msg in crypto_patterns:
        for match in re.finditer(pattern, source, re.IGNORECASE):
            line_no = source[: match.start()].count("\n") + 1
            lines = source.split("\n")
            context = lines[line_no - 1] if line_no <= len(lines) else ""
            findings.append(
                {
                    "type": "insecure_crypto",
                    "severity": "High",
                    "line": line_no,
                    "code": context.strip(),
                    "message": f"Insecure cryptography: {msg}",
                    "fix": "Protocol: Strong Cryptographic Standards. Replace weak, collision-prone hash algorithms (MD5, SHA-1, SHA-0) with secure hashes (SHA-256, SHA-3, or bcrypt for passwords). For symmetric encryption, replace insecure ciphers (DES, RC4) with AES-GCM (e.g., using python's cryptography package) or ChaCha20-Poly1305.",
                }
            )

    return findings
