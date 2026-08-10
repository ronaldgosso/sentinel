from .command_injection import detect_command_injection
from .crypto import detect_insecure_crypto
from .frontend import detect_frontend_vulnerabilities
from .secrets import detect_hardcoded_secrets
from .sql_injection import detect_sql_injection
from .xss import detect_xss

__all__ = [
    "detect_command_injection",
    "detect_frontend_vulnerabilities",
    "detect_hardcoded_secrets",
    "detect_insecure_crypto",
    "detect_sql_injection",
    "detect_xss",
]
