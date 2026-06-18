from .sql_injection import detect_sql_injection
from .xss import detect_xss
from .command_injection import detect_command_injection
from .secrets import detect_hardcoded_secrets
from .crypto import detect_insecure_crypto

__all__ = [
    "detect_sql_injection",
    "detect_xss",
    "detect_command_injection",
    "detect_hardcoded_secrets",
    "detect_insecure_crypto",
]
