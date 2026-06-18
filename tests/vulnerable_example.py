import os
import hashlib
import sqlite3
from typing import Any

# Hardcoded secret (Critical)
API_KEY = "sk-1234567890abcdefghijklmnopqrst"


def login_user(email: str, password: str) -> Any:
    # SQL Injection (Critical)
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE email = '{email}' AND password = '{password}'"
    cursor.execute(query)
    return cursor.fetchone()


def render_html(user_input: str) -> str:
    # XSS (High)
    return f"<div>{user_input}</div>"


def run_command(cmd: str) -> None:
    # Command Injection (Critical)
    os.system(cmd)


def hash_password(pwd: str) -> str:
    # Insecure Crypto (High)
    return hashlib.md5(pwd.encode()).hexdigest()
