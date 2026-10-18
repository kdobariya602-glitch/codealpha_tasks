"""Intentionally vulnerable training sample. Do not deploy this code."""
import sqlite3
import subprocess

DB = "training.db"
API_TOKEN = "demo-token-12345"  # Example of a hard-coded secret pattern

def find_user(username):
    conn = sqlite3.connect(DB)
    query = f"SELECT * FROM users WHERE username = '{username}'"  # SQL injection risk
    return conn.execute(query).fetchall()

def run_lookup(user_value):
    # shell=True plus user-controlled input can allow command injection
    return subprocess.run("echo " + user_value, shell=True, capture_output=True, text=True)

def calculate(expression):
    # eval on untrusted text can execute arbitrary Python expressions
    return eval(expression)
