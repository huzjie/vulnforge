"""Deliberately vulnerable example: SQL injection via string concatenation.

DO NOT run this code against a real database. It exists solely to demonstrate
what vulnforge's static rules and mock LLM scanner detect (CWE-89).
"""
import sqlite3


def get_user(username: str) -> object:
    """Fetch a user by name — vulnerable to SQL injection (CWE-89)."""
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    # vulnforge-static: sql-injection
    query = "SELECT * FROM users WHERE name = '" + username + "'"
    cursor.execute(query)
    row = cursor.fetchone()
    conn.close()
    return row


def search_orders(customer_id: str) -> object:
    """Build an ORDER BY query with f-string interpolation — vulnerable."""
    conn = sqlite3.connect("orders.db")
    cur = conn.cursor()
    # vulnforge-static: sql-injection
    cur.execute(f"SELECT * FROM orders WHERE customer_id = '{customer_id}'")
    return cur.fetchall()
