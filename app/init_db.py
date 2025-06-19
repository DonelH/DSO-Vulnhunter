import sqlite3

conn = sqlite3.connect('lab.db')
cur = conn.cursor()

cur.execute("DROP TABLE IF EXISTS users")
cur.execute("""
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    role TEXT)
""")

cur.executemany("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", [
    ("admin", "admin123", "admin"),
    ("alice", "pass1", "user"),
    ("bob", "pass2", "user")
])

conn.commit()
conn.close()