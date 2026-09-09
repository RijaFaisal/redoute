import sqlite3
import os


def get_user(conn, username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = '%s'" % username)
    return cur.fetchone()


def run_command(user_input):
    os.system("echo " + user_input)
