from flask import request
import sqlite3

# EXPECT PY.SEC.008
def execute_query(user_id):
    db = sqlite3.connect('app.db')
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    return db.execute(query).fetchall()

def route():
    user_id = request.args.get('id')
    return execute_query(user_id)
