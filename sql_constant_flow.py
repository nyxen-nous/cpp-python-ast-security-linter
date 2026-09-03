BASE = "SELECT * FROM users WHERE id="

def safe(cursor):
    q = BASE + "1"
    cursor.execute(q)
