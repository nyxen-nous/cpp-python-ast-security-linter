# EXPECT PY.SEC.008

def query_from_input(cursor):
    user = input()
    q = f"SELECT * FROM users WHERE id={user}"
    cursor.execute(q)
