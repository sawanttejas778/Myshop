import mysql.connector

def get_db():
    """Establish and return a MySQL database connection and cursor."""
    conn = mysql.connector.connect(
        host="localhost",
        user="root",
        password="8010",
        database="shop"
    )
    cursor = conn.cursor(dictionary=True)
    return conn, cursor