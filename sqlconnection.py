import mysql.connector
from dotenv import load_dotenv
import os

load_dotenv()

def get_db():
    """Establish and return a MySQL database connection and cursor."""
    conn = mysql.connector.connect(
        host=os.getenv("host"),
        user=os.getenv("user"),
        password=os.getenv("password"),
        database=os.getenv("database")
    )
    cursor = conn.cursor(dictionary=True)
    return conn, cursor