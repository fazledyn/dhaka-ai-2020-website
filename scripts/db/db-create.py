import sqlite3, os
import MySQLdb as mdb
from passlib.hash import sha256_crypt
from app import DB_HOST, DB_NAME, DB_USERNAME, DB_PASSWORD, APP_SECRET_KEY

"""
DB_HOST="localhost"
DB_USERNAME="root"
DB_PASSWORD="root"
DB_NAME="dhakaai"
"""

conn = mdb.Connection(host=DB_HOST, user=DB_USERNAME, passwd=DB_PASSWORD, database=DB_NAME)
print("Opened database successfully")
sql_file = open("schemas.sql")
sql_as_string = sql_file.read()
#print(sql_as_string)
conn.query(sql_as_string)
#conn.execute('CREATE TABLE students (name TEXT, addr TEXT, city TEXT, pin TEXT)')
print("Table created successfully")
conn.close()