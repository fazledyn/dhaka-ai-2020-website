import MySQLdb as mdb

DB_HOST="localhost"
DB_USERNAME="ufbxg9t1nebx"
DB_PASSWORD="Dhaka-ai123"
DB_NAME="dhakaai"

def main(): 
    conn = mdb.Connection(host=DB_HOST, user=DB_USERNAME, passwd=DB_PASSWORD, database=DB_NAME)
    conn.query('UPDATE Team SET DailyLimit=0 where 1=1')
    conn.commit()
    conn.close()

if __name__ == "__main__":
    main()