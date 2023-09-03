import MySQLdb as mdb

conn = mdb.Connection(host="localhost",user="root",passwd="",database="dhakaai")
conn.query('update Team set DailyLimit=0 where 1=1')
conn.commit()
conn.close()
