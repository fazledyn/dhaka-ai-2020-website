import MySQLdb as mdb
import jwt
from passlib.hash import sha256_crypt
from app import DB_HOST, DB_NAME, DB_USERNAME, DB_PASSWORD, APP_SECRET_KEY

"""
DB_HOST="localhost"
DB_USERNAME="root"
DB_PASSWORD="root"
DB_NAME="dhakaai"
APP_SECRET_KEY = b'_5#y2L"F4Q8z\n\xec]/'
"""

ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "n!md@2o2o"

email_token = jwt.encode({
    'TeamName': ADMIN_USERNAME,
    'Password': ADMIN_PASSWORD
}, key=APP_SECRET_KEY, algorithm='HS256').decode('utf-8')

conn = mdb.Connection(host=DB_HOST, user=DB_USERNAME, passwd=DB_PASSWORD, database=DB_NAME)
conn.query('Insert into Team values ("%s","%s","%s","%s",1,1,1,0, curdate())'%(ADMIN_USERNAME, sha256_crypt.hash(ADMIN_PASSWORD),'admin@dhaka-ai.com',email_token))

conn.commit()
conn.close()
print('admin created successfully !')
