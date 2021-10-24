import mysql.connector
from hash_types.sha256 import SHA256
import hash_types


class AuthMe:
    def __init__(self, db_user: str, db_password: str, db_name: str, db_host: str, db_port: int = 3306,
                 default_hash: hash_types.HashType = SHA256):
        self.db = mysql.connector.connect(host=db_host, user=db_user,
                                                 password=db_password, database=db_name,
                                                 port=db_port)
        self.default_hash = default_hash
