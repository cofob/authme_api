import mysql.connector
from authme_api.hash_types.sha256 import SHA256
from authme_api.hash_types import HashType


def find_hash_type(hash_str: str) -> HashType:
    mapping = {'SHA': SHA256}
    spl = hash_str.split('$')
    return mapping[spl[1]]


class AuthMe:
    def __init__(
        self,
        db_user: str,
        db_password: str,
        db_name: str,
        db_host: str,
        db_port: int = 3306,
        default_hash: HashType = SHA256,
    ):
        self.db = mysql.connector.connect(
            host=db_host,
            user=db_user,
            password=db_password,
            database=db_name,
            port=db_port,
        )
        self.default_hash = default_hash
