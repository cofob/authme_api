from authme_api.hash_types.sha256 import *
from authme_api.hash_types import *
from authme_api import *


def test_sha256_standard_init():
    # standard initialising
    _hash = SHA256('f9ca496861aeb0266ed5d5637513b1a778ba33f4b8f5eb00ef08ba98be7e3bba', 'salt')
    assert _hash._hash.hash == 'f9ca496861aeb0266ed5d5637513b1a778ba33f4b8f5eb00ef08ba98be7e3bba'
    assert _hash._hash.salt == 'salt'
    assert _hash._hash.hash == _hash.hash_func('1234', 'salt').hash
    assert _hash._hash.salt == _hash.hash_func('1234', 'salt').salt


def test_sha256_parsing():
    # parsing from `password` field
    _hash = SHA256.process_hash_str('$SHA$salt$f9ca496861aeb0266ed5d5637513b1a778ba33f4b8f5eb00ef08ba98be7e3bba')
    assert _hash._hash.hash == 'f9ca496861aeb0266ed5d5637513b1a778ba33f4b8f5eb00ef08ba98be7e3bba'
    assert _hash._hash.salt == 'salt'
    assert _hash._hash.hash == _hash.hash_func('1234', 'salt').hash
    assert _hash._hash.salt == _hash.hash_func('1234', 'salt').salt


def test_sha256_password_changing():
    # password changing
    _hash = SHA256.process_hash_str('$SHA$salt$f9ca496861aeb0266ed5d5637513b1a778ba33f4b8f5eb00ef08ba98be7e3bba')
    _hash.change_password('5678')
    assert _hash._hash.hash == 'f0bf9986cd9df3d8f4f9823a2bf1890d171ea05d0c36c593213a94e528dbef5b'
    assert _hash._hash.salt == 'salt'
    assert _hash._hash.hash == _hash.hash_func('5678', 'salt').hash
    assert _hash._hash.salt == _hash.hash_func('5678', 'salt').salt


def test_sha256_password_checking():
    _hash = SHA256.process_hash_str('$SHA$salt$f9ca496861aeb0266ed5d5637513b1a778ba33f4b8f5eb00ef08ba98be7e3bba')
    assert _hash.is_equal('1234')


def test_find_hash_type():
    assert SHA256 == find_hash_type('$SHA$salt$f9ca496861aeb0266ed5d5637513b1a778ba33f4b8f5eb00ef08ba98be7e3bba')
