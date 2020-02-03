import os

""" Configurable parameters """

KeyG = os.getenv("KEY_G",b"123")
hash_length = os.getenv("HASH_LENGTH",256)
SALT = os.getenv("SALT",b"abc123!?")
IV = os.getenv("IV",b"abcdefg")