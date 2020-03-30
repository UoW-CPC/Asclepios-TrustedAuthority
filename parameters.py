import os

""" Configurable parameters """

KeyG = str.encode(os.getenv("KEY_G"))
hash_length = int(os.getenv("HASH_LENGTH"))
SALT = str.encode(os.getenv("SALT"))
IV = str.encode(os.getenv("IV"))