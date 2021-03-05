import os

""" Configurable parameters """

hash_length = int(os.getenv("HASH_LENGTH"))
#SALT = str.encode(os.getenv("SALT")) # string -> bytes
IV = str.encode(os.getenv("IV")) # string -> bytes
MODE = os.getenv("MODE") # cipher mode
KS = int(os.getenv("KS"))# key size
#ITER = int(os.getenv("ITER")) # number of iterations to generate key from passphrase
TEEP_SERVER = os.getenv("TEEP_SERVER")
