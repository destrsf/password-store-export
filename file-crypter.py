"""
Usage:


The script is designed to create a copy of the password-store
on another device bypassing the built-in functional

Example:


get all passwords and save it in encrypted file

./pass-importer.py -a export

then copy it acript and output file to other device
and do:

./pass-importer.py -a import

"""
import os
import ast
import json
import base64
import random
import shutil
import string
import hashlib
import tempfile
import pyAesCrypt
import subprocess
from pathlib import Path
from getpass import getpass
from itertools import islice
from optparse import OptionParser
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SUPPORTED_ACTIONS = ['encrypt', 'decrypt']
IGNORED_DIRS = ['.git']
APP_CODE = 'U2FsdGVkX1/zjvjzFnfBZplDCXsKioJ0v6ZMywxeimW9ERTtMcs6aIDpTkau4mK+6a4Kvvu//v/gAovZS8SYXw=='
OUTPUT_FILE_NAME = 'passwords.json'
PASS_DIR = os.path.join(Path.home(), '.password-store')
PASS_BIN = subprocess.Popen('which pass', shell=True,
           stdout=subprocess.PIPE).stdout.read().decode('utf-8').split('\n')[0]

parser = OptionParser()
parser.add_option('-a', '--action',
                            dest='action',
                            help='encrypt, decrypt')
parser.add_option('-f', '--secret_file',
                            dest='secret_file',
                            default=OUTPUT_FILE_NAME,
                            help='path or just name of secret file whre will be saved encrypted passwords')
                  

(options, args) = parser.parse_args()


"""
The function takes a string
and returns its hash
"""
def hashing(string):
    return hashlib.md5(string.encode()).hexdigest().encode()

"""
Accepts the password that will be
used for encryption and salt
salt must be bytes
"""
def get_key(password, salt):
    encoded_password = password.encode()
    kdf = PBKDF2HMAC(
           algorithm=hashes.SHA256(),
           length=32,
           salt=salt,
           iterations=100000,
           backend=default_backend()
    )

    return(base64.urlsafe_b64encode(kdf.derive(encoded_password)))

"""
secret_file is path to the secret file, 
this is the file where it will be written encrypted
data of passwords
---
data_to_encrypt is password object which will be encrypted
---
password is password key
------------------------------
a function that encrypts all data received in the data_to_encrypt variable
and will write it to the secret file from secret_file var
"""
def encrypt(secret_file, password, salt):
    with open(secret_file, 'rb') as f:
        data_from_file = f.read()

    bufferSize = 64 * 1024
    fernet_data = Fernet(get_key(password, salt))
    encrypted = fernet_data.encrypt(data_from_file)
    
    print('Write encrypted data')
    with open(secret_file, 'wb+') as f:
        f.write(encrypted)

    py_aes(secret_file, password, salt, 'encrypt')

"""
secret_file is path to the secret file, 
this is the file where it will be written encrypted
data of passwords
---
password is password key
------------------------------
the function will read everything from a file 
with encrypted data and return it in decrypted form
"""
def py_aes(secret_file, password, salt, action):
    try:
        random_tmp_file_name = ''.join(random.choices(string.ascii_uppercase + string.digits, k=random.randint(10,40)))
        tmp_file_path = os.path.join(tempfile.gettempdir(), random_tmp_file_name)
        if action == 'encrypt':
            pyAesCrypt.encryptFile(secret_file, tmp_file_path, password)
        elif action == 'decrypt':
            pyAesCrypt.decryptFile(secret_file, tmp_file_path, password)

        shutil.move(tmp_file_path, secret_file)        
    except ValueError as e:
        print('Unsupported file type')
        exit(1)

def decrypt(secret_file, password, salt):
    print('Read and decrypt data')
    py_aes(secret_file, password, salt, 'decrypt')

    with open(secret_file, 'rb') as f:
        data_from_file = f.read()

    fernet_data = Fernet(get_key(password, salt))
    data = fernet_data.decrypt(data_from_file)

    with open(secret_file, 'wb+') as f:
        f.write(data)

"""
The main logic
"""
def main(s_actions, i_dirs, o_file_name):
    if options.action in s_actions:
        if options.action == 'encrypt':

            crypt_password = getpass('Enter the password for which the password file will be encrypted:')
            check_password = getpass('Confirm the password:')

            if crypt_password and check_password \
                    and crypt_password == check_password:
            
                encrypt(o_file_name, crypt_password, hashing(crypt_password))
            else:
                print('Password mismatch')
                exit(1)

        elif options.action == 'decrypt':
            
            crypt_password = getpass('Enter the password for which the password file will be decrypted:')

            if crypt_password:
                hashing(crypt_password)
                decrypt(o_file_name, crypt_password, hashing(crypt_password))

        else:
           print('WTF: Internal error')

    else:
        print('Unknown action')
        exit(1)

if __name__ == '__main__':
    main(SUPPORTED_ACTIONS, IGNORED_DIRS, options.secret_file)

