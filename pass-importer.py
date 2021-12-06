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
import hashlib
import subprocess
from pathlib import Path
from getpass import getpass
from itertools import islice
from optparse import OptionParser
from progress.spinner import Spinner
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEFAULT_TIMER_STATE = False
SUPPORTED_ACTIONS = ['import', 'export']
IGNORED_DIRS = ['.git']

OUTPUT_FILE_NAME = 'passwords.json'
PASS_DIR = os.path.join(Path.home(), '.password-store')
PASS_BIN = subprocess.Popen('which pass', shell=True,
           stdout=subprocess.PIPE).stdout.read().decode('utf-8').split('\n')[0]

parser = OptionParser()
parser.add_option('-a', '--action',
                            dest='action',
                            help='import, export')

(options, args) = parser.parse_args()


def animated_messages(message):
    spinner = Spinner(f'{message} =>')
    while DEFAULT_TIMER_STATE == False:
        spinner.next()
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
def encrypt(secret_file, data_to_encrypt, password, salt):
    fernet_data = Fernet(get_key(password, salt))
    encrypted = fernet_data.encrypt(data_to_encrypt.encode())

    print('Write encrypted data')
    with open(secret_file, 'wb+') as f:
        f.write(encrypted)

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

def decrypt(secret_file, password, salt):
    print('Read and decrypt data')
    with open(secret_file, 'r') as f:
        data_from_file = f.read()

    fernet_data = Fernet(get_key(password, salt))
    return fernet_data.decrypt(data_from_file.encode()).decode()

"""
similar command - pass insert -m <path> 
"""
def pass_insert(decrypted_passwords, ignored_dirs):
    to_json = json.loads(decrypted_passwords)
    for dir_name in to_json:
        if dir_name not in ignored_dirs:
            for k, v in to_json[dir_name].items():
                echo = subprocess.Popen(['echo', v], stdout=subprocess.PIPE)
                pass_insert = subprocess.Popen(f'pass insert -m {dir_name}/{k}', 
                                                     shell=True,
                                                     stdout=subprocess.PIPE,
                                                     stdin=echo.stdout).stdout.read().decode('utf-8').split('\n')[0]

                print(f'Import password for {dir_name} to {dir_name}/{k}')
                

"""
Return all passwords in json format
"""
def get_all_passwords(ignored_dirs):
    passwords = {}

    for dir_name in os.listdir(PASS_DIR):
        if dir_name not in ignored_dirs:
            tmp_passwords_names = {}
            if os.path.isdir(os.path.join(PASS_DIR, dir_name)):
                for files in os.listdir(os.path.join(PASS_DIR, dir_name)):
                    resource = files.split('.gpg')[0]
                    password = subprocess.Popen(f'{PASS_BIN} {dir_name}/{resource}',
                                                shell=True,
                                                stdout=subprocess.PIPE).stdout.read().decode('utf-8').split('\n')[0]
                    tmp_passwords_names[resource] = password

            passwords[dir_name] = tmp_passwords_names
        else:   
            print(f'Skip {dir_name}')

    return json.dumps(passwords, ensure_ascii=False, indent=4)

"""
The main logic
"""
def main():
    if options.action in SUPPORTED_ACTIONS:
        if options.action == 'export':
            DEFAULT_TIMER_STATE = True

            crypt_password = getpass('Enter the password for which the password file will be encrypted:')
            check_password = getpass('Confirm the password:')

            if crypt_password and check_password \
                    and crypt_password == check_password:
            
                print('Getting data from the password manager ... ')
                encrypt(OUTPUT_FILE_NAME, get_all_passwords(IGNORED_DIRS), crypt_password, hashing(crypt_password))
            else:
                print('Password mismatch')
                exit(1)

        elif options.action == 'import':
            
            crypt_password = getpass('Enter the password for which the password file will be decrypted:')

            if crypt_password:
                hashing(crypt_password)
                pass_insert(decrypt(OUTPUT_FILE_NAME, crypt_password, hashing(crypt_password)), IGNORED_DIRS)

        else:
           print('WTF: Internal error')

    else:
        print('Unknown action')
        exit(1)

if __name__ == '__main__':
    main()
