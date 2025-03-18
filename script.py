import hashlib
from Crypto.Cipher import DES, ARC4
import base64

import mysql.connector

mydb = mysql.connector.connect(
  host="localhost",
  user="yourusername",
  password="yourpassword"
)

mycursor = mydb.cursor()

mycursor.execute("CREATE DATABASE mydatabase")

conn.create_secret(Name="uwp/dev/nemo/auth_secrets",
                            # deepcode ignore HardcodedNonCryptoSecret/test: <please specify a reason of ignoring this>
                            SecretString=settings.AUTH_SECRETS)
      
       

#  Weak Hashing Functions
def weak_hashing(data):
    print("\n Using Weak Hashing Algorithms:")
    
    # MD5 (Weak)
    md5_hash = hashlib.md5(data.encode()).hexdigest()
    print(f" MD5 Hash: {md5_hash}")

    # SHA-1 (Weak)
    sha1_hash = hashlib.sha1(data.encode()).hexdigest()
    print(f" SHA-1 Hash: {sha1_hash}")

#  Weak Encryption Algorithms
def weak_encryption(data, key):
    print("\n Using Weak Encryption Algorithms:")

    # DES (Weak, requires 8-byte key)
    if len(key) != 8:
        print("❗ DES key must be exactly 8 bytes long. Adjusting the key...")
        key = key[:8].ljust(8, "0")  # Pad or trim the key to 8 bytes
    
    des_cipher = DES.new(key.encode(), DES.MODE_ECB)
    des_encrypted = des_cipher.encrypt(data.ljust(8).encode())  # Padding for DES
    print(f" DES Encrypted Data (Base64): {base64.b64encode(des_encrypted).decode()}")

    # RC4 (Weak)
    rc4_cipher = ARC4.new(key.encode())
    rc4_encrypted = rc4_cipher.encrypt(data.encode())
    print(f" RC4 Encrypted Data (Base64): {base64.b64encode(rc4_encrypted).decode()}")

#  Hardcoded Encryption Key (Security Risk)
HARD_CODED_KEY = "weak_key"

if __name__ == "__main__":
    sample_data = "SensitiveData"

    # Run weak hashing and encryption functions
    weak_hashing(sample_data)
    weak_encryption(sample_data, HARD_CODED_KEY)

