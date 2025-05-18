import struct
import hashlib
import os
from Crypto.Cipher import AES, DES3
import mysql.connector

DB_CONFIG = {
    "host": "127.0.0.1",
    "port": 3306,
    "user": "Project_db",
    "password": "Welcome@123",
    "database": "user_db"
}

def save_encryption_key(file_id, fragment_number, key):
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        cursor = connection.cursor()
        cursor.execute("""
            UPDATE file_fragments 
            SET encryption_key = %s 
            WHERE file_id = %s AND fragment_number = %s
        """, (key.hex(), file_id, fragment_number))
        connection.commit()
        cursor.close()
        connection.close()
    except Exception as e:
        print(f"Error saving encryption key: {e}")

def get_encryption_key(file_id, fragment_number):
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        cursor = connection.cursor()
        cursor.execute("""
            SELECT encryption_key FROM file_fragments 
            WHERE file_id = %s AND fragment_number = %s
        """, (file_id, fragment_number))
        result = cursor.fetchone()
        cursor.close()
        connection.close()
        if result:
            return bytes.fromhex(result[0])
        else:
            print(f"⚠️ Error: Encryption key not found for {file_id}, fragment {fragment_number}")
            return None
    except Exception as e:
        print(f"Error retrieving encryption key: {e}")
        return None

# ======================= RC6 Implementation =======================
class RC6:
    def __init__(self, key, w=32, r=20):
        self.w = w
        self.r = r
        self.modulo = 2 ** self.w
        self.mask = self.modulo - 1
        self.key = self._key_schedule(key)

    def _key_schedule(self, key):
        key = key.ljust(16, b'\x00')[:16]
        L = list(struct.unpack("<4L", key))
        P = 0xB7E15163
        Q = 0x9E3779B9
        S = [(P + i * Q) & self.mask for i in range(2 * self.r + 4)]
        A = B = i = j = 0
        for _ in range(3 * max(len(L), len(S))):
            A = S[i] = self._rotate_left((S[i] + A + B) & self.mask, 3)
            # Ensure shift value is non-negative using abs() if needed.
            B = L[j] = self._rotate_left((L[j] + A + B) & self.mask, abs((A + B) % self.w))
            i = (i + 1) % len(S)
            j = (j + 1) % len(L)
        return S

    def _rotate_left(self, x, n):
        n = n % self.w
        return ((x << n) & self.mask) | (x >> (self.w - n))

    def _rotate_right(self, x, n):
        n = n % self.w
        return (x >> n) | ((x << (self.w - n)) & self.mask)

    def encrypt_block(self, plaintext):
        A, B, C, D = struct.unpack("<4L", plaintext)
        B = (B + self.key[0]) & self.mask
        D = (D + self.key[1]) & self.mask
        for i in range(1, self.r + 1):
            t = (B * (2 * B + 1)) & self.mask
            t = self._rotate_left(t, 5)
            u = (D * (2 * D + 1)) & self.mask
            u = self._rotate_left(u, 5)
            A = (self._rotate_left(A ^ t, u) + self.key[2 * i]) & self.mask
            C = (self._rotate_left(C ^ u, t) + self.key[2 * i + 1]) & self.mask
            A, B, C, D = B, C, D, A
        A = (A + self.key[2 * self.r + 2]) & self.mask
        C = (C + self.key[2 * self.r + 3]) & self.mask
        return struct.pack("<4L", A, B, C, D)

    def decrypt_block(self, ciphertext):
        A, B, C, D = struct.unpack("<4L", ciphertext)
        C = (C - self.key[2 * self.r + 3]) & self.mask
        A = (A - self.key[2 * self.r + 2]) & self.mask
        for i in range(self.r, 0, -1):
            A, B, C, D = D, A, B, C
            u = (D * (2 * D + 1)) & self.mask
            u = self._rotate_left(u, 5)
            t = (B * (2 * B + 1)) & self.mask
            t = self._rotate_left(t, 5)
            C = (self._rotate_right((C - self.key[2 * i + 1]) & self.mask, t)) ^ u
            A = (self._rotate_right((A - self.key[2 * i]) & self.mask, u)) ^ t
        D = (D - self.key[1]) & self.mask
        B = (B - self.key[0]) & self.mask
        return struct.pack("<4L", A, B, C, D)

# ---------------------- Padding Functions ----------------------
def pad_data(data):
    padding_length = 16 - (len(data) % 16)
    return data + bytes([padding_length] * padding_length)

def unpad_data(data):
    return data[:-data[-1]]

# ---------------------- Encryption & Decryption Functions ----------------------
def generate_random_key(length=16):
    return os.urandom(length)

def encrypt_aes(data, file_name, fragment_number):
    key = generate_random_key(16)  
    print(f"[DEBUG] AES Key for {file_name} Fragment {fragment_number}: {key.hex()}")
    cipher = AES.new(hashlib.sha256(key).digest()[:16], AES.MODE_ECB)
    encrypted = cipher.encrypt(pad_data(data))
    print(f"[DEBUG] Encrypted AES data (first 64 bytes): {encrypted[:64].hex()}")
    return encrypted, key

def decrypt_aes(data, file_name, fragment_number, key):
    cipher = AES.new(hashlib.sha256(key).digest()[:16], AES.MODE_ECB)
    decrypted = unpad_data(cipher.decrypt(data))
    print(f"[DEBUG] Decrypted AES data for {file_name} Fragment {fragment_number} (first 64 bytes): {decrypted[:64].hex()}")
    return decrypted

def encrypt_3des(data, file_name, fragment_number):
    key = generate_random_key(24) 
    print(f"[DEBUG] 3DES Key for {file_name} Fragment {fragment_number}: {key.hex()}")
    cipher = DES3.new(hashlib.sha256(key).digest()[:24], DES3.MODE_ECB)
    encrypted = cipher.encrypt(pad_data(data))
    print(f"[DEBUG] Encrypted 3DES data (first 64 bytes): {encrypted[:64].hex()}")
    return encrypted, key

def decrypt_3des(data, file_name, fragment_number, key):
    cipher = DES3.new(hashlib.sha256(key).digest()[:24], DES3.MODE_ECB)
    decrypted = unpad_data(cipher.decrypt(data))
    print(f"[DEBUG] Decrypted 3DES data for {file_name} Fragment {fragment_number} (first 64 bytes): {decrypted[:64].hex()}")
    return decrypted

def encrypt_rc6(data, file_name, fragment_number):
    key = generate_random_key(16) 
    print(f"[DEBUG] RC6 Key for {file_name} Fragment {fragment_number}: {key.hex()}")
    rc6 = RC6(hashlib.sha256(key).digest()[:16])
    data = pad_data(data)
    encrypted = b"".join(rc6.encrypt_block(data[i:i+16]) for i in range(0, len(data), 16))
    print(f"[DEBUG] Encrypted RC6 data (first 64 bytes): {encrypted[:64].hex()}")
    return encrypted, key

def decrypt_rc6(data, file_name, fragment_number, key):
    from encryption import RC6 
    rc6 = RC6(hashlib.sha256(key).digest()[:16])
    decrypted = b"".join(rc6.decrypt_block(data[i:i+16]) for i in range(0, len(data), 16))
    decrypted = unpad_data(decrypted)
    print(f"[DEBUG] Decrypted RC6 data for {file_name} Fragment {fragment_number} (first 64 bytes): {decrypted[:64].hex()}")
    return decrypted
