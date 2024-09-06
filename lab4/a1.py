import sympy
import base64
import time
import json
import sqlite3
from flask import Flask, request, jsonify

app = Flask(__name__)

# Helper functions for ElGamal cryptosystem
def generate_elgamal_keypair(key_size):
    p = sympy.nextprime(sympy.randprime(2**(key_size//2 - 1), 2**(key_size//2)))
    g = sympy.nextprime(sympy.randprime(2, p - 1))
    x = sympy.randprime(1, p - 1)
    h = pow(g, x, p)
    return (p, g, h), (p, g, x)

def elgamal_encrypt(public_key, plaintext):
    p, g, h = public_key
    m = int.from_bytes(plaintext.encode(), byteorder='big')
    k = sympy.randprime(1, p - 1)
    c1 = pow(g, k, p)
    c2 = (m * pow(h, k, p)) % p
    return (c1, c2)

def elgamal_decrypt(private_key, ciphertext):
    p, g, x = private_key
    c1, c2 = ciphertext
    m = (c2 * pow(c1, p - 1 - x, p)) % p
    return m.to_bytes((m.bit_length() + 7) // 8, byteorder='big').decode()

# Database initialization
DATABASE = 'drm_system.db'

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS keys
                        (id INTEGER PRIMARY KEY,
                         master_key BLOB,
                         public_key BLOB,
                         private_key BLOB,
                         created_at TIMESTAMP,
                         updated_at TIMESTAMP)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS content
                        (id INTEGER PRIMARY KEY,
                         creator TEXT,
                         content BLOB,
                         access_control TEXT,
                         created_at TIMESTAMP,
                         updated_at TIMESTAMP)''')
        conn.execute('''CREATE TABLE IF NOT EXISTS access
                        (id INTEGER PRIMARY KEY,
                         customer TEXT,
                         content_id INTEGER,
                         access_expiration TIMESTAMP,
                         FOREIGN KEY(content_id) REFERENCES content(id))''')
        conn.commit()

def store_key_entry(master_key, public_key, private_key):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO keys (master_key, public_key, private_key, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (base64.b64encode(master_key[0]), base64.b64encode(public_key[0]), base64.b64encode(private_key[0]), int(time.time()), int(time.time())))
        conn.commit()

def get_key_entry():
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT master_key, public_key, private_key FROM keys ORDER BY id DESC LIMIT 1")
        return cur.fetchone()

def store_content(creator, content, access_control):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO content (creator, content, access_control, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
                    (creator, base64.b64encode(content), json.dumps(access_control), int(time.time()), int(time.time())))
        conn.commit()

def get_content(content_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("SELECT creator, content, access_control FROM content WHERE id=?", (content_id,))
        return cur.fetchone()

def grant_access(customer, content_id, expiration_time):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO access (customer, content_id, access_expiration) VALUES (?, ?, ?)",
                    (customer, content_id, expiration_time))
        conn.commit()

def revoke_access(customer, content_id):
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM access WHERE customer=? AND content_id=?", (customer, content_id))
        conn.commit()

def revoke_master_key():
    with sqlite3.connect(DATABASE) as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM keys")
        conn.commit()

def renew_master_key():
    global current_master_key
    key_size = 2048
    master_public_key, master_private_key = generate_elgamal_keypair(key_size)
    store_key_entry(master_public_key, master_public_key, master_private_key)
    current_master_key = master_public_key

@app.route('/generate_key', methods=['POST'])
def generate_key():
    key_size = request.json.get('key_size', 2048)
    master_public_key, master_private_key = generate_elgamal_keypair(key_size)
    store_key_entry(master_public_key, master_public_key, master_private_key)
    return jsonify({'public_key': base64.b64encode(master_public_key[0]).decode(),
                    'private_key': base64.b64encode(master_private_key[0]).decode()})

@app.route('/encrypt_content', methods=['POST'])
def encrypt_content():
    data = request.json
    content = data['content']
    creator = data['creator']
    master_key = get_key_entry()
    if master_key:
        _, public_key, _ = master_key
        public_key = base64.b64decode(public_key)
        encrypted_content = elgamal_encrypt(public_key, content)
        store_content(creator, encrypted_content, data['access_control'])
        return jsonify({'status': 'Content encrypted'})
    else:
        return jsonify({'error': 'Master key not found'}), 404

@app.route('/grant_access', methods=['POST'])
def grant_access():
    data = request.json
    customer = data['customer']
    content_id = data['content_id']
    expiration_time = data['expiration_time']
    grant_access(customer, content_id, expiration_time)
    return jsonify({'status': 'Access granted'})

@app.route('/revoke_access', methods=['POST'])
def revoke_access():
    data = request.json
    customer = data['customer']
    content_id = data['content_id']
    revoke_access(customer, content_id)
    return jsonify({'status': 'Access revoked'})

@app.route('/revoke_master_key', methods=['POST'])
def revoke_master_key_route():
    revoke_master_key()
    return jsonify({'status': 'Master key revoked'})

@app.route('/renew_master_key', methods=['POST'])
def renew_master_key_route():
    renew_master_key()
    return jsonify({'status': 'Master key renewed'})

@app.route('/decrypt_content', methods=['POST'])
def decrypt_content():
    data = request.json
    content_id = data['content_id']
    customer = data['customer']
    content_data = get_content(content_id)
    if content_data:
        creator, encrypted_content, access_control = content_data
        access_control = json.loads(access_control)
        master_key = get_key_entry()
        if master_key:
            _, private_key, _ = master_key
            private_key = base64.b64decode(private_key)
            if customer in access_control and int(time.time()) < access_control[customer]:
                decrypted_content = elgamal_decrypt(private_key, encrypted_content)
                return jsonify({'content': decrypted_content})
            else:
                return jsonify({'error': 'Access denied'}), 403
        else:
            return jsonify({'error': 'Master key not found'}), 404
    else:
        return jsonify({'error': 'Content not found'}), 404

if __name__ == "__main__":
    init_db()
    app.run(port=5000)
