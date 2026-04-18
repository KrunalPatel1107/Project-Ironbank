# Month 2 Extension: Cryptography Fundamentals for DevSecOps

!!! abstract "💰 Cost: $0 — Free tools (OpenSSL, Python cryptography library)"

!!! danger "Why Every Security Engineer Needs Cryptography"
    You can't defend what you don't understand. This extension teaches cryptographic principles that underpin ALL of Phase 2-4: TLS encryption (Phase 2), KMS keys (Phase 2 m5), JWT tokens (Phase 3 m7), mTLS in Kubernetes (Phase 3 m9), Secrets Manager (Phase 4 m10). Without understanding symmetric/asymmetric crypto, key derivation, and certificate management, you're blindly trusting the tooling.

!!! info "Background Context"
    In Phase 1 Month 2, you learned hashing (MD5, SHA-256) in Python. This extension goes deeper: symmetric encryption (AES), asymmetric encryption (RSA, ECDSA), key derivation functions (PBKDF2, scrypt, argon2), TLS/mTLS certificates, and key rotation. You'll understand the cryptography BEHIND the AWS KMS, RDS encryption, and JWT tokens you've been using throughout the course.

---

## Part 1: Symmetric Encryption (AES)

**Symmetric:** Both parties share the same key (key = secret). Fast, but key distribution is hard.

### AES Fundamentals

```
AES = Advanced Encryption Standard
Block size: 128 bits (16 bytes)
Key sizes: 128, 192, 256 bits
Modes: ECB, CBC, CTR, GCM (we use GCM)

Encryption: plaintext + key → ciphertext
Decryption: ciphertext + key → plaintext
(attacker can't recover plaintext without the key)
```

### Lab: Encrypt & Decrypt with AES

```bash
pip install cryptography --break-system-packages

cat > ~/aes-demo.py << 'EOF'
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

# Generate a random 256-bit key (32 bytes)
key = os.urandom(32)
print(f"Key (hex): {key.hex()}")
# Output: a1b2c3d4... (64 hex chars = 32 bytes)

# Generate a random IV (Initialization Vector) — ensures same plaintext encrypts differently
iv = os.urandom(16)
print(f"IV (hex): {iv.hex()}")

# Encrypt a message using AES-256-GCM
cipher = Cipher(
    algorithms.AES(key),
    modes.GCM(iv),
    backend=default_backend()
)
encryptor = cipher.encryptor()
plaintext = b"SECRET CREDIT CARD: 4532-1234-5678-9999"
ciphertext = encryptor.update(plaintext) + encryptor.finalize()
tag = encryptor.tag  # Authentication tag (proves it wasn't tampered with)

print(f"Plaintext: {plaintext}")
print(f"Ciphertext (hex): {ciphertext.hex()}")
print(f"Auth tag (hex): {tag.hex()}")

# Decrypt
cipher2 = Cipher(
    algorithms.AES(key),
    modes.GCM(iv, tag),
    backend=default_backend()
)
decryptor = cipher2.decryptor()
recovered = decryptor.update(ciphertext) + decryptor.finalize()
print(f"Decrypted: {recovered}")
# Output: b"SECRET CREDIT CARD: 4532-1234-5678-9999"

# Tamper attempt: modify one byte of ciphertext
print("\n--- Tamper Attempt ---")
corrupted = ciphertext[:-1] + bytes([ciphertext[-1] ^ 1])  # Flip last bit
try:
    cipher3 = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor3 = cipher3.decryptor()
    decryptor3.update(corrupted) + decryptor3.finalize()
except Exception as e:
    print(f"❌ Tamper detected: {e}")
EOF

python3 ~/aes-demo.py
```

### When to Use Symmetric Encryption

- Encrypting data at rest (S3, database)
- Encrypting files locally
- Bulk data encryption (faster than asymmetric)

### Problem: Key Distribution

If Alice wants to send Bob an encrypted message, both need the same key. But how do they share it securely over an untrusted network? Answer: asymmetric encryption (next section).

---

## Part 2: Asymmetric Encryption (RSA, ECDSA)

**Asymmetric:** Two keys (public key + private key). Public key is shared; private key is secret.

```
Public key: Anyone can use to ENCRYPT messages
Private key: Only you can use to DECRYPT messages

Example: Your email is public (@gmail.com), but you're the only one with your password (private key)
```

### RSA Fundamentals

```
RSA Encryption:
  plaintext + public_key → ciphertext
  (anyone can encrypt)
  
RSA Decryption:
  ciphertext + private_key → plaintext
  (only owner can decrypt)
  
RSA Digital Signature:
  plaintext + private_key → signature
  (only owner can sign; anyone can verify signature is authentic)
```

### Lab: RSA Encryption & Digital Signatures

```bash
cat > ~/rsa-demo.py << 'EOF'
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Generate RSA key pair (2048-bit, recommended minimum for production)
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
public_key = private_key.public_key()

print("=== RSA Encryption ===")
message = b"I promise to pay $100 to Alice"

# Alice encrypts with Bob's public key
ciphertext = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(f"Plaintext: {message}")
print(f"Ciphertext (hex): {ciphertext.hex()[:50]}...")

# Only Bob (with private key) can decrypt
decrypted = private_key.decrypt(
    ciphertext,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print(f"Decrypted: {decrypted}")

print("\n=== RSA Digital Signature ===")
# Bob signs a document with his private key
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print(f"Signature (hex): {signature.hex()[:50]}...")

# Anyone can verify with Bob's public key
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("✅ Signature verified — message is authentic")
except Exception as e:
    print(f"❌ Signature invalid: {e}")

# Tamper attempt: modify message after signing
print("\n=== Tamper Attempt ===")
tampered = b"I promise to pay $1000 to Alice"  # Changed amount
try:
    public_key.verify(signature, tampered, ...)
except Exception:
    print("❌ Tamper detected — signature doesn't match modified message")
EOF

python3 ~/rsa-demo.py
```

### RSA in the Real World

- **TLS certificates:** Server's public key is signed by a Certificate Authority (CA)
- **Code signing:** Developers sign binaries with private key; users verify with public key
- **Kubernetes:** Pod's service account token is signed with cluster's private key
- **Container images:** Images signed with cosign (uses ECDSA, similar principle)

---

## Part 3: Key Derivation Functions (KDF)

**Problem:** Users have weak passwords (e.g., "password123"). You can't use this directly as a cryptographic key.

**Solution:** Key Derivation Functions (KDFs) stretch weak passwords into strong keys.

### PBKDF2 (Password-Based Key Derivation Function 2)

```
PBKDF2(password, salt, iterations, dkLen, hash_algo)

password:   "MyPassword"
salt:       random bytes (prevents rainbow tables)
iterations: 100,000 (slows down brute-force)
dkLen:      32 (output = 256-bit key)
hash_algo:  SHA-256

Output: A strong 256-bit key derived from the weak password
```

### Lab: Derive Keys from Passwords

```bash
cat > ~/kdf-demo.py << 'EOF'
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import os

# User's weak password
password = b"MyPassword"  # Weak, but we'll derive a strong key

# Generate a random salt (should be saved with the stored key)
salt = os.urandom(16)
print(f"Salt (hex): {salt.hex()}")

# Derive a 256-bit key from the password
kdf = PBKDF2(
    algorithm=hashes.SHA256(),
    length=32,  # 256 bits
    salt=salt,
    iterations=100000,  # Standard for 2024 (was 50k in 2012)
    backend=default_backend()
)
key = kdf.derive(password)
print(f"Derived key (hex): {key.hex()}")

# Now use this key for encryption (AES, etc.)
print(f"\nDerived key can now be used as an AES key")

# Demonstrate: same password + same salt = same key (deterministic)
kdf2 = PBKDF2(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)
key2 = kdf2.derive(password)
print(f"Derived key again: {key == key2}")  # True — deterministic

# But different salt = different key (good for preventing rainbow tables)
salt2 = os.urandom(16)
kdf3 = PBKDF2(algorithm=hashes.SHA256(), length=32, salt=salt2, iterations=100000, backend=default_backend())
key3 = kdf3.derive(password)
print(f"Different salt, same password: {key == key3}")  # False — unique per user
EOF

python3 ~/kdf-demo.py
```

### Modern KDFs (Better than PBKDF2)

| KDF | Iterations | Memory | Speed | When to Use |
|---|---|---|---|---|
| **PBKDF2** | 100,000 | Low | Slow | Legacy systems, if required |
| **bcrypt** | ~12 rounds | Moderate | Slow | Password hashing (not general KDF) |
| **scrypt** | 2^14 | HIGH | Slow | Extreme security (mining-resistant) |
| **Argon2** | 2 | HIGH | Moderate | Modern apps — recommended 2024 |

**Argon2 Example (Modern):**

```python
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash("MyPassword")  # One-way hash for password storage
# Later, verify:
ph.verify(hash, "MyPassword")  # True
ph.verify(hash, "WrongPassword")  # False
```

---

## Part 4: TLS/mTLS & Certificates

**TLS (Transport Layer Security)** uses both symmetric and asymmetric crypto:

```
TLS Handshake:
1. Client connects to server
2. Server sends its public key (in a certificate signed by CA)
3. Client verifies cert is signed by trusted CA
4. Client & server agree on a shared session key (using asymmetric encryption)
5. All subsequent traffic encrypted with session key (symmetric encryption)
```

### X.509 Certificates

A certificate is a public key + metadata + signature (from a CA).

```bash
# Generate a self-signed certificate (for testing only)
openssl req \
  -x509 \
  -newkey rsa:2048 \
  -keyout key.pem \
  -out cert.pem \
  -days 365 \
  -nodes \
  -subj "/CN=example.com"

# View the certificate
openssl x509 -in cert.pem -text -noout

# Output shows:
# Subject: CN=example.com
# Issuer: CN=example.com (self-signed — not trusted by browsers)
# Public Key: RSA 2048-bit
# Validity: Jan 1 2024 - Jan 1 2025
# Signature Algorithm: sha256WithRSAEncryption
```

### Key Rotation for TLS Certificates

Certificates have expiration dates (usually 1 year). You must rotate them:

```bash
# Before expiration, generate a new cert
# Kubernetes automatically injects the new cert into pods
# No app restarts needed (with Kubernetes cert-manager)

# Check when your cert expires
openssl x509 -in cert.pem -noout -dates
# notBefore=Jan 1 2024
# notAfter=Jan 1 2025  ← Rotate before this date!

# Monitor cert expiration
openssl x509 -in cert.pem -noout -dates | grep notAfter
```

### mTLS in Kubernetes

Both client and server present certificates:

```bash
# Client cert: issued to application (e.g., "frontend.default.svc.cluster.local")
# Server cert: issued to service (e.g., "backend.default.svc.cluster.local")
# Each cert signed by the cluster's CA

# Verify cert issued to you:
openssl x509 -in client.crt -noout -subject
# Subject: CN=frontend.default.svc.cluster.local

# Both certs must be signed by the same CA for trust
openssl verify -CAfile ca.crt client.crt
# OK
```

---

## Part 5: Quantum Resistance & Future Crypto

**Quantum Computing Threat:** RSA and ECDSA will be broken by quantum computers (estimated 10-20 years).

**Post-Quantum Cryptography:** Algorithms believed to be resistant to quantum attacks.

### NIST Post-Quantum Standards (2024)

| Algorithm | Use Case | Status |
|---|---|---|
| **ML-KEM (Kyber)** | Key encapsulation | FIPS 203 (approved 2024) |
| **ML-DSA (Dilithium)** | Digital signatures | FIPS 204 (approved 2024) |
| **SLH-DSA (SPHINCS+)** | Stateless signatures | FIPS 205 (approved 2024) |

### What You Need to Know (2024)

- Start using post-quantum keys NOW if you store long-term secrets (30-year data)
- Governments/critical infrastructure moving to quantum-safe crypto
- Most apps can wait 5-10 years, but cloud providers are preparing
- Hybrid approach: use RSA + ML-KEM together until you're ready to switch fully

```bash
# Most tools don't support post-quantum yet, but prepare:
# - Monitor OpenSSL, Python cryptography library for post-quantum support
# - Design key rotation so you can swap algorithms later
```

---

## Part 6: Write a Cryptography Security Finding

```bash
cat > ~/crypto-finding.md << 'EOF'
# Finding: Weak Key Derivation Function (KDF) for Password Hashing

**Severity:** High  
**Component:** User Authentication (password storage)  

## Description
User passwords are hashed using MD5 instead of a proper KDF (PBKDF2, Argon2).
MD5 is cryptographically broken — attackers can crack millions of passwords/second
using rainbow tables and GPUs.

## Example
```
Stored in database:
  username: alice
  password_hash: 5d41402abc4b2a76b9719d911017c592  (MD5 of "hello")

Attacker downloads database, runs:
  hashcat -m 0 -a 0 hashes.txt rockyou.txt
  (cracks MD5 hashes against dictionary in minutes)
```

## Risk
- Attackers can compromise user accounts
- Passwords reused elsewhere (same email/password on 3 services)
- Lateral movement to other systems

## Remediation
Use Argon2 (2024 standard):
```python
from argon2 import PasswordHasher
ph = PasswordHasher()
hash = ph.hash(user_password)  # Store this
# Later, verify:
ph.verify(hash, attempted_password)
```
EOF

cat ~/crypto-finding.md
```

---

## 🧹 Cleanup

```bash
rm -f ~/aes-demo.py ~/rsa-demo.py ~/kdf-demo.py ~/crypto-finding.md
rm -f cert.pem key.pem

echo "✅ Cryptography lab cleaned up"
```

---

## Checklist

**Symmetric Encryption (AES)**
- [ ] Can explain: AES block size (128 bits), key sizes (128/192/256 bits)
- [ ] Understand modes: ECB (insecure), CBC, CTR, GCM (authenticated)
- [ ] Ran AES encryption/decryption lab in Python
- [ ] Can explain: IV (Initialization Vector) and why it matters
- [ ] Know when to use symmetric (bulk data, at-rest)

**Asymmetric Encryption (RSA/ECDSA)**
- [ ] Can explain public/private key pairs and their purpose
- [ ] Know when to use asymmetric (key exchange, signatures)
- [ ] Ran RSA encryption/decryption lab
- [ ] Ran RSA digital signature lab — understand tampering detection
- [ ] Can explain: anyone can verify a signature, but only owner can create it

**Key Derivation Functions (KDF)**
- [ ] Understand PBKDF2 (password → strong key)
- [ ] Know parameters: salt, iterations, output length
- [ ] Can explain why salt prevents rainbow tables
- [ ] Ran KDF lab in Python
- [ ] Know modern alternatives: Argon2 (recommended 2024)
- [ ] Understand: never use MD5/SHA1 for password hashing

**TLS & Certificates**
- [ ] Can draw TLS handshake (client/server cert exchange)
- [ ] Understand X.509 certificate structure (subject, issuer, public key)
- [ ] Generated a self-signed certificate using openssl
- [ ] Know certificate expiration and rotation requirements
- [ ] Understand mTLS: both client and server present certificates

**Quantum Cryptography**
- [ ] Know: RSA/ECDSA will be broken by quantum computers (10-20 years)
- [ ] Can name NIST post-quantum algorithms (ML-KEM, ML-DSA, SLH-DSA)
- [ ] Understand hybrid approach (RSA + ML-KEM together)
- [ ] Know when to start migrating (now for long-term secrets, 5-10 years for others)

**Real-World Application**
- [ ] Can explain: JWT tokens (asymmetric signature verification)
- [ ] Can explain: AWS KMS (uses AES for at-rest encryption)
- [ ] Can explain: TLS in Phase 2 RDS encryption
- [ ] Can explain: mTLS in Phase 3 Kubernetes (Service Mesh)
- [ ] Understand cryptography as the FOUNDATION for all Phase 2-4 security

---

## Integration with Course

This cryptography extension is foundational for:
- **Phase 2 m5:** RDS encryption (AES at rest, TLS in transit)
- **Phase 2 m6:** KMS keys (HSM storage of asymmetric keys)
- **Phase 3 m7:** JWT tokens (RSA/ECDSA signature verification)
- **Phase 3 m9:** Kubernetes mTLS (certificate-based auth)
- **Phase 4 m10:** Secrets Manager (KMS + asymmetric encryption)
- **Phase 4 m11:** Compliance frameworks (require encryption with key rotation)

You now have the **cryptographic fundamentals** to understand every encryption mechanism in the Iron Bank curriculum. 🎓
