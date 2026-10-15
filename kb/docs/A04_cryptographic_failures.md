# A04:2025 - Cryptographic Failures

## Description
Cryptographic Failures (previously Sensitive Data Exposure) occur when cryptography is absent, improperly implemented, or uses broken algorithms (e.g., MD5, SHA-1, DES, RC4). Issues include transmitting sensitive data in cleartext (HTTP, FTP, Telnet), using predictable pseudorandom number generators (PRNGs) for security keys, hardcoded encryption keys, or insufficient password hashing (missing salt or insufficient work factor).

## Vulnerable and Secure Code Examples

### Python

#### Vulnerable Code
```python
import hashlib
import random

# Vulnerability 1: Fast, un-salted hashing algorithm for passwords
def hash_user_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

# Vulnerability 2: Predictable PRNG for security tokens
def generate_reset_token() -> str:
    return str(random.randint(100000, 999999))
```

#### Secure Code
```python
import bcrypt
import secrets

# Secure: Adaptive, salted algorithm (bcrypt / argon2)
def hash_user_password(password: str) -> str:
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(password.encode("utf-8"), salt).decode("utf-8")

def verify_user_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))

# Secure: Cryptographically secure random token
def generate_reset_token() -> str:
    return secrets.token_urlsafe(32)
```

---

### Java

#### Vulnerable Code
```java
import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class CryptoService {
    public static String hashPassword(String password) throws Exception {
        // Vulnerability: SHA-1 is vulnerable to collision attacks
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        byte[] digest = md.digest(password.getBytes());
        return bytesToHex(digest);
    }

    public static byte[] encryptData(byte[] data, byte[] key) throws Exception {
        // Vulnerability: DES is obsolete with a 56-bit key length
        SecretKeySpec keySpec = new SecretKeySpec(key, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(data);
    }
}
```

#### Secure Code
```java
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;

public class SecureCryptoService {
    private static final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(12);

    public static String hashPassword(String password) {
        return encoder.encode(password);
    }

    public static byte[] encryptAESGCM(byte[] plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[12];
        SecureRandom.getInstanceStrong().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ciphertext = cipher.doFinal(plaintext);
        
        // Prepend IV to ciphertext
        byte[] combined = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, combined, 0, iv.length);
        System.arraycopy(ciphertext, 0, combined, iv.length, ciphertext.length);
        return combined;
    }
}
```

## Prevention Tips
1. Classify all processed, stored, and transmitted data; apply encryption to all sensitive data in transit (TLS 1.3) and at rest (AES-256-GCM).
2. Never store passwords using fast hash algorithms (MD5, SHA-1, SHA-256). Use memory-hard/work-factor algorithms like Argon2id or bcrypt.
3. Use cryptographically secure pseudorandom number generators (CSPRNG) such as Python's `secrets` or Java's `SecureRandom`.
4. Ensure encryption keys are never committed into version control; use cloud key management services (AWS KMS, Azure Key Vault, HashiCorp Vault).
