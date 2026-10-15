# A07:2025 - Authentication Failures

## Description
Authentication Failures occur when functions related to user identity, authentication, session tokens, and credentials are weak or incorrectly managed. Common issues include hardcoded API keys and secrets, credential stuffing vulnerabilities, lack of brute-force lockout / rate-limiting, session fixation, and tokens that do not expire upon logout.

## Vulnerable and Secure Code Examples

### Python

#### Vulnerable Code (Hardcoded Secrets & Missing Rate Limiting)
```python
# Flaw 1: Hardcoded credentials committed in source code
ADMIN_API_KEY = "example_dummy_admin_api_key_12345"

# Flaw 2: Vulnerable to credential stuffing / brute force
@app.route("/api/login", methods=["POST"])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    user = authenticate(username, password)
    if not user:
        return jsonify({"error": "Invalid password for user " + username}), 401 # Leaks valid usernames
    return jsonify({"token": create_session(user)})
```

#### Secure Code
```python
import os
from flask_limiter import Limiter

# Secure 1: Read secret keys from environment variables or secrets manager
API_KEY = os.environ.get("ADMIN_API_KEY")

# Secure 2: Rate limit login attempts & return generic authentication failure messages
limiter = Limiter(key_func=get_remote_address)

@app.route("/api/login", methods=["POST"])
@limiter.limit("5 per minute")
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    user = authenticate(username, password)
    if not user:
        # Prevent username enumeration through generic response
        return jsonify({"error": "Invalid username or password"}), 401
    
    session = create_secure_session(user)
    return jsonify({"token": session.token})
```

---

### Java

#### Vulnerable Code
```java
// Flaw: Hardcoded JWT signing secret and static lifetime
public class TokenService {
    private static final String SECRET = "mySuperSecretKey123456"; // Hardcoded secret

    public String generateToken(String username) {
        return Jwts.builder()
            .setSubject(username)
            .signWith(SignatureAlgorithm.HS256, SECRET.getBytes()) // Missing expiration!
            .compact();
    }
}
```

#### Secure Code
```java
public class SecureTokenService {
    private final Key signingKey;

    public SecureTokenService(@Value("${app.jwt.secret}") String secretKey) {
        this.signingKey = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public String generateToken(String username) {
        Instant now = Instant.now();
        return Jwts.builder()
            .setSubject(username)
            .setIssuedAt(Date.from(now))
            .setExpiration(Date.from(now.plus(15, ChronoUnit.MINUTES))) // Enforce short TTL
            .signWith(signingKey, SignatureAlgorithm.HS256)
            .compact();
    }
}
```

## Prevention Tips
1. Never commit secrets, passwords, or tokens in source code. Use `.gitignore` and tools like `gitleaks` or `trufflehog`.
2. Implement Multi-Factor Authentication (MFA) to mitigate compromised credentials.
3. Protect against brute-force attacks by rate-limiting failed logins and applying exponential backoff or CAPTCHAs.
4. Use unified error messages (e.g., "Invalid credentials") to prevent user enumeration.
5. Invalidate sessions and JWTs on logout and use short-lived access tokens with rotating refresh tokens.
