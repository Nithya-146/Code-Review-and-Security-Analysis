# A02:2025 - Security Misconfiguration

## Description
Security Misconfiguration represents insecure default configurations, incomplete or ad-hoc configurations, open cloud storage buckets, misconfigured HTTP headers, unnecessary features enabled (such as debug mode), and verbose error messages containing stack traces or sensitive internal details.

## Vulnerable and Secure Code Examples

### Python (Django / Flask)

#### Vulnerable Code
```python
# settings.py / app.py
DEBUG = True
ALLOWED_HOSTS = ['*']
SECRET_KEY = 'insecure-default-key'

@app.errorhandler(500)
def internal_server_error(e):
    # Vulnerability: Leaks raw stack trace and environment details to end users
    import traceback
    return f"<pre>{traceback.format_exc()}</pre>", 500
```

#### Secure Code
```python
import os

DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1")
ALLOWED_HOSTS = os.getenv("ALLOWED_HOSTS", "myapp.example.com").split(",")
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]

@app.errorhandler(500)
def internal_server_error(e):
    # Secure: Log trace internally, show generic error to client
    app.logger.error("Internal Server Error: %s", str(e), exc_info=True)
    return jsonify({"error": "An internal error occurred. Please contact support."}), 500
```

---

### Java (Spring Boot)

#### Vulnerable Code
```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: "*"  # Vulnerability: Exposes all actuator endpoints including heapdump, env, shutdown
server:
  error:
    include-stacktrace: always
```

#### Secure Code
```yaml
# application.yml
management:
  endpoints:
    web:
      exposure:
        include: "health,info"
server:
  error:
    include-stacktrace: never
```

## Prevention Tips
1. Implement automated hardening processes and repeatable configuration templates.
2. Disable debug modes, unused ports, features, services, and framework sample applications in production.
3. Apply security headers: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Content-Type-Options: nosniff, and X-Frame-Options: DENY.
4. Keep secrets, keys, and credentials externalized in a dedicated vault or environment variables.
