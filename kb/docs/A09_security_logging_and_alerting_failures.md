# A09:2025 - Security Logging and Alerting Failures

## Description
Security Logging and Alerting Failures occur when security-critical events (such as failed authentication attempts, privilege escalation, access control violations, or input validation errors) are not logged, logged with insufficient context, or never alerted upon in real time. Conversely, logging sensitive data (such as passwords, credit cards, or session tokens) or allowing log injection also introduces severe risks.

## Vulnerable and Secure Code Examples

### Python

#### Vulnerable Code
```python
# Flaw 1: Silent failure swallows attack indicators without logging
def transfer_funds(sender_id: int, recipient_id: int, amount: float):
    if amount > 10000:
        return False  # Denied silently; no alert or audit trail generated!

# Flaw 2: Log Injection / Sensitive data leak
def login_vulnerable(username: str, password_raw: str):
    # Flaw: Leaks plaintext password into log file and allows CRLF log spoofing via username
    logging.info(f"User login attempt: {username} with password {password_raw}")
```

#### Secure Code
```python
import logging
import json

security_logger = logging.getLogger("security_audit")

def transfer_funds_secure(sender_id: int, recipient_id: int, amount: float, client_ip: str):
    if amount > 10000:
        security_logger.warning(
            json.dumps({
                "event": "HIGH_VALUE_TRANSFER_BLOCKED",
                "sender_id": sender_id,
                "recipient_id": recipient_id,
                "amount": amount,
                "client_ip": client_ip,
                "status": "BLOCKED"
            })
        )
        return False
    return True

def login_secure(username: str, client_ip: str, success: bool):
    # Sanitize inputs (strip newlines) and never log passwords
    safe_username = username.replace("\r", "").replace("\n", "")[:50]
    security_logger.info(
        json.dumps({
            "event": "AUTH_ATTEMPT",
            "username": safe_username,
            "success": success,
            "ip_address": client_ip
        })
    )
```

---

### Java

#### Vulnerable Code
```java
public void processPayment(String creditCard, double amount) {
    try {
        paymentGateway.charge(creditCard, amount);
    } catch (PaymentException e) {
        // Flaw: Silent catch block hides fraudulent transactions or integration outages
    }
}
```

#### Secure Code
```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SecurePaymentService {
    private static final Logger secAudit = LoggerFactory.getLogger("SECURITY_AUDIT");

    public void processPayment(String maskedCard, double amount, String userId) {
        try {
            paymentGateway.charge(maskedCard, amount);
            secAudit.info("Payment succeeded for user={}, amount={}", userId, amount);
        } catch (PaymentException e) {
            secAudit.error("Payment failure anomaly detected: user={}, amount={}, reason={}", 
                userId, amount, e.getMessage());
            throw new PaymentFailedException("Transaction declined.");
        }
    }
}
```

## Prevention Tips
1. Ensure all login, access control failures, and server-side input validation failures are logged with sufficient user context.
2. Store logs in an append-only, tamper-resistant centralized system (e.g., Elasticsearch, Splunk, CloudWatch).
3. Sanitize log messages against CRLF Injection (`\r\n`) to prevent log forging.
4. Never log passwords, payment card details (PAN), session tokens, or personal identifiable information (PII).
5. Establish real-time alerting thresholds for repeated anomalous activities (e.g., 10 failed logins within 60 seconds).
