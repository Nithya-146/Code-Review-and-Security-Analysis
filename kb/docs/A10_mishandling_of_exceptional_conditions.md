# A10:2025 - Mishandling of Exceptional Conditions

## Description
Mishandling of Exceptional Conditions involves failing to anticipate, safely catch, or properly respond to runtime exceptions, errors, and boundary condition states. Common flaws include bare `except:` blocks that mask catastrophic errors or system aborts, empty `catch` blocks that leave applications in an inconsistent or vulnerable state (fail-open rather than fail-secure), and unhandled exceptions that crash the service or leak stack traces and sensitive internals.

## Vulnerable and Secure Code Examples

### Python

#### Vulnerable Code
```python
# Flaw 1: Bare except catches SystemExit/KeyboardInterrupt and masks security failures
def verify_admin_token(token: str) -> bool:
    try:
        payload = decode_jwt(token)
        return payload.get("is_admin", False)
    except:
        # Dangerous: Bare except hides bugs and might fail open or silently pass
        return True # Or pass without error logging!

# Flaw 2: Error leaking internal database details
def query_user(user_id: int):
    try:
        return db.find(user_id)
    except Exception as e:
        # Flaw: Leaking raw database stack trace directly to HTTP client
        return {"error": str(e), "traceback": repr(e)}, 500
```

#### Secure Code
```python
import logging
from jwt import PyJWTError

logger = logging.getLogger(__name__)

def verify_admin_token(token: str) -> bool:
    try:
        payload = decode_jwt(token)
        return bool(payload.get("is_admin", False))
    except PyJWTError as e:
        logger.warning("JWT validation failed: %s", str(e))
        return False  # Fail-secure: default to denying access on error
    except Exception as e:
        logger.error("Unexpected error in auth verification", exc_info=True)
        return False

def query_user(user_id: int):
    try:
        return db.find(user_id)
    except DatabaseConnectionError:
        logger.error("Database connection failure during query_user(%s)", user_id, exc_info=True)
        # Fail-secure: Return clean, sanitized error message
        return {"error": "Service temporarily unavailable"}, 503
```

---

### Java

#### Vulnerable Code
```java
// Flaw: Empty catch block leaves transaction half-committed (fail-open state)
public boolean transferBalance(String fromAccount, String toAccount, BigDecimal amount) {
    try {
        debit(fromAccount, amount);
        credit(toAccount, amount);
        return true;
    } catch (Exception e) {
        // Flaw: Swallowing exception without rollback causes financial corruption
        return false;
    }
}
```

#### Secure Code
```java
@Transactional(rollbackFor = Exception.class)
public boolean transferBalance(String fromAccount, String toAccount, BigDecimal amount) {
    try {
        debit(fromAccount, amount);
        credit(toAccount, amount);
        return true;
    } catch (AccountNotFoundException | InsufficientFundsException e) {
        log.warn("Transfer rejected: {}", e.getMessage());
        throw e; // Propagate checked business error
    } catch (Exception e) {
        log.error("Fatal transaction error during transfer", e);
        throw new TransactionProcessingException("Transfer failed safely. System rolled back.");
    }
}
```

## Prevention Tips
1. Never use bare `except:` in Python or empty `catch (Exception e) {}` in Java. Always catch specific, expected exception types.
2. Ensure systems fail-secure: if an exception occurs during authentication, authorization, or monetary operations, default to closed/deny.
3. Guarantee proper resource cleanup and transactional atomicity via context managers (`with` statements in Python) or `try-with-resources` in Java.
4. Return generic, sanitized error messages to end users while preserving detailed stack traces in internal, secured log stores.
