# A05:2025 - Injection

## Description
Injection flaws (including SQL Injection, Command Injection, Cross-Site Scripting / HTML Injection, and LDAP Injection) occur when hostile or untrusted data is sent to an interpreter as part of a command or query. The attacker's hostile data tricks the interpreter into executing unintended commands or accessing unauthorized data without proper authorization.

## Vulnerable and Secure Code Examples

### Python

#### Vulnerable Code (SQL Injection & Command Injection)
```python
import sqlite3
import os

# SQL Injection
def get_user_vulnerable(username: str):
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Flaw: String concatenation in SQL query
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return cursor.fetchall()

# Command Injection
def ping_host_vulnerable(host: str):
    # Flaw: Raw user input passed to system shell
    os.system("ping -c 1 " + host)
```

#### Secure Code (SQL Injection & Command Injection)
```python
import sqlite3
import subprocess
import re

# Secure SQL: Parameterized query
def get_user_secure(username: str):
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        query = "SELECT * FROM users WHERE username = ?"
        cursor.execute(query, (username,))
        return cursor.fetchall()

# Secure Command Execution: List-based arguments without shell execution
def ping_host_secure(host: str):
    # Strict validation via allow-list regex
    if not re.fullmatch(r"^[a-zA-Z0-9.-]+$", host):
        raise ValueError("Invalid hostname format")
    result = subprocess.run(
        ["ping", "-c", "1", host],
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout
```

---

### Java

#### Vulnerable Code (SQL Injection)
```java
import java.sql.*;

public class UserService {
    public ResultSet findUser(Connection conn, String username) throws SQLException {
        Statement stmt = conn.createStatement();
        // Flaw: Untrusted input formatted directly into query string
        String sql = "SELECT id, email FROM accounts WHERE username = '" + username + "'";
        return stmt.executeQuery(sql);
    }
}
```

#### Secure Code (SQL Injection)
```java
import java.sql.*;

public class SecureUserService {
    public ResultSet findUser(Connection conn, String username) throws SQLException {
        // Secure: Prepared statement with typed parameter binding
        String sql = "SELECT id, email FROM accounts WHERE username = ?";
        PreparedStatement pstmt = conn.prepareStatement(sql);
        pstmt.setString(1, username);
        return pstmt.executeQuery();
    }
}
```

## Prevention Tips
1. Use safe APIs that avoid the interpreter entirely or provide a parameterized interface (e.g., PreparedStatements in JDBC, parameterized queries with SQLAlchemy / SQLite, ORMs with proper parameter binding).
2. For command execution, avoid invoking shell interpreters (`shell=True` in Python, `sh -c` / `cmd.exe`). Pass argument lists directly using `subprocess.run` or `ProcessBuilder`.
3. Apply context-aware output encoding (HTML entity encoding, URL encoding) before rendering data in web browsers.
4. Use positive input validation (allow-lists) rather than trying to filter out known bad characters (block-lists).
