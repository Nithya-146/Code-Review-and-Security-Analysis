# Step 2 Study Notes: Code Review & Security Analysis Agent
OWASP Top 10:2025 edition. Examples are Python,then Java.

## 1. OWASP Top 10:2025 in one line each
| ID | Category | One-line meaning |
|----|----------|------------------|
| A01 | Broken Access Control | Users can do or see things they should not (e.g. change an ID in the URL to see another user's data) |
| A02 | Security Misconfiguration | Default passwords, debug mode on, open cloud storage, unsafe settings |
| A03 | Software Supply Chain Failures | Compromised or vulnerable dependencies, build tools, or update channels |
| A04 | Cryptographic Failures | Weak or missing encryption, weak hashing, exposed secrets in transit or storage |
| A05 | Injection | Untrusted input is run as code or a query (SQL, OS command, XSS) |
| A06 | Insecure Design | The design lacks security controls, so coding well cannot fix it |
| A07 | Authentication Failures | Weak passwords, hardcoded credentials, no lockout, broken sessions |
| A08 | Software or Data Integrity Failures | Unsafe deserialization, unverified updates |
| A09 | Security Logging and Alerting Failures | Attacks happen and nobody is alerted |
| A10 | Mishandling of Exceptional Conditions | Errors handled badly, leaking information or leaving the app unsafe |

New in 2025: A03 (Supply Chain) and A10 (Exceptional Conditions). Injection moved from A03 to A05, Cryptographic Failures from A02 to A04.

## 2. Vulnerability catalog (Python first, then Java)

### 2.1 SQL Injection | A05 Injection | CWE-89 | Severity: High
**How it works:** user input is joined into a SQL string, so an attacker changes the query (`' OR '1'='1`).

**Python (vulnerable)**
```python
cur.execute("SELECT * FROM users WHERE name = '" + name + "'")
```
**Python (fixed)**
```python
cur.execute("SELECT * FROM users WHERE name = ?", (name,))
```
**Java (vulnerable)**
```java
Statement st = conn.createStatement();
ResultSet rs = st.executeQuery("SELECT * FROM users WHERE name = '" + name + "'");
```
**Java (fixed)**
```java
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");
ps.setString(1, name);
ResultSet rs = ps.executeQuery();
```
**Why the fix works:** the query structure is fixed first; input is only ever data.
**How my agent detects it:** AST check for string concatenation or f-strings passed to `execute()`.

### 2.2 Cross-Site Scripting (XSS) | A05 Injection | CWE-79 | Severity: High
**How it works:** user input is placed in a page without escaping, so the attacker's script runs in other users' browsers.

**Python (vulnerable, Flask)**
```python
return render_template_string("<h1>Hello " + name + "</h1>")
```
**Python (fixed)**
```python
return render_template_string("<h1>Hello {{ name }}</h1>", name=name)
```
**Java (vulnerable, servlet)**
```java
out.println("<h1>Hello " + request.getParameter("name") + "</h1>");
```
**Java (fixed, OWASP Java Encoder)**
```java
import org.owasp.encoder.Encode;
out.println("<h1>Hello " + Encode.forHtml(request.getParameter("name")) + "</h1>");
```
**Why the fix works:** `<script>` becomes harmless text.
**How my agent detects it:** user input flowing into HTML output with no escape call in between.

### 2.3 Command Injection | A05 Injection | CWE-78 | Severity: Critical
**How it works:** user input is passed to a shell, so `; rm -rf` style input runs commands.

**Python (vulnerable)**
```python
os.system("ping -c 1 " + host)
```
**Python (fixed)**
```python
import re, subprocess
if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
    raise ValueError("invalid host")
subprocess.run(["ping", "-c", "1", host], check=True)
```
**Java (vulnerable)**
```java
Runtime.getRuntime().exec("ping -c 1 " + host);
```
**Java (fixed)**
```java
if (!host.matches("[A-Za-z0-9.-]+")) throw new IllegalArgumentException("invalid host");
new ProcessBuilder("ping", "-c", "1", host).start();
```
**Why the fix works:** no shell parses the input, and an allow-list limits what is accepted.

### 2.4 Hardcoded Credentials | A07 Authentication Failures | CWE-798 | Severity: High
**How it works:** passwords or API keys in source code leak through GitHub.

**Python (vulnerable)**
```python
API_KEY = "sk-12345-secret"
```
**Python (fixed)**
```python
import os
API_KEY = os.environ["API_KEY"]
```
**Java (vulnerable)**
```java
String apiKey = "sk-12345-secret";
```
**Java (fixed)**
```java
String apiKey = System.getenv("API_KEY");
```
**Also:** add `.env` to `.gitignore` and rotate any key that was ever committed.
**How my agent detects it:** regex for key patterns plus an entropy check on string literals.

### 2.5 Weak Password Hashing | A04 Cryptographic Failures | CWE-327 / CWE-328 | Severity: High
**How it works:** MD5 and SHA-1 are fast and broken, so stolen hashes are cracked quickly.

**Python (vulnerable)**
```python
import hashlib
hashed = hashlib.md5(password.encode()).hexdigest()
```
**Python (fixed)**
```python
import bcrypt
hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
```
**Java (vulnerable)**
```java
MessageDigest md = MessageDigest.getInstance("MD5");
byte[] hash = md.digest(password.getBytes());
```
**Java (fixed, Spring Security)**
```java
PasswordEncoder encoder = new BCryptPasswordEncoder();
String hash = encoder.encode(password);
```
**Why the fix works:** bcrypt is deliberately slow and adds a unique salt per password.

### 2.6 Broken Access Control (IDOR) | A01 Broken Access Control | CWE-639 | Severity: High
**How it works:** the app trusts an ID from the request and never checks who owns the record.

**Python (vulnerable)**
```python
invoice = db.get_invoice(invoice_id)
return jsonify(invoice)
```
**Python (fixed)**
```python
invoice = db.get_invoice(invoice_id)
if invoice.owner_id != current_user.id:
    abort(403)
return jsonify(invoice)
```
**Java (vulnerable)**
```java
Invoice invoice = repo.findById(invoiceId);
return invoice;
```
**Java (fixed)**
```java
Invoice invoice = repo.findById(invoiceId);
if (!invoice.getOwnerId().equals(currentUser.getId())) {
    throw new AccessDeniedException("Not your invoice");
}
return invoice;
```
**Why the fix works:** ownership is checked on the server for every request.

### ### 2.7 Cross-Site Request Forgery (CSRF) | A01 Broken Access Control | CWE-352 | Severity: Medium
**How it works:** a malicious site makes your logged-in browser send a request (e.g. change email) without your knowledge. It has no category of its own in the Top 10.

**Python (vulnerable, Flask)**
```python
@app.route("/change-email", methods=["POST"])
def change_email():
    user.email = request.form["email"]   # no token check
```
**Python (fixed, Flask-WTF)**
```python
from flask_wtf import CSRFProtect
csrf = CSRFProtect(app)   # and add {{ csrf_token() }} in every form
```
**Java (vulnerable, Spring Security)**
```java
http.csrf(csrf -> csrf.disable());
```
**Java (fixed)**
```java
http.csrf(Customizer.withDefaults());
```
**Also:** use `SameSite=Lax` or `Strict` cookies.

## 3. OWASP cheat sheet takeaways
- **SQL Injection Prevention:** parameterized queries first, then stored procedures, then allow-list validation. Never concatenate queries.
- **XSS Prevention:** escape output for its context (HTML, attribute, JavaScript, URL), use auto-escaping frameworks, add a Content-Security-Policy header.
- **CSRF Prevention:** synchronizer token per session, SameSite cookies, re-authentication for sensitive actions.
- **Secrets Management:** keep secrets out of code, use environment variables or a vault, rotate regularly, scan repos for leaked keys.

## 4. Ten code smells (Python first, then Java for two of them)
1. **Long Method:** one function does too much; split it.
2. **Large Class (God Class):** one class holds unrelated responsibilities.
3. **Duplicate Code:** the same logic copied in many places.
4. **Long Parameter List:** too many arguments; group them into an object.
5. **Deep Nesting:** many levels of if/for; use early returns.
6. **Magic Numbers:** unexplained constants; use named constants.
7. **Dead Code:** unused variables, functions, or branches.
8. **Feature Envy:** a method uses another class's data more than its own.
9. **Data Clumps:** the same group of variables always appears together.
10. **Primitive Obsession:** raw strings and ints instead of small meaningful types.

**Magic Numbers, Python**
```python
# smell
if status == 7: ...
# better
STATUS_SHIPPED = 7
if status == STATUS_SHIPPED: ...
```
**Magic Numbers, Java**
```java
// smell
if (status == 7) { ... }
// better
private static final int STATUS_SHIPPED = 7;
if (status == STATUS_SHIPPED) { ... }
```
**Deep Nesting, Python**
```python
# smell
if user:
    if user.active:
        if user.is_admin:
            do_work()
# better
if not user or not user.active or not user.is_admin:
    return
do_work()
```
**Deep Nesting, Java**
```java
// smell
if (user != null) { if (user.isActive()) { if (user.isAdmin()) { doWork(); } } }
// better
if (user == null || !user.isActive() || !user.isAdmin()) return;
doWork();
```

## 5. RAG in four steps (my pipeline is Python)
1. **Chunk:** split documents into pieces (about 500 characters, 50 overlap) so each holds one idea.
2. **Embed:** turn each chunk into a vector with `all-MiniLM-L6-v2`, so similar meanings sit close together.
3. **Store:** save vectors and metadata (source, topic, CWE) in ChromaDB.
4. **Retrieve:** embed the question, find the closest chunks, give them to the LLM so answers are grounded in real sources.

```python
from langchain_text_splitters import RecursiveCharacterTextSplitter
from sentence_transformers import SentenceTransformer
import chromadb

splitter = RecursiveCharacterTextSplitter(chunk_size=500, chunk_overlap=50)
chunks = splitter.split_text(document_text)

model = SentenceTransformer("all-MiniLM-L6-v2")
client = chromadb.PersistentClient(path="kb_store")
col = client.get_or_create_collection("secure_coding")
col.add(ids=[f"c{i}" for i in range(len(chunks))],
        documents=chunks,
        embeddings=model.encode(chunks).tolist(),
        metadatas=[{"source": "owasp_sqli"}] * len(chunks))

hits = col.query(query_embeddings=model.encode(["prevent SQL injection"]).tolist(), n_results=3)
```

## 6. How these notes feed my project
- Section 2 becomes my test set for measuring detection accuracy (precision and recall).
- Section 4 feeds the Code Analysis Agent.
- Section 3 becomes knowledge base content for the RAG assistant.
- Section 5 is the pipeline I build in the knowledge base module.

## 7. What will make my project different
- Static analysis (AST and taint checks) first, then LLM reasoning, not LLM alone.
- CWE IDs and severity scores with a confidence level for every finding.
- Re-scan every generated fix and only show fixes that pass.
- Precision and recall from my own vulnerable code samples.
- RAG answers that cite the source chunk.
- Uses the current OWASP Top 10:2025 categories, including A03 (check `requirements.txt` for vulnerable packages) and A10 (flag bare `except:` blocks and error messages that leak stack traces).

## 8. Open questions
- How do I avoid false positives in the Security Agent?
- How to handle large source files that exceed the LLM context window?
- How to ensure generated remediation diffs do not introduce regression bugs?
