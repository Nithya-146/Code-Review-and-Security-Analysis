"""
Unit tests for SecurityAgent (Step 2).

Verifies:
1. Vulnerable inline samples for both Python and Java trigger correct OWASP categories and line numbers.
2. Safe inline samples for both Python and Java produce zero findings.
3. Taint analysis yields high confidence (0.85-0.95) with tainted paths and lower confidence (0.4-0.6) without.
4. Agent operates safely without crashing when KB retriever is unavailable or fails.
5. All findings satisfy schema validation and CVSS scoring rules.
"""

from unittest.mock import MagicMock
import pytest

from agents.security import SecurityAgent
from app.schemas import OWASPCategory, SeverityLevel


@pytest.fixture
def security_agent() -> SecurityAgent:
    """Fixture providing a fresh SecurityAgent instance."""
    return SecurityAgent()


# ==============================================================================
# 1. Vulnerable Python Rule Samples
# ==============================================================================

def test_vulnerable_py_sql_injection(security_agent: SecurityAgent):
    code = """
import sqlite3

def get_user(conn, user_id):
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE id = '{user_id}'"
    cursor.execute(query)
    return cursor.fetchone()
"""
    findings = security_agent.run(code, language="python", filename="vuln_sqli.py")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-89"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A05
    assert f.severity == SeverityLevel.CRITICAL
    assert f.line_start == 7
    assert "cursor.execute" in f.code_snippet


def test_vulnerable_py_command_injection(security_agent: SecurityAgent):
    code = """
import os

def check_host(host):
    os.system("ping -c 1 " + host)
"""
    findings = security_agent.run(code, language="python", filename="vuln_cmdi.py")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-78"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A05
    assert f.line_start == 5


def test_vulnerable_py_xss(security_agent: SecurityAgent):
    code = """
from flask import render_template_string

def greeting(name):
    return render_template_string(f"<h1>Hello {name}</h1>")
"""
    findings = security_agent.run(code, language="python", filename="vuln_xss.py")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-79"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A05
    assert f.line_start == 5


def test_vulnerable_py_hardcoded_secret(security_agent: SecurityAgent):
    code = """
def authenticate():
    API_KEY = "AKIAIOSFODNN7EXAMPLE12345"
    return API_KEY
"""
    findings = security_agent.run(code, language="python", filename="vuln_secret.py")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-798"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A07
    assert f.line_start == 3


def test_vulnerable_py_weak_crypto(security_agent: SecurityAgent):
    code = """
import hashlib

def hash_token(data):
    return hashlib.md5(data.encode()).hexdigest()
"""
    findings = security_agent.run(code, language="python", filename="vuln_crypto.py")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-327"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A04
    assert f.line_start == 5


def test_vulnerable_py_deserialization(security_agent: SecurityAgent):
    code = """
import pickle

def load_payload(raw_bytes):
    return pickle.loads(raw_bytes)
"""
    findings = security_agent.run(code, language="python", filename="vuln_deserial.py")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-502"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A08
    assert f.line_start == 5


def test_vulnerable_py_path_traversal(security_agent: SecurityAgent):
    code = """
def read_upload(filename):
    with open("/var/data/" + filename, "r") as f:
        return f.read()
"""
    findings = security_agent.run(code, language="python", filename="vuln_traversal.py")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-22"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A01
    assert f.line_start == 3


def test_vulnerable_py_ssrf_tls(security_agent: SecurityAgent):
    code = """
import requests

def fetch_data(target_url):
    return requests.get(target_url, verify=False)
"""
    findings = security_agent.run(code, language="python", filename="vuln_tls.py")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-295"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A02
    assert f.line_start == 5


def test_vulnerable_py_debug_misconfiguration(security_agent: SecurityAgent):
    code = """
DEBUG = True
WTF_CSRF_ENABLED = False
"""
    findings = security_agent.run(code, language="python", filename="vuln_debug.py")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-209"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A02
    assert f.line_start == 2


# ==============================================================================
# 2. Vulnerable Java Rule Samples
# ==============================================================================

def test_vulnerable_java_sql_injection(security_agent: SecurityAgent):
    code = """
public class UserDao {
    public void queryUser(Statement stmt, String userId) throws SQLException {
        stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
    }
}
"""
    findings = security_agent.run(code, language="java", filename="UserDao.java")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-89"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A05
    assert f.line_start == 4


def test_vulnerable_java_command_injection(security_agent: SecurityAgent):
    code = """
public class PingService {
    public void executePing(String target) throws IOException {
        Runtime.getRuntime().exec("ping -c 1 " + target);
    }
}
"""
    findings = security_agent.run(code, language="java", filename="PingService.java")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-78"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A05
    assert f.line_start == 4


def test_vulnerable_java_xss(security_agent: SecurityAgent):
    code = """
public class UserServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
        PrintWriter out = resp.getWriter();
        out.println("<h1>Hello " + req.getParameter("name") + "</h1>");
    }
}
"""
    findings = security_agent.run(code, language="java", filename="UserServlet.java")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-79"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A05
    assert f.line_start == 5


def test_vulnerable_java_hardcoded_secret(security_agent: SecurityAgent):
    code = """
public class Config {
    private String dbPassword = "SecretAdminPassword987!";
}
"""
    findings = security_agent.run(code, language="java", filename="Config.java")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-798"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A07
    assert f.line_start == 3


def test_vulnerable_java_weak_crypto(security_agent: SecurityAgent):
    code = """
public class CryptoUtil {
    public MessageDigest getDigest() throws Exception {
        return MessageDigest.getInstance("MD5");
    }
}
"""
    findings = security_agent.run(code, language="java", filename="CryptoUtil.java")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-327"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A04
    assert f.line_start == 4


def test_vulnerable_java_deserialization(security_agent: SecurityAgent):
    code = """
public class Deserializer {
    public Object parse(InputStream in) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(in);
        return ois.readObject();
    }
}
"""
    findings = security_agent.run(code, language="java", filename="Deserializer.java")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-502"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A08
    assert f.line_start in (4, 5)


def test_vulnerable_java_path_traversal(security_agent: SecurityAgent):
    code = """
public class FileReader {
    public File getFile(String userPath) {
        return new File("/data/" + userPath);
    }
}
"""
    findings = security_agent.run(code, language="java", filename="FileReader.java")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-22"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A01
    assert f.line_start == 4


def test_vulnerable_java_tls_and_csrf(security_agent: SecurityAgent):
    code = """
public class SecurityConfig {
    public void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
    }
}
"""
    findings = security_agent.run(code, language="java", filename="SecurityConfig.java")
    assert len(findings) >= 1
    f = next((x for x in findings if x.cwe_id == "CWE-352"), None)
    assert f is not None
    assert f.owasp_category == OWASPCategory.A01
    assert f.line_start == 4


# ==============================================================================
# 3. Safe Samples Producing Zero Findings
# ==============================================================================

def test_safe_python_samples_produce_zero_findings(security_agent: SecurityAgent):
    safe_code = """
import os
import hashlib
import subprocess
import yaml
from pathlib import Path

# Safe SQL: Parameterized query
def safe_query(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = ?", (uid,))

# Safe Command: Process list invocation with shell=False
def safe_cmd(host):
    subprocess.run(["ping", "-c", "1", host], check=True)

# Safe Secrets: Loaded from environment variables
API_KEY = os.getenv("API_KEY")

# Safe Crypto: Modern SHA-256 hash
def safe_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Safe Deserialization: SafeLoader
def safe_yaml(content):
    return yaml.safe_load(content)

# Safe Traversal: Strict resolve and containment check
def safe_path(base_dir, user_filename):
    target = (base_dir / user_filename).resolve()
    if target.is_relative_to(base_dir):
        return open(target, "r")

# Safe Config
DEBUG = False
"""
    findings = security_agent.run(safe_code, language="python", filename="safe_samples.py")
    assert len(findings) == 0, f"Expected 0 findings for safe Python code, but found: {[f.title for f in findings]}"


def test_safe_java_samples_produce_zero_findings(security_agent: SecurityAgent):
    safe_code = """
public class SafeService {
    // Safe SQL: PreparedStatement
    public void safeSql(Connection conn, String id) throws SQLException {
        try (PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")) {
            pstmt.setString(1, id);
            pstmt.executeQuery();
        }
    }

    // Safe Command: ProcessBuilder with tokenized arguments
    public void safeCommand(String host) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
        pb.start();
    }

    // Safe Secret: Environment lookup
    private String apiKey = System.getenv("API_KEY");

    // Safe Crypto: SHA-256
    public MessageDigest safeCrypto() throws Exception {
        return MessageDigest.getInstance("SHA-256");
    }

    // Safe Path: Normalized containment check
    public File safeFile(Path base, String userPath) {
        Path resolved = base.resolve(userPath).normalize();
        if (resolved.startsWith(base)) {
            return resolved.toFile();
        }
        throw new SecurityException("Invalid path");
    }

    // Safe XSS: Contextual encoding
    public void safeOutput(PrintWriter out, String raw) {
        out.println(org.owasp.encoder.Encode.forHtml(raw));
    }
}
"""
    findings = security_agent.run(safe_code, language="java", filename="SafeService.java")
    assert len(findings) == 0, f"Expected 0 findings for safe Java code, but found: {[f.title for f in findings]}"


# ==============================================================================
# 4. Taint Check & Confidence Verification
# ==============================================================================

def test_taint_check_confidence_differential(security_agent: SecurityAgent):
    # Case A: Tainted input (from request.args) flows directly to dangerous sink
    tainted_code = """
def handle_request(request):
    user_cmd = request.args.get("command")
    os.system(user_cmd)
"""
    findings_tainted = security_agent.run(tainted_code, language="python", filename="tainted.py")
    assert len(findings_tainted) >= 1
    cmdi_tainted = next((f for f in findings_tainted if f.cwe_id == "CWE-78"), None)
    assert cmdi_tainted is not None
    assert 0.85 <= cmdi_tainted.confidence <= 0.95
    assert cmdi_tainted.severity_score == 9.8

    # Case B: Dangerous sink called with local static literal (no tainted path found)
    untainted_code = """
def run_internal_worker():
    static_cmd = "run_daily_backup"
    os.system(static_cmd)
"""
    findings_untainted = security_agent.run(untainted_code, language="python", filename="untainted.py")
    assert len(findings_untainted) >= 1
    cmdi_untainted = next((f for f in findings_untainted if f.cwe_id == "CWE-78"), None)
    assert cmdi_untainted is not None
    assert 0.40 <= cmdi_untainted.confidence <= 0.60
    assert cmdi_untainted.severity_score < cmdi_tainted.severity_score


# ==============================================================================
# 5. Resilience: Retriever Unavailable / Throwing Exception
# ==============================================================================

def test_agent_survives_when_kb_retriever_is_unavailable():
    agent = SecurityAgent()
    # Explicitly disable retriever
    agent.retriever = None

    code = "os.system('rm -rf /')"
    findings = agent.run(code, language="python", filename="test.py")
    assert len(findings) >= 1
    assert findings[0].evidence is None or findings[0].evidence == ""


def test_agent_survives_when_kb_retriever_raises_exception():
    agent = SecurityAgent()
    # Mock retriever to throw runtime error
    mock_retriever = MagicMock()
    mock_retriever.search.side_effect = RuntimeError("ChromaDB connection timed out")
    agent.retriever = mock_retriever

    code = "import hashlib\nhashlib.md5(b'123').hexdigest()"
    findings = agent.run(code, language="python", filename="test_resilience.py")
    assert len(findings) >= 1
    assert findings[0].evidence is None


# ==============================================================================
# 6. Finding Schema Details & CVSS Scoring Integrity
# ==============================================================================

def test_finding_schema_and_attributes(security_agent: SecurityAgent):
    code = """
import sqlite3
def get_user(conn, uid):
    conn.execute(f"SELECT * FROM users WHERE id = {uid}")
"""
    findings = security_agent.run(code, language="python", filename="User.py")
    assert len(findings) >= 1
    finding = findings[0]

    assert finding.id.startswith("SEC-")
    assert finding.agent == "security_analysis"
    assert finding.category == "Security Vulnerability"
    assert finding.owasp_category == OWASPCategory.A05
    assert finding.cwe_id == "CWE-89"
    assert finding.source == "rule"
    assert 0.0 <= finding.severity_score <= 10.0
    assert finding.line_start >= 1
    assert finding.line_end >= finding.line_start
    assert len(finding.explanation) > 10
    assert len(finding.suggestion) > 5
