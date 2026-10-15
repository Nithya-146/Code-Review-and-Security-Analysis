# A03:2025 - Software Supply Chain Failures

## Description
Software Supply Chain Failures involve vulnerabilities or compromises introduced through external software artifacts, dependencies, build pipelines, third-party repositories, or distribution channels. Risks include dependency confusion, typosquatting, unvetted open-source packages, outdated dependencies with known CVEs, compromised CI/CD pipelines, and unpinned package versions.

## Vulnerable and Secure Code Examples

### Python (Pip / Requirements)

#### Vulnerable Code
```text
# requirements.txt
# Vulnerability: Unpinned dependencies allow malicious or breaking upgrades automatically
requests
flask
pyyaml
urllib3
```
Or downloading dependencies directly over plain HTTP:
```bash
pip install --extra-index-url http://insecure-internal-mirror/simple/ somepackage
```

#### Secure Code
```text
# requirements.txt
# Secure: Pin exact versions and use hash verification
requests==2.32.3 --hash=sha256:70761ce403...
flask==3.0.3 --hash=sha256:a6b245...
pyyaml==6.0.1 --hash=sha256:bfdf54...
```
In pipeline verification:
```bash
pip-audit -r requirements.txt
pip install --require-hashes -r requirements.txt
```

---

### Java (Maven / Gradle)

#### Vulnerable Code
```xml
<!-- pom.xml -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.14.1</version> <!-- Vulnerable to Log4Shell (CVE-2021-44228) -->
</dependency>
<repositories>
    <!-- Vulnerability: insecure HTTP repository allows MitM payload tampering -->
    <repository>
        <id>custom-repo</id>
        <url>http://untrusted-repo.org/maven2</url>
    </repository>
</repositories>
```

#### Secure Code
```xml
<!-- pom.xml -->
<dependency>
    <groupId>org.apache.logging.log4j</groupId>
    <artifactId>log4j-core</artifactId>
    <version>2.24.1</version> <!-- Patched, vetted version -->
</dependency>
<!-- Enforce HTTPS only and scan with Dependency-Check plugin -->
<build>
    <plugins>
        <plugin>
            <groupId>org.owasp</groupId>
            <artifactId>dependency-check-maven</artifactId>
            <version>10.0.4</version>
        </plugin>
    </plugins>
</build>
```

## Prevention Tips
1. Maintain an inventory of all third-party components using Software Bill of Materials (SBOM) standards (CycloneDX or SPDX).
2. Pin exact versions of dependencies and enforce hash verification.
3. Continuously scan dependencies using tools like `pip-audit`, OWASP Dependency-Check, Snyk, or GitHub Dependabot.
4. Restrict package registries to trusted, verified internal mirrors using HTTPS and authentication.
5. Sign and verify CI/CD artifacts and release binaries cryptographically.
