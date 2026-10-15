# A01:2025 - Broken Access Control

## Description
Broken Access Control occurs when restrictions on what authenticated users are allowed to do are not properly enforced. Attackers can exploit these flaws to access unauthorized functionality, view sensitive data, modify other users' records, or change access rights (e.g., Insecure Direct Object References - IDOR, missing function level access control).

## Vulnerable and Secure Code Examples

### Python (Flask)

#### Vulnerable Code
```python
@app.route("/api/invoice/<int:invoice_id>", methods=["GET"])
@login_required
def get_invoice(invoice_id):
    # Vulnerability: IDOR - no verification that the invoice belongs to the current user
    invoice = db.session.query(Invoice).filter_by(id=invoice_id).first()
    return jsonify(invoice.to_dict())
```

#### Secure Code
```python
@app.route("/api/invoice/<int:invoice_id>", methods=["GET"])
@login_required
def get_invoice(invoice_id):
    # Secure: Verify ownership before returning data
    invoice = db.session.query(Invoice).filter_by(id=invoice_id, owner_id=current_user.id).first()
    if not invoice:
        abort(404, description="Invoice not found or access denied")
    return jsonify(invoice.to_dict())
```

---

### Java (Spring Boot)

#### Vulnerable Code
```java
@GetMapping("/documents/{docId}")
public ResponseEntity<Document> getDocument(@PathVariable Long docId) {
    // Vulnerability: IDOR - does not check if caller has permission for docId
    Document doc = documentRepository.findById(docId)
        .orElseThrow(() -> new ResourceNotFoundException("Not found"));
    return ResponseEntity.ok(doc);
}
```

#### Secure Code
```java
@GetMapping("/documents/{docId}")
@PreAuthorize("hasPermission(#docId, 'Document', 'READ')")
public ResponseEntity<Document> getDocument(@PathVariable Long docId, @AuthenticationPrincipal UserDetails user) {
    Document doc = documentRepository.findByIdAndOwner(docId, user.getUsername())
        .orElseThrow(() -> new AccessDeniedException("Access denied to requested document"));
    return ResponseEntity.ok(doc);
}
```

## Prevention Tips
1. Deny access by default: Except for public resources, require explicit authorization.
2. Implement access control mechanisms once and re-use them throughout the application.
3. Validate ownership on the server side for every request; never rely on hidden fields or client-side checks.
4. Disable directory browsing and ensure web server root directories do not expose sensitive files.
5. Log access control failures and rate-limit sensitive endpoints.
