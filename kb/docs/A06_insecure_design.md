# A06:2025 - Insecure Design

## Description
Insecure Design represents fundamental design and architectural weaknesses where security controls and threat modeling were omitted prior to code implementation. A perfect implementation of an insecure design remains vulnerable because the core business logic, trust boundaries, or risk assessments were flawed (e.g., unlimited credential recovery attempts, lack of transaction rate limits, or trusting unauthenticated client inputs for price calculations).

## Vulnerable and Secure Code Examples

### Python (E-Commerce Checkout)

#### Vulnerable Code
```python
# Flaw: The client specifies the total price or discounts directly in the payload
@app.route("/api/checkout", methods=["POST"])
def checkout():
    cart_items = request.json.get("items")
    client_total = request.json.get("total_amount") # Trusting client for monetary calculation!
    
    payment_gateway.charge(amount=client_total)
    db.create_order(items=cart_items, paid=client_total)
    return jsonify({"status": "order placed"})
```

#### Secure Code
```python
@app.route("/api/checkout", methods=["POST"])
@login_required
def checkout():
    cart_items = request.json.get("items")
    
    # Secure Design: Server calculates prices from trusted DB authority
    total_amount = Decimal("0.00")
    for item in cart_items:
        product = db.session.query(Product).filter_by(id=item["product_id"]).first()
        if not product:
            abort(400, "Invalid item")
        total_amount += product.price * item["quantity"]
        
    payment_gateway.charge(amount=total_amount)
    db.create_order(items=cart_items, paid=total_amount, user_id=current_user.id)
    return jsonify({"status": "order placed", "amount_charged": str(total_amount)})
```

---

### Java (Password Reset Workflow)

#### Vulnerable Code
```java
// Flaw: Secret questions with predictable answers (e.g., favorite color)
public boolean verifySecurityQuestion(String username, String answer) {
    User user = userRepository.findByUsername(username);
    return user.getSecurityAnswer().equalsIgnoreCase(answer); // Easily guessable / brute-forced
}
```

#### Secure Code
```java
// Secure Design: Time-limited, cryptographically random single-use tokens sent via verified out-of-band channel
public void initiatePasswordReset(String email) {
    User user = userRepository.findByEmail(email);
    if (user != null) {
        String token = tokenService.generateSecureToken(user, Duration.ofMinutes(15));
        emailService.sendPasswordResetLink(user.getEmail(), token);
    }
    // Rate limit per IP and email to prevent enumeration
}
```

## Prevention Tips
1. Establish and use a secure software development lifecycle (SSDLC) with threat modeling (e.g., STRIDE) early in the design phase.
2. Formulate abuse cases and evaluate threat boundaries between frontend, backend microservices, and external partners.
3. Segregate tenant data strictly at the architecture tier and enforce defense-in-depth principles.
4. Integrate unit and integration tests specifically to validate that business limits and security invariants cannot be bypassed.
