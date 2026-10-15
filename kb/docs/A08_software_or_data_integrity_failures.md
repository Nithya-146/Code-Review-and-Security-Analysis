# A08:2025 - Software or Data Integrity Failures

## Description
Software and Data Integrity Failures relate to code and infrastructure that do not protect against integrity violations. A prime example is insecure deserialization (such as Python `pickle` or Java `ObjectInputStream`), where unvalidated serialized objects are unpacked by the application, giving attackers the ability to achieve Remote Code Execution (RCE). It also encompasses automatic updates without signature validation.

## Vulnerable and Secure Code Examples

### Python

#### Vulnerable Code (Insecure Deserialization via pickle)
```python
import pickle
import base64

@app.route("/api/restore_state", methods=["POST"])
def restore_state():
    data = request.json.get("state")
    # Flaw: Unpickling untrusted input allows arbitrary code execution via __reduce__
    raw_bytes = base64.b64decode(data)
    user_state = pickle.loads(raw_bytes)
    return jsonify({"status": "restored"})
```

#### Secure Code (Safe Structured Serialization via JSON / Pydantic)
```python
import json
from pydantic import BaseModel, Field

class UserState(BaseModel):
    user_id: int
    preferences: dict = Field(default_factory=dict)
    theme: str = "light"

@app.route("/api/restore_state", methods=["POST"])
def restore_state():
    # Secure: Use strict schema validation over standard JSON
    try:
        user_state = UserState.model_validate(request.json)
        return jsonify({"status": "restored", "theme": user_state.theme})
    except Exception as e:
        return jsonify({"error": "Malformed state payload"}), 400
```

---

### Java

#### Vulnerable Code (Insecure Deserialization via ObjectInputStream)
```java
import java.io.*;

public class StateManager {
    public Object deserializeFromNetwork(InputStream inputStream) throws Exception {
        // Flaw: Arbitrary class instantiations and gadget chains execute during readObject()
        ObjectInputStream ois = new ObjectInputStream(inputStream);
        return ois.readObject();
    }
}
```

#### Secure Code (JSON with Jackson / Whitelisted Filters)
```java
import com.fasterxml.jackson.databind.ObjectMapper;

public class SecureStateManager {
    private static final ObjectMapper mapper = new ObjectMapper();

    public UserProfile deserializeProfile(String jsonPayload) throws Exception {
        // Secure: Jackson without polymorphic default typing prevents gadget execution
        return mapper.readValue(jsonPayload, UserProfile.class);
    }
}
```

## Prevention Tips
1. Never deserialize untrusted data using native serialization formats (`pickle`, `yaml.load` without `SafeLoader`, Java `ObjectInputStream`, PHP `unserialize`).
2. Prefer standard serialization formats like JSON, Protocol Buffers, or CBOR with strict validation schemas.
3. If native deserialization is strictly mandatory, implement object look-ahead filters (e.g., `ValidatingObjectInputStream` in Java) or sign the serialized payload with HMAC-SHA256.
4. Ensure all deployment packages and client updates verify digital signatures (PGP / X.509) before execution.
