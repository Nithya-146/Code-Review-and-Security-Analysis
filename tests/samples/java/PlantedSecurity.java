package samples;

import java.io.InputStream;
import java.io.ObjectInputStream;
import java.security.MessageDigest;
import java.sql.Statement;

/**
 * Planted Security Vulnerabilities Sample in Java.
 * Contains intentional security flaws for security_analysis agent.
 */
public class PlantedSecurity {

    private String dbPassword = "SecretAdminPassword987!";

    /**
     * SQL injection via Statement concatenation.
     */
    public void queryDatabase(Statement stmt, String userId) throws Exception {
        stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
    }

    /**
     * Command injection via Runtime.getRuntime().exec.
     */
    public void executeSystemCommand(String host) throws Exception {
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    /**
     * Weak cryptographic digest using MD5.
     */
    public MessageDigest createWeakDigest() throws Exception {
        return MessageDigest.getInstance("MD5");
    }

    /**
     * Insecure deserialization using ObjectInputStream.
     */
    public Object deserializePayload(InputStream in) throws Exception {
        return new ObjectInputStream(in).readObject();
    }
}
