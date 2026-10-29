package samples;

import java.io.File;
import java.io.PrintWriter;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

/**
 * Tricky Safe Java Sample.
 * Demonstrates secure implementations that must produce zero findings.
 */
public class TrickySafe {

    private String apiKey = System.getenv("API_KEY");

    /**
     * Safe SQL: PreparedStatement with bind variable placeholder.
     */
    public void queryAccount(Connection conn, String accountId) throws Exception {
        try (PreparedStatement pstmt = conn.prepareStatement("SELECT * FROM accounts WHERE id = ?")) {
            pstmt.setString(1, accountId);
            try (ResultSet rs = pstmt.executeQuery()) {
                if (rs.next()) {
                    System.out.println("Account found");
                }
            }
        }
    }

    /**
     * Safe Command: ProcessBuilder with separate tokenized arguments.
     */
    public void runPing(String host) throws Exception {
        ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
        pb.start();
    }

    /**
     * Safe Crypto: SHA-256 digest.
     */
    public MessageDigest getSecureDigest() throws Exception {
        return MessageDigest.getInstance("SHA-256");
    }

    /**
     * Safe Path: Normalization and directory boundary containment check.
     */
    public File getSafeFile(Path baseDirectory, String userSuppliedPath) {
        Path resolved = baseDirectory.resolve(userSuppliedPath).normalize();
        if (resolved.startsWith(baseDirectory)) {
            return resolved.toFile();
        }
        throw new SecurityException("Directory traversal attack detected");
    }

    /**
     * Safe XSS: Contextual output encoding.
     */
    public void renderGreeting(PrintWriter out, String rawInput) {
        out.println(org.owasp.encoder.Encode.forHtml(rawInput));
    }
}
