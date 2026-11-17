package heldout;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;

/**
 * Held-Out Clean Java Sample: Immutable Financial Ledger Service.
 * Clean, well-documented, secure Java code with zero planted defects
 * used to measure false positives on unseen clean Java code.
 */
public class CleanLedgerService {

    private static final double BASIS_POINTS_DIVISOR = 10000.0;
    private static final int NONCE_BYTE_LENGTH = 16;

    private final Path exportBaseDir;
    private final SecureRandom secureRandom = new SecureRandom();

    /** Initializes the ledger service with a normalized export directory. */
    public CleanLedgerService(String exportBaseDir) {
        this.exportBaseDir = Paths.get(exportBaseDir).toAbsolutePath().normalize();
    }

    /** Loads the ledger signing key safely from environment variables. */
    public String loadSigningKey() {
        String key = System.getenv("LEDGER_SIGNING_KEY");
        return key == null ? "" : key;
    }

    /** Fetches a ledger entry safely using PreparedStatement parameter binding. */
    public ResultSet fetchEntryById(Connection conn, String entryId) throws Exception {
        PreparedStatement pstmt = conn.prepareStatement(
                "SELECT entry_id, amount_cents FROM ledger_entries WHERE entry_id = ?");
        pstmt.setString(1, entryId);
        return pstmt.executeQuery();
    }

    /** Computes a SHA-256 digest of a canonical ledger record. */
    public byte[] computeEntryHash(String canonicalRecord) throws Exception {
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        return sha256.digest(canonicalRecord.getBytes("UTF-8"));
    }

    /** Generates cryptographically strong random bytes for idempotency nonces. */
    public byte[] generateNonce() {
        byte[] nonce = new byte[NONCE_BYTE_LENGTH];
        secureRandom.nextBytes(nonce);
        return nonce;
    }

    /** Resolves an export filename while enforcing strict directory containment. */
    public Path resolveSafeExportPath(String requestedName) {
        Path candidate = exportBaseDir.resolve(requestedName).normalize();
        if (!candidate.startsWith(exportBaseDir)) {
            throw new IllegalArgumentException("Path escapes ledger export directory");
        }
        return candidate;
    }

    /** Converts fee basis points to a decimal fee amount using a named constant. */
    public double calculateFee(double principal, int feeBasisPoints) {
        if (principal <= 0.0 || feeBasisPoints <= 0) {
            return 0.0;
        }
        return principal * (feeBasisPoints / BASIS_POINTS_DIVISOR);
    }

    /** Parses a positive integer account index catching only NumberFormatException. */
    public int parseAccountIndex(String rawIndex) {
        try {
            int parsed = Integer.parseInt(rawIndex.trim());
            return Math.max(0, parsed);
        } catch (NumberFormatException ex) {
            return 0;
        }
    }

    /** Collects non-empty ledger reference codes in normalized uppercase form. */
    public List<String> normalizeReferenceCodes(List<String> rawCodes) {
        List<String> normalized = new ArrayList<String>();
        for (String code : rawCodes) {
            if (code != null && !code.trim().isEmpty()) {
                normalized.add(code.trim().toUpperCase());
            }
        }
        return normalized;
    }
}

