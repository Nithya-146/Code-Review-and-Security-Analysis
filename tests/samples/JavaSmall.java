package evalsamples;

import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Small Java Evaluation Sample (Milestone 4).
 * Single class (~50 lines) with 3 planted issues:
 * - Hardcoded secret (CWE-798)
 * - SQL injection via Statement concatenation (CWE-89)
 * - Overly broad catch (Exception e) (broad_exception)
 */
public class JavaSmall {

    private static final String SERVICE_PASSWORD = "SuperSecretProdPassword#9911";

    /** Formats a readable display tag for an account record. */
    public String formatAccountTag(String accountId, String owner) {
        String safeOwner = (owner == null || owner.isEmpty()) ? "Unknown" : owner.trim();
        return accountId + ":" + safeOwner;
    }

    /** Fetches an account record using an unsafe concatenated SQL query. */
    public ResultSet lookupAccount(Statement stmt, String accountId) throws Exception {
        String query = "SELECT id, owner, balance FROM accounts WHERE id = '" + accountId + "'";
        return stmt.executeQuery(query);
    }

    /** Parses an integer quantity with an overly broad Exception catch. */
    public int parseQuantity(String rawQty) {
        try {
            int parsed = Integer.parseInt(rawQty.trim());
            return Math.max(0, parsed);
        } catch (Exception e) {
            return 0;
        }
    }

    /** Returns a non-sensitive configuration status label. */
    public String getServiceMarker() {
        return SERVICE_PASSWORD.isEmpty() ? "empty" : "configured";
    }
}
