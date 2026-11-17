package evalsamples;

import java.io.File;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Medium Java Evaluation Sample (Milestone 4).
 * Document administration helper (~135 lines) containing 5 security
 * vulnerabilities and 3 code quality issues.
 */
public class JavaMedium {

    private final String exportRoot;

    /** Initializes helper with export root directory. */
    public JavaMedium(String exportRoot) {
        this.exportRoot = exportRoot;
    }

    /** Searches reports by owner using unsafe SQL string concatenation. */
    public ResultSet searchReports(Statement stmt, String requestUser) throws Exception {
        String query = "SELECT id, title FROM reports WHERE owner = '" + requestUser + "'";
        return stmt.executeQuery(query);
    }

    /** Executes a diagnostic ping command using untrusted host input. */
    public Process archiveHostLogs(String requestHost) throws Exception {
        return Runtime.getRuntime().exec("ping -c 1 " + requestHost);
    }

    /** Writes an unescaped HTML banner directly to the response stream. */
    public void renderWelcomeBanner(PrintWriter writer, String requestName) {
        writer.write("<div class='banner'>Welcome " + requestName + "</div>");
    }

    /** Computes a payload digest using deprecated MD5 hashing. */
    public byte[] computeFileDigest(String payload) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("MD5");
        return digest.digest(payload.getBytes("UTF-8"));
    }

    /** Resolves an export file directly from an unvalidated user filename. */
    public File resolveExportFile(String requestFilename) {
        return new File(exportRoot + "/" + requestFilename);
    }

    /** Evaluates multi-factor approval status using deeply nested conditionals. */
    public String evaluateApprovalMatrix(
            String region,
            int tier,
            boolean isVerified,
            boolean hasBudget,
            boolean isUrgent) {
        if (region != null) {
            if (tier > 0) {
                if (isVerified) {
                    if (hasBudget) {
                        if (isUrgent) {
                            return "FAST_TRACK";
                        }
                        return "STANDARD_APPROVED";
                    }
                    return "BUDGET_HOLD";
                }
                return "VERIFY_REQUIRED";
            }
            return "INVALID_TIER";
        }
        return "MISSING_REGION";
    }

    /** Builds a notification payload (exceeds 5 parameters). */
    public Map<String, Object> buildNotificationEnvelope(
            String recipient,
            String sender,
            String subject,
            String body,
            String channel,
            int priority,
            String correlationId) {
        Map<String, Object> envelope = new HashMap<String, Object>();
        envelope.put("recipient", recipient);
        envelope.put("sender", sender);
        envelope.put("subject", subject);
        envelope.put("body", body);
        envelope.put("channel", channel);
        envelope.put("priority", priority);
        envelope.put("correlationId", correlationId);
        return envelope;
    }

    /** Calculates shipping fee using an unexplained magic number. */
    public double computeShippingFee(double subtotal) {
        if (subtotal <= 0.0) {
            return 0.0;
        }
        return subtotal * 47.5;
    }

    /** Formats non-null report titles into uppercase strings. */
    public List<String> summarizeTitles(List<String> titles) {
        List<String> cleaned = new ArrayList<String>();
        for (String entry : titles) {
            if (entry != null) {
                cleaned.add(entry.trim().toUpperCase());
            }
        }
        return cleaned;
    }
}
