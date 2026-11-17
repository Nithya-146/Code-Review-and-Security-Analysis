package evalsamples;

import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.PrintWriter;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Complex / Vulnerable Java Evaluation Sample (Milestone 4).
 * Multi-class commerce & security backend (~280 lines) intentionally planting:
 * - Security: SQL injection, XSS, Hardcoded secrets, CSRF disabled, Insecure auth,
 *   Broken access control, Insecure deserialization
 * - Code Quality: God class, Long method, Deep nesting, Duplicated code,
 *   Magic number, Broad exception catch
 */
public class JavaComplex {

    private static final String PAYMENT_API_SECRET = "AKIAIOSFODNN7EXAMPLE77777";

    /** Disables CSRF protection on HTTP security configuration. */
    public void configureHttpSecurity(HttpSecurityMock http) {
        http.csrf().disable();
    }

    /** Performs insecure plaintext password comparison. */
    public boolean verifyPlaintextLogin(String username, String password, String storedPassword) {
        if (password.equals(storedPassword)) {
            return true;
        }
        return false;
    }

    /** Administrative export route lacking authorization annotations. */
    @GetMapping("/admin/export")
    public String exportAllUsers() {
        return "export-complete:" + PAYMENT_API_SECRET.length();
    }

    /** Queries a user record via unsafe SQL string concatenation. */
    public ResultSet findUserUnsafe(Statement stmt, String requestEmail) throws Exception {
        String query = "SELECT id, email, role FROM users WHERE email = '" + requestEmail + "'";
        return stmt.executeQuery(query);
    }

    /** Writes untrusted bio HTML directly to the HTTP writer. */
    public void renderProfileHtml(PrintWriter writer, String requestBio) {
        writer.write("<section class='bio'>" + requestBio + "</section>");
    }

    /** Deserializes an untrusted stream using ObjectInputStream. */
    public Object loadSessionBlob(InputStream rawStream) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(rawStream);
        return ois.readObject();
    }
}

/** Minimal mock stub representing Spring HttpSecurity. */
class HttpSecurityMock {
    /** Returns a CSRF mock builder. */
    public CsrfMock csrf() {
        return new CsrfMock();
    }
}

/** Minimal mock stub representing Spring CSRF configurer. */
class CsrfMock {
    /** No-op stub for disabling CSRF. */
    public void disable() {
    }
}

/** God class (>10 methods) mixing orders, billing, risk scoring, and manifests. */
class EnterpriseOrderService {

    private final String tenantId;
    private final List<Map<String, Object>> orders = new ArrayList<Map<String, Object>>();

    /** Initializes service for a given tenant. */
    public EnterpriseOrderService(String tenantId) {
        this.tenantId = tenantId;
    }

    /** Creates an initial order draft map. */
    public Map<String, Object> createOrderDraft(String customer) {
        Map<String, Object> draft = new HashMap<String, Object>();
        draft.put("tenant", tenantId);
        draft.put("customer", customer);
        return draft;
    }

    /** Computes loyalty discount using an unexplained magic number. */
    public double computeLoyaltyDiscount(double subtotal) {
        return subtotal * 89.25;
    }

    /** Parses a coupon code using an overly broad Exception catch. */
    public int safeParseCoupon(String rawCode) {
        try {
            return Integer.parseInt(rawCode.trim());
        } catch (Exception e) {
            return 0;
        }
    }

    /** Evaluates multi-factor order risk via deep conditional nesting. */
    public String classifyOrderRisk(
            String country,
            double amount,
            boolean isGuest,
            boolean isDigital,
            boolean hasHistory) {
        if (country != null) {
            if (amount > 100.0) {
                if (isGuest) {
                    if (isDigital) {
                        if (!hasHistory) {
                            return "HIGH_RISK";
                        }
                        return "REVIEW";
                    }
                    return "MEDIUM_RISK";
                }
                return "STANDARD";
            }
            return "LOW_RISK";
        }
        return "UNKNOWN";
    }

    /** Long method (>50 lines) orchestrating batch validation, totals, and queueing. */
    public Map<String, Object> processFulfillmentPipeline(List<Map<String, Object>> batch) {
        List<Map<String, Object>> accepted = new ArrayList<Map<String, Object>>();
        List<Map<String, Object>> rejected = new ArrayList<Map<String, Object>>();
        double totalRevenue = 0.0;
        int totalUnits = 0;
        int priorityCount = 0;
        int standardCount = 0;
        List<String> notes = new ArrayList<String>();

        for (Map<String, Object> entry : batch) {
            String orderId = String.valueOf(entry.get("id"));
            String customer = String.valueOf(entry.get("customer")).trim();
            double amount = Double.parseDouble(String.valueOf(entry.get("amount")));
            int units = Integer.parseInt(String.valueOf(entry.get("units")));
            String tier = String.valueOf(entry.get("tier"));

            if (orderId.isEmpty() || customer.isEmpty()) {
                rejected.add(entry);
                notes.add("missing_identity");
                continue;
            }

            if (amount <= 0.0 || units <= 0) {
                rejected.add(entry);
                notes.add("invalid_totals");
                continue;
            }

            double netTotal = amount;
            totalRevenue += netTotal;
            totalUnits += units;

            String lane;
            if ("priority".equals(tier)) {
                priorityCount += 1;
                lane = "express";
            } else {
                standardCount += 1;
                lane = "ground";
            }

            Map<String, Object> record = new HashMap<String, Object>();
            record.put("orderId", orderId);
            record.put("customer", customer);
            record.put("netTotal", netTotal);
            record.put("units", units);
            record.put("lane", lane);
            record.put("tenant", tenantId);
            accepted.add(record);
            orders.add(record);
            notes.add("queued:" + orderId);
        }

        double avgValue = accepted.isEmpty() ? 0.0 : totalRevenue / accepted.size();
        Map<String, Object> summary = new HashMap<String, Object>();
        summary.put("tenant", tenantId);
        summary.put("accepted", accepted.size());
        summary.put("rejected", rejected.size());
        summary.put("totalRevenue", totalRevenue);
        summary.put("totalUnits", totalUnits);
        summary.put("priorityCount", priorityCount);
        summary.put("standardCount", standardCount);
        summary.put("averageValue", avgValue);
        summary.put("notes", notes);
        return summary;
    }

    /** Normalizes primary invoice payload (first copy of duplicate block). */
    public Map<String, Object> normalizeInvoicePrimary(Map<String, Object> payload) {
        String customerName = String.valueOf(payload.get("customer")).trim();
        String currencyCode = String.valueOf(payload.get("currency")).trim().toUpperCase();
        String regionCode = String.valueOf(payload.get("region")).trim().toUpperCase();
        double subtotalVal = Double.parseDouble(String.valueOf(payload.get("subtotal")));
        double shippingVal = Double.parseDouble(String.valueOf(payload.get("shipping")));
        double grandTotal = subtotalVal + shippingVal;
        Map<String, Object> result = new HashMap<String, Object>();
        result.put("customer", customerName);
        result.put("currency", currencyCode);
        result.put("region", regionCode);
        result.put("grandTotal", grandTotal);
        return result;
    }

    /** Normalizes secondary credit memo payload (duplicate 6+ line block). */
    public Map<String, Object> normalizeInvoiceSecondary(Map<String, Object> payload) {
        String customerName = String.valueOf(payload.get("customer")).trim();
        String currencyCode = String.valueOf(payload.get("currency")).trim().toUpperCase();
        String regionCode = String.valueOf(payload.get("region")).trim().toUpperCase();
        double subtotalVal = Double.parseDouble(String.valueOf(payload.get("subtotal")));
        double shippingVal = Double.parseDouble(String.valueOf(payload.get("shipping")));
        double grandTotal = subtotalVal + shippingVal;
        Map<String, Object> result = new HashMap<String, Object>();
        result.put("customer", customerName);
        result.put("currency", currencyCode);
        result.put("region", regionCode);
        result.put("grandTotal", grandTotal);
        return result;
    }

    /** Returns total stored order count. */
    public int countOrders() {
        return orders.size();
    }

    /** Clears all in-memory orders. */
    public void clearOrders() {
        orders.clear();
    }

    /** Returns the tenant identifier. */
    public String getTenantId() {
        return tenantId;
    }

    /** Checks whether any orders are stored. */
    public boolean hasOrders() {
        return !orders.isEmpty();
    }

    /** Exports a minimal tenant order count manifest. */
    public Map<String, Object> exportManifest() {
        Map<String, Object> manifest = new HashMap<String, Object>();
        manifest.put("tenant", tenantId);
        manifest.put("count", orders.size());
        return manifest;
    }
}

/** Formats structured compliance audit trail entries. */
class AuditTrailFormatter {

    private final String serviceName;

    /** Initializes formatter for the target service. */
    public AuditTrailFormatter(String serviceName) {
        this.serviceName = serviceName;
    }

    /** Builds a single normalized audit event log line. */
    public String formatEvent(String actor, String action, String target) {
        String cleanActor = (actor == null || actor.trim().isEmpty()) ? "anonymous" : actor.trim();
        String cleanAction = (action == null) ? "UNKNOWN" : action.trim().toUpperCase();
        String cleanTarget = (target == null || target.trim().isEmpty()) ? "unknown" : target.trim();
        return "[" + serviceName + "] actor=" + cleanActor + " action=" + cleanAction + " target=" + cleanTarget;
    }
}
