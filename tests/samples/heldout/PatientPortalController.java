package heldout;

import java.io.IOException;
import java.io.PrintWriter;
import java.security.MessageDigest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.util.HashMap;
import java.util.Map;

/**
 * Held-Out Java Sample 1: Patient Portal Controller.
 * Different coding style (StringBuilder SQL, SHA-1 + Random, println XSS) with 5 planted issues:
 * - SQL injection using StringBuilder concatenated into executeQuery
 * - Cross-Site Scripting via response.getWriter().println
 * - Weak cryptography using SHA-1 MessageDigest
 * - CSRF protection disabled via securityBuilder.csrf().disable()
 * - Too many parameters in scheduleVisit (7 parameters)
 */
public class PatientPortalController {

    private static final String DEFAULT_CLINIC = "MAIN-CLINIC";

    /** Disables CSRF protection on the portal HTTP builder. */
    public void configurePortalSecurity(PortalSecurityBuilder securityBuilder) {
        securityBuilder.csrf().disable();
    }

    /** Looks up a patient record using StringBuilder SQL concatenation. */
    public ResultSet findPatientByMrn(Connection conn, String mrnParam) throws Exception {
        StringBuilder sb = new StringBuilder("SELECT id, full_name FROM patients WHERE mrn = '");
        sb.append(mrnParam).append("'");
        return conn.createStatement().executeQuery(sb.toString());
    }

    /** Writes an unescaped patient alias directly to the HTTP servlet response. */
    public void renderGreeting(MockHttpResponse response, String patientAlias) throws IOException {
        response.getWriter().println("<p class='greeting'>Hello " + patientAlias + "</p>");
    }

    /** Computes a weak SHA-1 digest over a patient appointment token. */
    public byte[] hashAppointmentToken(String tokenText) throws Exception {
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        return sha1.digest(tokenText.getBytes("UTF-8"));
    }

    /** Schedules an outpatient visit (accepts 7 parameters). */
    public Map<String, Object> scheduleVisit(
            String patientId,
            String clinicCode,
            String physicianId,
            String roomNo,
            String slotTime,
            String visitType,
            String intakeNotes) {
        Map<String, Object> booking = new HashMap<String, Object>();
        booking.put("patientId", patientId);
        booking.put("clinic", clinicCode == null ? DEFAULT_CLINIC : clinicCode);
        booking.put("physicianId", physicianId);
        booking.put("room", roomNo);
        booking.put("slot", slotTime);
        booking.put("type", visitType);
        booking.put("notes", intakeNotes);
        return booking;
    }

    /** Generates a display confirmation code using a non-sensitive prefix. */
    public String formatClinicHeader(String clinicName) {
        String clean = (clinicName == null || clinicName.trim().isEmpty()) ? DEFAULT_CLINIC : clinicName.trim();
        return "Portal :: " + clean;
    }
}

/** Minimal mock HTTP response stub for standalone compilation. */
class MockHttpResponse {
    /** Returns an output writer stub. */
    public PrintWriter getWriter() {
        return new PrintWriter(System.out);
    }
}

/** Minimal mock security builder stub. */
class PortalSecurityBuilder {
    /** Returns a CSRF configurer stub. */
    public PortalCsrf csrf() {
        return new PortalCsrf();
    }
}

/** Minimal mock CSRF stub. */
class PortalCsrf {
    /** Disables CSRF checks (stub). */
    public void disable() {
    }
}
