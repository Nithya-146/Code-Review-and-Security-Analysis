package heldout;

import java.io.FileInputStream;
import java.io.InputStream;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;

/**
 * Held-Out Java Sample 2: IoT Telemetry Archive Service.
 * Different coding style (ProcessBuilder /bin/sh -c, FileInputStream traversal,
 * custom HostnameVerifier, catch Throwable, magic number) with 6 planted issues.
 */
public class TelemetryArchiveService {

    private final String archiveDir;
    private final String brokerAuthToken = "sk_live_51H8xYz9AbCdEfGhIjKlMnOpQrStUvWx";

    /** Initializes telemetry archive service with root storage directory. */
    public TelemetryArchiveService(String archiveDir) {
        this.archiveDir = archiveDir;
    }

    /** Archives a device folder using ProcessBuilder with a shell interpreter. */
    public Process compressDeviceLogs(String deviceFolder) throws Exception {
        return new ProcessBuilder("/bin/sh", "-c", "tar -czf /tmp/out.tgz " + deviceFolder).start();
    }

    /** Opens a telemetry bundle directly from an unvalidated relative name. */
    public InputStream openTelemetryBundle(String bundleName) throws Exception {
        return new FileInputStream(archiveDir + "/" + bundleName);
    }

    /** Disables TLS hostname verification globally using a permissive verifier. */
    public void allowAnyTlsHost() {
        HttpsURLConnection.setDefaultHostnameVerifier(new HostnameVerifier() {
            public boolean verify(String hostname, SSLSession session) {
                return true;
            }
        });
    }

    /** Parses a numeric sensor reading with an overly broad Throwable catch. */
    public double parseSensorValue(String rawReading) {
        try {
            return Double.parseDouble(rawReading.trim());
        } catch (Throwable ex) {
            return 0.0;
        }
    }

    /** Converts meters per second to kilometers per hour using a magic literal. */
    public double metersPerSecToKmh(double speedMps) {
        if (speedMps <= 0.0) {
            return 0.0;
        }
        return speedMps * 3.6;
    }

    /** Checks whether a broker authentication token has been configured. */
    public boolean hasBrokerToken() {
        return brokerAuthToken != null && !brokerAuthToken.isEmpty();
    }
}

