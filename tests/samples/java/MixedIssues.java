package samples;

import java.io.File;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;

/**
 * Mixed Code Quality and Security Issues Sample in Java.
 */
public class MixedIssues {

    /**
     * Method with too many parameters containing Path Traversal.
     */
    public File resolveUploadPath(
        String baseDir,
        String fileName,
        String tenantId,
        String userId,
        String uploadType,
        String versionTag
    ) {
        return new File(baseDir + "/" + fileName);
    }

    /**
     * Spring Security configuration disabling CSRF protection and broad catch.
     */
    public void configureSecurity(HttpSecurity http) {
        try {
            http.csrf().disable();
        } catch (Exception e) {
            System.err.println("Security config failed");
        }
    }
}
