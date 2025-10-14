package fish.payara.resource;

import jakarta.ws.rs.ApplicationPath;
import jakarta.ws.rs.core.Application;
import org.eclipse.microprofile.auth.LoginConfig;

/**
 * Configures RESTful Web Services for the application.
 */
@LoginConfig(authMethod = "MP-JWT", realmName = "jdd-poland")
@ApplicationPath("resources")
public class RestConfiguration extends Application {

}
