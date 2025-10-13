package fish.payara.healthcare.config;

import jakarta.annotation.sql.DataSourceDefinition;
import jakarta.enterprise.context.ApplicationScoped;

@DataSourceDefinition(
    name = "java:global/jdbc/PatientDS",
    className = "org.postgresql.ds.PGSimpleDataSource",
    serverName = "${MPCONFIG=db.host}",
    portNumber = 5432,
    databaseName = "${MPCONFIG=db.name}",
    user = "${MPCONFIG=db.user}",
    password = "${MPCONFIG=db.password}"
)
@ApplicationScoped
public class AppConfig {
}
