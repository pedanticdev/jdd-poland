# Modern Java Security: Zero Trust Architectures with Jakarta EE 11

Demo application for JDD Poland conference showcasing a Zero Trust security implementation using Jakarta EE 11, MicroProfile 7, and Payara.

This project demonstrates how to implement fine-grained security using standard specifications like MicroProfile JWT and Jakarta Security, while also showing how to extend them for advanced Attribute-Based Access Control (ABAC).

## Getting Started

### Prerequisites

- [Java SE 21+](https://adoptium.net/?variant=openjdk21)
- [Maven](https://maven.apache.org/download.cgi)
- [Docker](https://www.docker.com/get-started) and Docker Compose

## Quick Start

### 1. Start Keycloak and PostgreSQL

```bash
docker-compose up -d
```

This will start:
- **Keycloak** at http://localhost:8180 (admin/admin)
- **PostgreSQL** database for Keycloak

Wait for Keycloak to be fully started (check with `docker-compose logs -f keycloak`).

### 2. Verify Keycloak Setup

Access the Keycloak admin console at http://localhost:8180.

The realm `jdd-poland` will be automatically imported with:
- **4 pre-configured users** with different roles and attributes.
- **2 clients** (the main application and a service-to-service client).
- **4 roles** (DOCTOR, NURSE, ADMIN, PATIENT).

### 3. Run the Application

```bash
./mvnw clean package payara-micro:dev
```

The application will start at http://localhost:8080/

## Testing the API

Once the application is running, you can run the test script to see the security rules in action.

```bash
./test-api.sh
```

This script uses the pre-configured users to test various endpoints and demonstrates the RBAC and ABAC rules.

## Pre-configured Test Users

**Note:** The passwords listed below are temporary. Upon first login via the Keycloak UI, you will be required to set a new password.

| Username    | Password   | Role    | Department | Description                                                   |
|-------------|------------|---------|------------|---------------------------------------------------------------|
| dr.smith    | doctor123  | DOCTOR  | Cardiology | Can read/write patient records in the Cardiology dept.        |
| nurse.jones | nurse123   | NURSE   | Emergency  | Can read patient records in the Emergency dept.               |
| admin       | admin123   | ADMIN   | (N/A)      | Can perform system-wide operations (e.g., list all patients). |
| patient.doe | patient123 | PATIENT | (N/A)      | Has no access to the patient API.                             |

## Architecture

This application demonstrates Zero Trust security principles by leveraging standard Jakarta EE and MicroProfile APIs:

- **Authentication**: Handled by **MicroProfile JWT**. The application is configured with the issuer and public key location of the Keycloak server, and the Payara runtime automatically validates incoming JWTs.
- **Role-Based Access Control (RBAC)**: Implemented using the standard `jakarta.annotation.security.RolesAllowed` annotation.
- **Attribute-Based Access Control (ABAC)**: For more fine-grained control, we extend the standard security model. A custom `@RequireAttribute` annotation and a CDI interceptor (`AuthorizationInterceptor`) are used to validate claims from the JWT (e.g., ensuring a doctor can only access their own department).
- **Continuous Validation**: CDI interceptors (`AuditInterceptor`) are used for runtime monitoring and to generate security events.

### Input Validation

A key principle of Zero Trust is "Never Trust, Always Verify". This applies to all data entering the system. This demo uses Jakarta Bean Validation to enforce strict data validation at the API boundary. For a detailed explanation of the input validation strategy, see [VALIDATION_ZERO_TRUST.md](VALIDATION_ZERO_TRUST.md).

## Docker Commands

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop all services
docker-compose down

# Stop and remove volumes (clean slate)
docker-compose down -v
```

## Keycloak Configuration

Client credentials for application:
- **Client ID**: `jdd-healthcare-app`
- **Client Secret**: `jdd-healthcare-secret-2024`
- **Realm**: `jdd-poland`

Service-to-service client:
- **Client ID**: `service-client`
- **Client Secret**: `service-client-secret-2024`

## Development

The application uses:
- Jakarta EE 11
- Payara 7.2025.1.Beta1
- Java 21
- MicroProfile 7.0