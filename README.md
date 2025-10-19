# Modern Java Security: Zero Trust Architectures with Jakarta EE 11

Demo application for JDD Poland conference showcasing a Zero Trust security implementation using Jakarta EE 11,
MicroProfile 7, and Payara.

This project demonstrates how to implement fine-grained security using standard specifications like MicroProfile JWT and
Jakarta Security, while also showing how to extend them for advanced Attribute-Based Access Control (ABAC).

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

The `test-api.sh` script is included to demonstrate how the API endpoints can be tested.

**Note:** Due to the secure user setup (forcing a password change on first login), this script is not fully automated.
It is provided as a reference for the API calls that can be made.

## Pre-configured Test Users

The realm is created with the following users. The passwords listed are for the **first login only**. Upon the first
login attempt for any of these users, you will be prompted by Keycloak to create a new, permanent password.

This is a security best practice enforced by a realm-level "Required Action" in Keycloak. While the initial passwords
are in the realm configuration file for demo convenience, they are immediately invalidated after first use.

| Username    | Initial Password | Role    | Department | Description                                                   |
|-------------|------------------|---------|------------|---------------------------------------------------------------|
| dr.smith    | doctor123        | DOCTOR  | Cardiology | Can read/write patient records in the Cardiology dept.        |
| nurse.jones | nurse123         | NURSE   | Emergency  | Can read patient records in the Emergency dept.               |
| admin       | admin123         | ADMIN   | (N/A)      | Can perform system-wide operations (e.g., list all patients). |
| patient.doe | patient123       | PATIENT | (N/A)      | Has no access to the patient API.                             |

## Architecture

This application demonstrates Zero Trust security principles by leveraging standard Jakarta EE and MicroProfile APIs:

### Core Security Features

- **Authentication**: Handled by **MicroProfile JWT**. The application is configured with the issuer and public key
  location of the Keycloak server, and the Payara runtime automatically validates incoming JWTs.
- **Role-Based Access Control (RBAC)**: Implemented using the standard `jakarta.annotation.security.RolesAllowed`
  annotation.
- **Attribute-Based Access Control (ABAC)**: For more fine-grained control, we extend the standard security model. A
  custom `@RequireAttribute` annotation and a CDI interceptor (`AuthorizationInterceptor`) are used to validate claims
  from the JWT (e.g., ensuring a doctor can only access their own department).
- **Multi-Factor Authentication (MFA)**: TOTP-based OTP generation and validation with 5-minute expiration.
- **Encrypted Data Transit**: Custom `@Encrypted` annotation enforces TLS/HTTPS for sensitive endpoints.

### Production-Grade Security Controls

- **Session Management**: Tracks active user sessions with configurable timeout enforcement (default: 30 minutes).
- **Rate Limiting**: Prevents brute force attacks with configurable limits:
  - 5 authentication attempts per minute per IP address
  - 10 authentication attempts per 5 minutes per username
- **Token Revocation**: Maintains a blacklist of revoked tokens to prevent reuse after logout.
- **Persistent Audit Logs**: All security-sensitive operations are logged to the database for compliance and forensic analysis.
- **Continuous Validation**: CDI interceptors (`AuditInterceptor`) are used for runtime monitoring and to generate
  security events that feed into the anomaly detection system.

### Input Validation

A key principle of Zero Trust is "Never Trust, Always Verify". This applies to all data entering the system. This demo
uses Jakarta Bean Validation to enforce strict data validation at the API boundary. For a detailed explanation of the
input validation strategy, see [VALIDATION_ZERO_TRUST.md](VALIDATION_ZERO_TRUST.md).

## Database Schema

The application uses PostgreSQL with two main tables:

### Patient Table
Stores healthcare patient information with department-based access control:
- Patient demographics (name, DOB, contact info)
- Medical information (blood type, allergies, conditions)
- Assignment (doctor, department)
- Audit timestamps (created_at, updated_at)

### Audit Log Table
Stores security-sensitive operations for compliance:
- Event metadata (timestamp, username, IP address)
- Operation details (action, resource, method, class)
- Security context (sensitivity level, success/failure)
- Performance metrics (duration)
- Additional context (user agent, error messages)

Indexes are created on frequently-queried fields (username, timestamp, action, sensitivity level).

## API Endpoints

### Authentication & Security
- `POST /api/security/token` - Obtain JWT token (rate limited)
- `POST /api/security/token/refresh` - Refresh expired token
- `POST /api/security/logout` - Revoke token and end session
- `GET /api/security/events` - View security audit trail (ADMIN only)
- `GET /api/security/config` - Get security configuration (public)

### Multi-Factor Authentication
- `POST /api/mfa/generate` - Generate OTP for user
- `POST /api/mfa/validate` - Validate OTP
- `GET /api/mfa/status/{username}` - Check MFA status

### Patient Management
- `GET /api/patients` - List all patients (ADMIN only)
- `GET /api/patients/{id}` - Get patient details (DOCTOR/NURSE, department-scoped)
- `GET /api/patients/department/{dept}` - List patients by department (DOCTOR/NURSE/ADMIN)
- `POST /api/patients` - Create patient (DOCTOR only)
- `PUT /api/patients/{id}` - Update patient (DOCTOR only)
- `DELETE /api/patients/{id}` - Delete patient (ADMIN only)
- `GET /api/patients/stats` - Get patient statistics (DOCTOR/NURSE/ADMIN)

### Monitoring
- `GET /api/metrics/security` - Security metrics (auth success/failure, violations)
- `GET /api/metrics/performance` - System performance (memory, CPU, uptime)

All endpoints are protected with:
- JWT authentication (MicroProfile JWT)
- Role-based authorization (@RolesAllowed)
- Rate limiting (authentication endpoints)
- Audit logging (@Audited interceptor)
- TLS enforcement for sensitive data (@Encrypted)

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