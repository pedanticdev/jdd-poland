# Modern Java Security: Zero Trust Architectures with Jakarta EE 11

Demo application for JDD Poland conference showcasing Zero Trust security implementation using Jakarta EE 11 and Payara.

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

Access the Keycloak admin console at http://localhost:8180

The realm `jdd-poland` will be automatically imported with:
- **4 pre-configured users** (doctor, nurse, admin, patient)
- **2 clients** (main app and service client)
- **4 roles** (DOCTOR, NURSE, ADMIN, PATIENT)

### 3. Run the Application

```bash
./mvnw clean package payara-micro:dev
```

The application will start at http://localhost:8080/

## Pre-configured Test Users

| Username    | Password   | Role    | Description                    |
|-------------|------------|---------|--------------------------------|
| dr.smith    | doctor123  | DOCTOR  | Full access to patient records |
| nurse.jones | nurse123   | NURSE   | Limited patient access         |
| admin       | admin123   | ADMIN   | System administration          |
| patient.doe | patient123 | PATIENT | Self-access only               |

## Architecture

This application demonstrates Zero Trust security principles:

- **Fine-grained Authentication**: OAuth 2.0/OIDC via Keycloak
- **Attribute-Based Access Control**: Jakarta Security with custom attributes
- **Continuous Validation**: CDI interceptors for runtime monitoring
- **Service-to-Service Security**: JWT-based authentication with least privilege
- **Encrypted Transit**: Jakarta Security annotations

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

## Environment Variables

Copy `.env.example` to `.env` and adjust as needed:

```bash
cp .env.example .env
```

## Development

The application uses:
- Jakarta EE 11
- Payara 7.2025.1.Beta1
- Java 21
- MicroProfile 7.0




