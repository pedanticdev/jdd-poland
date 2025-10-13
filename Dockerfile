# Build stage
FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /app
COPY pom.xml .
COPY src ./src
RUN mvn clean package -DskipTests -Ddockerfile.skip=true

# Runtime stage
FROM payara/micro:6.2025.9-jdk21
COPY --from=build /app/target/payara-oracle-nosql-0.1-SNAPSHOT.war $DEPLOY_DIR/ROOT.war
