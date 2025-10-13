# Input Validation in Zero Trust Architecture

## Zero Trust Principle: Never Trust, Always Verify

Input validation is a critical component of Zero Trust security. Every piece of data entering the system must be validated, regardless of its source.

## Bean Validation as Zero Trust Control

### 1. Data Integrity Layer

```java
public record Patient(
    @NotBlank(message = "First name is required")
    @Size(min = 2, max = 50)
    String firstName,

    @Past(message = "Date of birth must be in the past")
    LocalDate dateOfBirth,

    @Pattern(regexp = "\\d{3}-\\d{2}-\\d{4}")
    String ssn
) {}
```

**Zero Trust Benefit**: Data is validated at the boundary, preventing invalid/malicious input from entering the system.

### 2. API Parameter Validation

```java
public Response getPatient(@PathParam("id") @NotBlank String id) {
    // Validation happens BEFORE method execution
    // Zero Trust: verify the input before processing
}
```

**Zero Trust Benefit**: Path parameters, query parameters, and request bodies are all validated automatically.

### 3. Immutability with Records

```java
public record Patient(...) {
    public Patient withId(String newId) {
        return new Patient(newId, firstName, ...);
    }
}
```

**Zero Trust Benefit**:
- Immutable data prevents tampering
- Thread-safe by design
- Clear audit trail (new objects for changes)
- Prevents accidental or malicious modification

## Defense in Depth

```
┌─────────────────────────────────────────────┐
│  1. Network Layer (TLS)                     │
├─────────────────────────────────────────────┤
│  2. Authentication (JWT Validation)         │
├─────────────────────────────────────────────┤
│  3. Authorization (Role/Attribute Checks)   │
├─────────────────────────────────────────────┤
│  4. Input Validation (Bean Validation) ←───┤ YOU ARE HERE
├─────────────────────────────────────────────┤
│  5. Business Logic                          │
├─────────────────────────────────────────────┤
│  6. Data Access Layer                       │
├─────────────────────────────────────────────┤
│  7. Audit Logging                           │
└─────────────────────────────────────────────┘
```

## Validation Constraints Used

### String Validation
- `@NotBlank` - Prevents null, empty, or whitespace-only values
- `@Size` - Limits length to prevent buffer overflows
- `@Pattern` - Enforces format (SSN, phone, blood type)
- `@Email` - Validates email format

### Temporal Validation
- `@Past` - Ensures dates are in the past (date of birth)
- `@NotNull` - Prevents null values

### Numeric Validation
- `@Positive` - Ensures positive numbers (e.g., limit parameter)

## Attack Prevention

### 1. Injection Prevention
```java
@Pattern(regexp = "\\d{3}-\\d{2}-\\d{4}")
String ssn;
```
Prevents SQL injection, XSS, and other injection attacks by enforcing strict format.

### 2. Buffer Overflow Prevention
```java
@Size(max = 1000)
String medicalConditions;
```
Prevents denial-of-service attacks via oversized inputs.

### 3. Business Logic Bypass Prevention
```java
@Past
LocalDate dateOfBirth;
```
Prevents future dates that could bypass age checks.

### 4. Data Integrity
```java
@Valid @NotNull Patient patient
```
Ensures entire object graph is validated, not just top-level fields.

## Zero Trust in Action

### Before Validation (Trusting Input)
```java
public Response createPatient(Patient patient) {
    // DANGEROUS: No validation
    // Accepts malicious/invalid data
    return patientRepository.save(patient);
}
```

### After Validation (Zero Trust)
```java
public Response createPatient(@Valid @NotNull Patient patient) {
    // SAFE: Validated before method entry
    // Jakarta EE returns 400 if invalid
    return patientRepository.save(patient);
}
```

## Validation Error Response

When validation fails, Jakarta EE automatically returns:

```json
{
  "error": "Validation failed",
  "violations": [
    {
      "field": "firstName",
      "message": "First name is required"
    },
    {
      "field": "dateOfBirth",
      "message": "Date of birth must be in the past"
    }
  ]
}
```

## Best Practices

1. **Validate at Boundaries** - API layer, not just business logic
2. **Fail Fast** - Reject invalid input immediately
3. **Clear Messages** - Help developers fix issues (but don't leak sensitive info)
4. **Whitelist, Don't Blacklist** - Use patterns to define what's valid
5. **Combine with Other Controls** - Validation + Authentication + Authorization + Audit

## Conference Talking Points

1. **Validation IS Security** - It's not just about data quality
2. **Zero Trust Starts at Input** - Never assume input is safe
3. **Immutability Matters** - Records prevent tampering
4. **Jakarta EE Makes It Easy** - Declarative validation with annotations
5. **Defense in Depth** - One of many layers in Zero Trust

## Demo Scenarios

### Valid Input
```bash
curl -X POST http://localhost:8080/api/patients \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "John",
    "lastName": "Doe",
    "dateOfBirth": "1990-01-01",
    "ssn": "123-45-6789",
    "email": "john@example.com"
  }'
# Returns: 201 Created
```

### Invalid Input (Triggers Validation)
```bash
curl -X POST http://localhost:8080/api/patients \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "firstName": "X",
    "lastName": "",
    "dateOfBirth": "2030-01-01",
    "ssn": "invalid",
    "email": "not-an-email"
  }'
# Returns: 400 Bad Request with validation errors
```

## Summary

Input validation is a fundamental Zero Trust control:
- **Never Trust**: All input is suspect
- **Always Verify**: Validation happens automatically
- **Fail Securely**: Invalid data is rejected, not processed
- **Immutable Records**: Prevent post-validation tampering
- **Defense in Depth**: One layer in a comprehensive security strategy
