package fish.payara.healthcare.model;

import jakarta.validation.constraints.*;

import java.time.LocalDate;
import java.time.LocalDateTime;

/**
 * Patient record for healthcare demo application.
 * Represents sensitive patient data requiring strict access control.
 * Immutable by design for security and thread-safety.
 */
public record Patient(
        String id,

        @NotBlank(message = "First name is required")
        @Size(min = 2, max = 50, message = "First name must be between 2 and 50 characters")
        String firstName,

        @NotBlank(message = "Last name is required")
        @Size(min = 2, max = 50, message = "Last name must be between 2 and 50 characters")
        String lastName,

        @NotNull(message = "Date of birth is required")
        @Past(message = "Date of birth must be in the past")
        LocalDate dateOfBirth,

        @Pattern(regexp = "\\d{3}-\\d{2}-\\d{4}", message = "SSN must be in format XXX-XX-XXXX")
        String ssn,

        @Email(message = "Invalid email format")
        String email,

        @Pattern(regexp = "\\d{3}-\\d{4}", message = "Phone must be in format XXX-XXXX")
        String phone,

        @Size(max = 200, message = "Address must not exceed 200 characters")
        String address,

        @Pattern(regexp = "A\\+|A-|B\\+|B-|AB\\+|AB-|O\\+|O-", message = "Invalid blood type")
        String bloodType,

        @Size(max = 500, message = "Allergies description must not exceed 500 characters")
        String allergies,

        @Size(max = 1000, message = "Medical conditions must not exceed 1000 characters")
        String medicalConditions,

        @Size(max = 100, message = "Assigned doctor name must not exceed 100 characters")
        String assignedDoctor,

        @Size(max = 50, message = "Department name must not exceed 50 characters")
        String department,

        LocalDateTime createdAt,
        LocalDateTime updatedAt
) {
    /**
     * Compact constructor for creating new patients without ID/timestamps
     */
    public Patient(String firstName, String lastName, LocalDate dateOfBirth) {
        this(null, firstName, lastName, dateOfBirth, null, null, null, null, null, null, null, null, null,
                LocalDateTime.now(), LocalDateTime.now());
    }

    /**
     * Create a new patient with generated timestamp
     */
    public static Patient create(String id, String firstName, String lastName, LocalDate dateOfBirth,
                                  String ssn, String email, String phone, String address,
                                  String bloodType, String allergies, String medicalConditions,
                                  String assignedDoctor, String department) {
        LocalDateTime now = LocalDateTime.now();
        return new Patient(id, firstName, lastName, dateOfBirth, ssn, email, phone, address,
                bloodType, allergies, medicalConditions, assignedDoctor, department, now, now);
    }

    /**
     * Update patient with new timestamp
     */
    public Patient withUpdatedTimestamp() {
        return new Patient(id, firstName, lastName, dateOfBirth, ssn, email, phone, address,
                bloodType, allergies, medicalConditions, assignedDoctor, department,
                createdAt, LocalDateTime.now());
    }

    /**
     * Update patient with new ID (for repository save operations)
     */
    public Patient withId(String newId) {
        return new Patient(newId, firstName, lastName, dateOfBirth, ssn, email, phone, address,
                bloodType, allergies, medicalConditions, assignedDoctor, department,
                createdAt != null ? createdAt : LocalDateTime.now(),
                LocalDateTime.now());
    }

    /**
     * Get full name of patient
     */
    public String getFullName() {
        return firstName + " " + lastName;
    }

    @Override
    public String toString() {
        return "Patient{id='" + id + "', name='" + getFullName() + "', department='" + department + "'}";
    }
}
