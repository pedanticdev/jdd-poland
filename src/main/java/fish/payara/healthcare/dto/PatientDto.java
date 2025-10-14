package fish.payara.healthcare.dto;

import fish.payara.healthcare.model.Patient;
import jakarta.validation.constraints.*;
import java.time.LocalDate;
import java.util.UUID;

public record PatientDto(
    UUID id,
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
    @Pattern(regexp = "(A|B|AB|O)[+-]", message = "Invalid blood type")
    String bloodType,
    @Size(max = 500, message = "Allergies description must not exceed 500 characters")
    String allergies,
    @Size(max = 1000, message = "Medical conditions must not exceed 1000 characters")
    String medicalConditions,
    @Size(max = 100, message = "Assigned doctor name must not exceed 100 characters")
    String assignedDoctor,
    @Size(max = 50, message = "Department name must not exceed 50 characters")
    String department
) {
    public static PatientDto from(Patient patient) {
        return new PatientDto(
            patient.getId(),
            patient.getFirstName(),
            patient.getLastName(),
            patient.getDateOfBirth(),
            patient.getSsn(),
            patient.getEmail(),
            patient.getPhone(),
            patient.getAddress(),
            patient.getBloodType(),
            patient.getAllergies(),
            patient.getMedicalConditions(),
            patient.getAssignedDoctor(),
            patient.getDepartment()
        );
    }

    public Patient to() {
        Patient patient = new Patient();
        patient.setId(this.id);
        patient.setFirstName(this.firstName);
        patient.setLastName(this.lastName);
        patient.setDateOfBirth(this.dateOfBirth);
        patient.setSsn(this.ssn);
        patient.setEmail(this.email);
        patient.setPhone(this.phone);
        patient.setAddress(this.address);
        patient.setBloodType(this.bloodType);
        patient.setAllergies(this.allergies);
        patient.setMedicalConditions(this.medicalConditions);
        patient.setAssignedDoctor(this.assignedDoctor);
        patient.setDepartment(this.department);
        return patient;
    }
}
