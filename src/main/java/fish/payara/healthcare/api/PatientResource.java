package fish.payara.healthcare.api;

import fish.payara.healthcare.dto.PatientDto;
import fish.payara.healthcare.model.Patient;
import fish.payara.healthcare.repository.PatientRepository;
import fish.payara.security.annotations.Audited;
import fish.payara.security.annotations.Encrypted;
import jakarta.annotation.security.RolesAllowed;
import jakarta.inject.Inject;
import jakarta.security.enterprise.SecurityContext;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

import java.util.List;
import java.util.UUID;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Patient REST API with role-based access control.
 * Demonstrates Zero Trust security with fine-grained authorization.
 */
@Path("/patients")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "Patients", description = "Patient records management")
@SecurityRequirement(name = "bearer-jwt")
public class PatientResource {

    private static final Logger LOGGER = Logger.getLogger(PatientResource.class.getName());

    @Inject
    private PatientRepository patientRepository;

    @Inject
    private SecurityContext securityContext;

    @Inject
    private JsonWebToken jwt;

    @GET
    @Operation(summary = "List all patients", description = "Retrieve all patient records (ADMIN only)")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Patients retrieved successfully"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    @RolesAllowed("ADMIN")
    @Audited(action = "LIST_PATIENTS", level = Audited.SensitivityLevel.HIGH)
    public Response getAllPatients() {
        LOGGER.info("Fetching all patients");
        List<PatientDto> patients = StreamSupport.stream(patientRepository.findAll().spliterator(), false)
                .map(PatientDto::from)
                .collect(Collectors.toList());
        return Response.ok(patients).build();
    }

    @GET
    @Path("/{id}")
    @Operation(summary = "Get patient by ID", description = "Retrieve specific patient record")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Patient found"),
            @APIResponse(responseCode = "404", description = "Patient not found"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    @RolesAllowed({"DOCTOR", "NURSE"})
    @Audited(action = "VIEW_PATIENT", level = Audited.SensitivityLevel.CRITICAL)
    @Encrypted(algorithm = Encrypted.Algorithm.AES_256_GCM)
    public Response getPatient(@PathParam("id") @NotBlank String id) {
        LOGGER.info("Fetching patient: " + id);
        UUID patientId;
        try {
            patientId = UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new ErrorResponse("Invalid patient ID format")).build();
        }
        return patientRepository.findById(patientId)
                .map(PatientDto::from)
                .map(patient -> Response.ok(patient).build())
                .orElse(Response.status(Response.Status.NOT_FOUND).build());
    }

    @GET
    @Path("/department/{department}")
    @Operation(summary = "Get patients by department", description = "Retrieve patients for a specific department. Access is restricted to users in the same department, unless the user has the ADMIN role.")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Patients retrieved"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    @RolesAllowed({"DOCTOR", "NURSE", "ADMIN"})
    @Audited(action = "VIEW_DEPARTMENT_PATIENTS", level = Audited.SensitivityLevel.HIGH)
    public Response getPatientsByDepartment(@PathParam("department") @NotBlank String department) {
        if (!securityContext.isCallerInRole("ADMIN")) {
            String userDepartment = jwt.getClaim("department");
            if (!department.equals(userDepartment)) {
                throw new ForbiddenException("User not authorized for this department");
            }
        }

        LOGGER.info("Fetching patients for department: " + department);
        List<PatientDto> patients = patientRepository.findByDepartment(department)
                .stream()
                .map(PatientDto::from)
                .collect(Collectors.toList());
        return Response.ok(patients).build();
    }

    @POST
    @Operation(summary = "Create new patient", description = "Add a new patient record (Doctor only)")
    @APIResponses({
            @APIResponse(responseCode = "201", description = "Patient created"),
            @APIResponse(responseCode = "400", description = "Invalid input"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    @RolesAllowed("DOCTOR")
    @Audited(action = "CREATE_PATIENT", level = Audited.SensitivityLevel.CRITICAL)
    @Encrypted(algorithm = Encrypted.Algorithm.AES_256_GCM)
    public Response createPatient(@Valid @NotNull PatientDto patientDto) {
        LOGGER.info("Creating new patient: " + patientDto.firstName() + " " + patientDto.lastName());
        Patient patient = patientDto.to();
        patient.setId(null); // Ensure ID is generated by the database
        Patient saved = patientRepository.save(patient);
        return Response.status(Response.Status.CREATED).entity(PatientDto.from(saved)).build();
    }

    @PUT
    @Path("/{id}")
    @Operation(summary = "Update patient", description = "Update existing patient record (Doctor only)")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Patient updated"),
            @APIResponse(responseCode = "404", description = "Patient not found"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    @RolesAllowed("DOCTOR")
    @Audited(action = "UPDATE_PATIENT", level = Audited.SensitivityLevel.CRITICAL)
    public Response updatePatient(
            @PathParam("id") @NotBlank String id,
            @Valid @NotNull PatientDto patientData) {
        LOGGER.info("Updating patient: " + id);
        UUID patientId;
        try {
            patientId = UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new ErrorResponse("Invalid patient ID format")).build();
        }

        return patientRepository.findById(patientId)
                .map(existingPatient -> {
                    // Update fields from the request body
                    existingPatient.setFirstName(patientData.firstName());
                    existingPatient.setLastName(patientData.lastName());
                    existingPatient.setDateOfBirth(patientData.dateOfBirth());
                    existingPatient.setSsn(patientData.ssn());
                    existingPatient.setEmail(patientData.email());
                    existingPatient.setPhone(patientData.phone());
                    existingPatient.setAddress(patientData.address());
                    existingPatient.setBloodType(patientData.bloodType());
                    existingPatient.setAllergies(patientData.allergies());
                    existingPatient.setMedicalConditions(patientData.medicalConditions());
                    existingPatient.setAssignedDoctor(patientData.assignedDoctor());
                    existingPatient.setDepartment(patientData.department());

                    Patient updated = patientRepository.save(existingPatient);
                    return Response.ok(PatientDto.from(updated)).build();
                })
                .orElse(Response.status(Response.Status.NOT_FOUND).build());
    }

    @DELETE
    @Path("/{id}")
    @Operation(summary = "Delete patient", description = "Remove patient record (Admin only)")
    @APIResponses({
            @APIResponse(responseCode = "204", description = "Patient deleted"),
            @APIResponse(responseCode = "404", description = "Patient not found"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    @RolesAllowed("ADMIN")
    @Audited(action = "DELETE_PATIENT", level = Audited.SensitivityLevel.CRITICAL)
    public Response deletePatient(@PathParam("id") @NotBlank String id) {
        LOGGER.warning("Deleting patient: " + id);
        UUID patientId;
        try {
            patientId = UUID.fromString(id);
        } catch (IllegalArgumentException e) {
            return Response.status(Response.Status.BAD_REQUEST).entity(new ErrorResponse("Invalid patient ID format")).build();
        }

        if (patientRepository.findById(patientId).isEmpty()) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        patientRepository.deleteById(patientId);
        return Response.noContent().build();
    }

    @GET
    @Path("/stats")
    @Operation(summary = "Get patient statistics", description = "Retrieve patient count and statistics")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Statistics retrieved"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    @RolesAllowed({"DOCTOR", "NURSE", "ADMIN"})
    @Audited(action = "VIEW_STATISTICS", level = Audited.SensitivityLevel.LOW)
    public Response getStatistics() {
        long count = patientRepository.count();
        return Response.ok(new PatientStatistics(count)).build();
    }

    public record PatientStatistics(long totalPatients) {
    }

    public record ErrorResponse(String error) {
    }
}