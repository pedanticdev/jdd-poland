package fish.payara.healthcare.api;

import fish.payara.healthcare.model.Patient;
import fish.payara.healthcare.repository.PatientRepository;
import fish.payara.security.annotations.Audited;
import fish.payara.security.annotations.RequireRole;
import jakarta.inject.Inject;
import jakarta.security.enterprise.SecurityContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

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
    private HttpServletRequest request;

    @GET
    @Operation(summary = "List all patients", description = "Retrieve all patient records (ADMIN only)")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Patients retrieved successfully"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    @RequireRole("ADMIN")
    @Audited(action = "LIST_PATIENTS", level = Audited.SensitivityLevel.HIGH)
    public Response getAllPatients() {
        LOGGER.info("Fetching all patients");
        List<Patient> patients = patientRepository.findAll();
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
    @RequireRole({"DOCTOR", "NURSE"})
    @Audited(action = "VIEW_PATIENT", level = Audited.SensitivityLevel.CRITICAL)
    public Response getPatient(@PathParam("id") @NotBlank String id) {
        LOGGER.info("Fetching patient: " + id);
        return patientRepository.findById(id)
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
    @RequireRole({"DOCTOR", "NURSE", "ADMIN"})
    @Audited(action = "VIEW_DEPARTMENT_PATIENTS", level = Audited.SensitivityLevel.HIGH)
    public Response getPatientsByDepartment(@PathParam("department") @NotBlank String department) {
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) request.getAttribute("claims");

        if (!securityContext.isCallerInRole("ADMIN")) {
            if (claims == null) {
                throw new ForbiddenException("Authentication required");
            }
            Object userDepartment = claims.get("department");
            if (userDepartment == null || !department.equals(userDepartment.toString())) {
                throw new ForbiddenException("User not authorized for this department");
            }
        }

        LOGGER.info("Fetching patients for department: " + department);
        List<Patient> patients = patientRepository.findByDepartment(department);
        return Response.ok(patients).build();
    }

    @POST
    @Operation(summary = "Create new patient", description = "Add a new patient record (Doctor only)")
    @APIResponses({
            @APIResponse(responseCode = "201", description = "Patient created"),
            @APIResponse(responseCode = "400", description = "Invalid input"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    @RequireRole("DOCTOR")
    @Audited(action = "CREATE_PATIENT", level = Audited.SensitivityLevel.CRITICAL)
    public Response createPatient(@Valid @NotNull Patient patient) {
        LOGGER.info("Creating new patient: " + patient.getFullName());

        Patient saved = patientRepository.save(patient);
        return Response.status(Response.Status.CREATED).entity(saved).build();
    }

    @PUT
    @Path("/{id}")
    @Operation(summary = "Update patient", description = "Update existing patient record (Doctor only)")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Patient updated"),
            @APIResponse(responseCode = "404", description = "Patient not found"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    @RequireRole("DOCTOR")
    @Audited(action = "UPDATE_PATIENT", level = Audited.SensitivityLevel.CRITICAL)
    public Response updatePatient(
            @PathParam("id") @NotBlank String id,
            @Valid @NotNull Patient patient) {
        LOGGER.info("Updating patient: " + id);

        if (!patientRepository.exists(id)) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        Patient updated = patientRepository.save(patient.withId(id));
        return Response.ok(updated).build();
    }

    @DELETE
    @Path("/{id}")
    @Operation(summary = "Delete patient", description = "Remove patient record (Admin only)")
    @APIResponses({
            @APIResponse(responseCode = "204", description = "Patient deleted"),
            @APIResponse(responseCode = "404", description = "Patient not found"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    @RequireRole("ADMIN")
    @Audited(action = "DELETE_PATIENT", level = Audited.SensitivityLevel.CRITICAL)
    public Response deletePatient(@PathParam("id") @NotBlank String id) {
        LOGGER.warning("Deleting patient: " + id);

        if (!patientRepository.exists(id)) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }

        patientRepository.delete(id);
        return Response.noContent().build();
    }

    @GET
    @Path("/stats")
    @Operation(summary = "Get patient statistics", description = "Retrieve patient count and statistics")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Statistics retrieved"),
            @APIResponse(responseCode = "403", description = "Insufficient permissions")
    })
    @RequireRole({"DOCTOR", "NURSE", "ADMIN"})
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
