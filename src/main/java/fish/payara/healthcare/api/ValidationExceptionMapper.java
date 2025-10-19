package fish.payara.healthcare.api;

import jakarta.json.Json;
import jakarta.json.JsonArrayBuilder;
import jakarta.json.JsonObject;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.ConstraintViolationException;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.ExceptionMapper;
import jakarta.ws.rs.ext.Provider;

/**
 * Exception mapper for Bean Validation errors.
 * Converts ConstraintViolationException to JSON format that the frontend can parse.
 */
@Provider
public class ValidationExceptionMapper implements ExceptionMapper<ConstraintViolationException> {

    @Override
    public Response toResponse(ConstraintViolationException exception) {
        JsonArrayBuilder violations = Json.createArrayBuilder();

        for (ConstraintViolation<?> violation : exception.getConstraintViolations()) {
            String field = getFieldName(violation.getPropertyPath().toString());
            String message = violation.getMessage();

            violations.add(Json.createObjectBuilder()
                    .add("field", field)
                    .add("message", message)
                    .build());
        }

        JsonObject error = Json.createObjectBuilder()
                .add("error", "Validation failed")
                .add("violations", violations)
                .build();

        return Response.status(Response.Status.BAD_REQUEST)
                .entity(error)
                .build();
    }

    private String getFieldName(String propertyPath) {
        // Extract just the field name from the property path
        // e.g., "createPatient.patient.phone" -> "phone"
        String[] parts = propertyPath.split("\\.");
        return parts[parts.length - 1];
    }
}
