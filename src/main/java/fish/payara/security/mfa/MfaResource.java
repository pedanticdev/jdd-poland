package fish.payara.security.mfa;

import jakarta.annotation.security.PermitAll;
import jakarta.inject.Inject;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.tags.Tag;

/**
 * Multi-Factor Authentication REST endpoints.
 * Demonstrates MFA integration as part of Zero Trust security.
 */
@Path("/mfa")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Tag(name = "MFA", description = "Multi-factor authentication operations")
public class MfaResource {

    @Inject
    private MfaService mfaService;

    @Context
    private HttpServletRequest request;

    @POST
    @Path("/generate")
    @PermitAll
    @Operation(summary = "Generate MFA OTP", description = "Generate a one-time password for multi-factor authentication")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "OTP generated successfully"),
            @APIResponse(responseCode = "400", description = "Invalid request")
    })
    public Response generateOtp(@Valid @NotNull GenerateOtpRequest otpRequest) {
        String ipAddress = request.getRemoteAddr();
        String otp = mfaService.generateOtp(otpRequest.username(), ipAddress);

        // PRODUCTION: Don't return OTP in response! Send via SMS/Email/Authenticator app
        // For demo purposes, we include it to make testing easier
        String demoOtp = System.getProperty("mfa.demo.mode", "true").equals("true") ? otp : null;

        return Response.ok(new OtpGeneratedResponse(
                "OTP generated successfully. In production, this would be sent via SMS/Email.",
                demoOtp, // Only included in demo mode
                300 // 5 minutes in seconds
        )).build();
    }

    @POST
    @Path("/validate")
    @PermitAll
    @Operation(summary = "Validate MFA OTP", description = "Validate a one-time password for multi-factor authentication")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "OTP validated successfully"),
            @APIResponse(responseCode = "401", description = "Invalid OTP")
    })
    public Response validateOtp(@Valid @NotNull ValidateOtpRequest otpRequest) {
        String ipAddress = request.getRemoteAddr();
        boolean valid = mfaService.validateOtp(otpRequest.username(), otpRequest.otp(), ipAddress);

        if (valid) {
            return Response.ok(new OtpValidationResponse(true, "OTP validated successfully")).build();
        } else {
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new OtpValidationResponse(false, "Invalid or expired OTP"))
                    .build();
        }
    }

    @GET
    @Path("/status/{username}")
    @PermitAll
    @Operation(summary = "Check MFA status", description = "Check if MFA is required and completed for a user")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "MFA status retrieved")
    })
    public Response getMfaStatus(@PathParam("username") @NotBlank String username) {
        boolean required = mfaService.isMfaRequired(username);
        boolean completed = mfaService.isMfaCompleted(username);

        return Response.ok(new MfaStatusResponse(required, completed)).build();
    }

    public record GenerateOtpRequest(
            @NotBlank(message = "Username is required")
            String username
    ) {
    }

    public record ValidateOtpRequest(
            @NotBlank(message = "Username is required")
            String username,
            @NotBlank(message = "OTP is required")
            String otp
    ) {
    }

    public record OtpGeneratedResponse(
            String message,
            String otp, // Only populated in demo mode
            int expiresIn
    ) {
    }

    public record OtpValidationResponse(
            boolean valid,
            String message
    ) {
    }

    public record MfaStatusResponse(
            boolean required,
            boolean completed
    ) {
    }
}
