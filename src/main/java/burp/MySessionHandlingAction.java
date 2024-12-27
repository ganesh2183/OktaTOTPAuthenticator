package burp;

import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.sessions.SessionHandlingAction;
import burp.api.montoya.http.sessions.SessionHandlingActionData;
import burp.api.montoya.http.sessions.ActionResult;
import burp.api.montoya.MontoyaApi;
import okta.OktaHandler;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class MySessionHandlingAction implements SessionHandlingAction {
    private final MontoyaApi api;
    private final OktaHandler oktaHandler;

    public MySessionHandlingAction(MontoyaApi api, OktaHandler oktaHandler) {
        this.api = api;
        this.oktaHandler = oktaHandler;
    }

    @Override
    public String name() {
        return "Okta TOTP Handler";
    }

    @Override
    public ActionResult performAction(SessionHandlingActionData actionData) {
        // Get the original request
        HttpRequest request = actionData.request();

        // Generate the TOTP code
        String otpCode = oktaHandler.generateTOTP();
        if (otpCode == null || otpCode.isEmpty()) {
            api.logging().logToError("TOTP generation failed. Request processing skipped.");
            return ActionResult.actionResult(request);
        }

        // Extract the regex pattern
        String regex = oktaHandler.getRegex();
        if (regex == null || regex.isEmpty()) {
            api.logging().logToError("No regex pattern provided. Request processing skipped.");
            return ActionResult.actionResult(request);
        }

        // Apply the regex to replace the TOTP code in the request body
        String requestBody = request.bodyToString();
        if (requestBody == null || requestBody.isEmpty()) {
            api.logging().logToOutput("Request body is empty. No TOTP replacement applied.");
            return ActionResult.actionResult(request);
        }

        try {
            Pattern pattern = Pattern.compile(regex);
            Matcher matcher = pattern.matcher(requestBody);

            if (matcher.find()) {
                String updatedBody = matcher.replaceAll(otpCode);
                HttpRequest updatedRequest = request.withBody(updatedBody);
                api.logging().logToOutput("TOTP successfully applied to the request.");
                return ActionResult.actionResult(updatedRequest);
            } else {
                api.logging().logToOutput("No matching regex found in the request body. No changes made.");
                return ActionResult.actionResult(request);
            }
        } catch (Exception e) {
            api.logging().logToError("Error applying regex to request body: " + e.getMessage());
            return ActionResult.actionResult(request);
        }
    }
}