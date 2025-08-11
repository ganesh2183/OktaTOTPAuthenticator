package burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import okta.OktaHandler;
import okta.OktaUIInterface;

public class BurpExtender implements BurpExtension {
    private static final String EXTENSION_NAME = "Okta TOTP Authenticator";
    private OktaUIInterface oktaUIInterface;

    @Override
    public void initialize(MontoyaApi api) {
        // Set extension name
        api.extension().setName(EXTENSION_NAME);

        // Log initialization start
        api.logging().logToOutput("Initializing " + EXTENSION_NAME + "...");

        // Initialize data handler and UI
        OktaHandler oktaHandler = new OktaHandler(api);
        oktaUIInterface = new OktaUIInterface(api, oktaHandler);

        // Register session handling action
        api.http().registerSessionHandlingAction(new MySessionHandlingAction(api, oktaHandler));

        // Add the custom UI tab
        api.userInterface().registerSuiteTab("Okta Authenticator", oktaUIInterface);

        api.extension().registerUnloadingHandler(() -> {
            if (oktaUIInterface != null) {
                oktaUIInterface.stopAuthenticator();
            }
        });

        // Log extension initialization success
        api.logging().logToOutput(EXTENSION_NAME + " initialized successfully.");

    }

}