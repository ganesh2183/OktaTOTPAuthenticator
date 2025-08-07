package okta;

import burp.api.montoya.MontoyaApi;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.warrenstrange.googleauth.GoogleAuthenticator;

import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.Base64;

public class OktaHandler {
    private final MontoyaApi api;
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final ObjectMapper objectMapper = new ObjectMapper();
    private String sharedSecretEncoded;
    private String regex;

//    private final GoogleAuthenticator googleAuthenticator;

    public OktaHandler(MontoyaApi api) {
        this.api = api;
        this.sharedSecretEncoded = null;
        this.regex = "";
    }

    public String getSharedSecretEncoded() {
        return this.sharedSecretEncoded;
    }

    public void setSharedSecret(String secret) {
        if (secret == null || secret.trim().isEmpty()) {
            this.sharedSecretEncoded = null;
            api.logging().logToError("Shared secret cleared.");
        } else {
            this.sharedSecretEncoded = Base64.getEncoder().encodeToString(secret.trim().getBytes(StandardCharsets.UTF_8));
        }
    }

    public String decodeSharedSecret() {
        if (sharedSecretEncoded == null || sharedSecretEncoded.isEmpty()) {
            return null;
        }
        try {
            byte[] decodeBytes = Base64.getDecoder().decode(sharedSecretEncoded);
            return new String(decodeBytes,StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public String getRegex() {
        return regex;
    }


    public void setRegex(String regex) {
        this.regex = regex;
    }


    public String generateTOTP() {
        String decodedSecret = decodeSharedSecret();
        if (decodedSecret == null || decodedSecret.isEmpty()) {
            return null;
        }
        try {
            GoogleAuthenticator authenticator = new GoogleAuthenticator();
            int totp = authenticator.getTotpPassword(decodedSecret);
            return String.format("%06d", totp);
        } catch (Exception e) {
            api.logging().logToError("Error generating TOTP: " + e.getMessage());
            return null;
        }
    }

    public static class OktaVerifyData {
        public String t;
        public String f;
        public String domain;
    }

    public OktaVerifyData extractVerifyData(String qrUrl) throws Exception {
        URI uri = URI.create(qrUrl);

        if (!"oktaverify".equals(uri.getScheme())) {
            throw new IllegalArgumentException("Invalid QR code URL schema. Expected 'oktaverify'.");
        }

        var queryParams = parseQuery(uri);

        OktaVerifyData verifyData = new OktaVerifyData();
        verifyData.t = queryParams.get("t");
        verifyData.f = queryParams.get("f");
        verifyData.domain = queryParams.get("issuer");

        if (verifyData.domain == null || verifyData.t == null || verifyData.f == null) {
            throw new IllegalArgumentException("Missing required parameters in QR code URL.");
        }

        return verifyData;
    }

    public String[] getDomainKey(String domain) throws Exception {
        String url = "https://" + domain + "/oauth2/v1/keys";

        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .GET()
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to fetch domain keys. HTTP Status: " + response.statusCode());
        }

        JsonNode keysNode = objectMapper.readTree(response.body()).get("keys");
        if (keysNode == null || !keysNode.isArray() || keysNode.size() == 0) {
            throw new IllegalArgumentException("No keys found in the response.");
        }

        String kid = keysNode.get(0).get("kid").asText();
        String n = keysNode.get(0).get("n").asText();

        return new String[]{kid, n};
    }

    public String createOktaAuthenticator(String deviceName, OktaVerifyData verifyData, String kid, String n) throws Exception {
        String url = "https://" + verifyData.domain + "/idp/authenticators";

        String authorizationHeader = "OTDT " + verifyData.t;
        String userAgent = "D2DD7D3915.com.okta.android.auth/6.8.1 DeviceSDK/0.19.0 Android/7.1.1 unknown/Google";


        Map<String, Object> clientInstanceKey = new HashMap<>();
        clientInstanceKey.put("alg", "RS256");
        clientInstanceKey.put("e", "AQAB");
        clientInstanceKey.put("okta:isFipsCompliant", false);
        clientInstanceKey.put("okta:kpr", "SOFTWARE");
        clientInstanceKey.put("kty", "RSA");
        clientInstanceKey.put("use", "sig");
        clientInstanceKey.put("kid", kid);
        clientInstanceKey.put("n", n);

        Map<String, Object> deviceDetails = new HashMap<>();
        deviceDetails.put("clientInstanceBundleId", "com.okta.android.auth");
        deviceDetails.put("clientInstanceDeviceSdkVersion", "DeviceSDK 0.19.0");
        deviceDetails.put("clientInstanceVersion", "6.8.1");
        deviceDetails.put("clientInstanceKey", clientInstanceKey);
        deviceDetails.put("displayName", deviceName);
        deviceDetails.put("fullDiskEncryption", false);
        deviceDetails.put("isHardwareProtectionEnabled", false);
        deviceDetails.put("manufacturer", "unknown");
        deviceDetails.put("model", "Google");
        deviceDetails.put("osVersion", "25");
        deviceDetails.put("platform", "ANDROID");
        deviceDetails.put("rootPrivileges", true);
        deviceDetails.put("screenLock", false);
        deviceDetails.put("secureHardwarePresent", false);

        List<Map<String, Object>> methods = new ArrayList<>();
        Map<String, Object> methodDetails = new HashMap<>();
        methodDetails.put("isFipsCompliant", false);
        methodDetails.put("supportUserVerification", false);
        methodDetails.put("type", "totp");
        methods.add(methodDetails);

        Map<String, Object> requestBodyMap = new HashMap<>();
        requestBodyMap.put("authenticatorId", verifyData.f);
        requestBodyMap.put("device", deviceDetails);
        requestBodyMap.put("key", "okta_verify");
        requestBodyMap.put("methods", methods);

        String requestBody = objectMapper.writeValueAsString(requestBodyMap);


        HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Authorization", authorizationHeader)
                .header("User-Agent", userAgent)
                .header("Accept", "application/json; charset=UTF-8")
                .header("Accept-Encoding", "gzip, deflate")
                .header("Content-Type", "application/json; charset=UTF-8")
                .POST(HttpRequest.BodyPublishers.ofString(requestBody))
                .build();

        HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

        if (response.statusCode() != 200) {
            throw new RuntimeException("Failed to create Okta authenticator. HTTP Status: " + response.statusCode());
        }

        JsonNode responseNode = objectMapper.readTree(response.body());
        return responseNode.get("methods").get(0).get("sharedSecret").asText();
    }

    private Map<String, String> parseQuery(URI uri) throws Exception {
        Map<String, String> query = new LinkedHashMap<>();
        String[] pairs = uri.getQuery().split("&");
        for (String pair : pairs) {
            int idx = pair.indexOf("=");
            query.put(URLDecoder.decode(pair.substring(0, idx), StandardCharsets.UTF_8),
                    URLDecoder.decode(pair.substring(idx + 1), StandardCharsets.UTF_8));
        }
        return query;
    }
}