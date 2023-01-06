package org.fiware.kong.pep;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.awaitility.Awaitility;
import org.fiware.kong.pep.model.ApplicationContainerObject;
import org.fiware.kong.pep.model.BearerToken;
import org.fiware.kong.pep.model.KeyrockApplication;
import org.fiware.kong.pep.model.KeyrockApplicationResponse;
import org.fiware.kong.pep.model.KeyrockPermission;
import org.fiware.kong.pep.model.PermissionContainer;
import org.fiware.kong.pep.model.RoleContainer;
import org.fiware.kong.pep.model.UserList;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class KeyrockKongPepIT {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);


    private static final String KONG_ADDRESS = "http://localhost:8070";
    private static final String KEYROCK_ADDRESS = "http://localhost:8080";
    private static final String ORION_PATH = "/orion-keyrock";
    private static final String ADMIN_EMAIL = "admin@fiware.org";
    private static final String ADMIN_PASSWORD = "admin";

    @BeforeAll
    public static void waitForKeyrock() throws Exception {
        Awaitility.await().atMost(Duration.of(2, ChronoUnit.MINUTES))
                .until(() -> {
                    try {
                        return HttpClient.newHttpClient()
                                .send(HttpRequest.newBuilder()
                                        .GET()
                                        .uri(URI.create(KEYROCK_ADDRESS))
                                        .build(), HttpResponse.BodyHandlers.ofString()).statusCode() == 200;
                    } catch (Exception e) {
                        return false;
                    }
                });

        //wait for the config to be present
        Thread.sleep(60000);
    }


    @DisplayName("Kong should reject calls without a bearer-token to a secured path.")
    @Test
    public void rejectWithoutToken() throws Exception {

        HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(String.format("%s%s/version", KONG_ADDRESS, ORION_PATH)))
                .version(HttpClient.Version.HTTP_1_1)
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(403, response.statusCode(), "Requests without a valid token should be rejected.");
    }


    @DisplayName("Kong should reject calls without a valid bearer-token to a secured path.")
    @Test
    public void rejectWithoutValidToken() throws Exception {

        String invalidToken = "Bearer myInvalidToken";
        HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(String.format("%s%s/version", KONG_ADDRESS, ORION_PATH)))
                .version(HttpClient.Version.HTTP_1_1)
                .header("Authorization", invalidToken)
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(403, response.statusCode(), "Requests without a valid token should be rejected.");
    }

    @DisplayName("Kong should allow requests with valid tokens.")
    @Test
    public void requestWithValidToken() throws Exception {
        String adminToken = getAdminToken();

        KeyrockApplication keyrockApplication = new KeyrockApplication();
        keyrockApplication.grantType = List.of("password");
        keyrockApplication.redirectUri = "http://test.uri";
        keyrockApplication.tokenTypes = List.of("jwt");
        keyrockApplication.name = "Test-App";
        keyrockApplication.description = "Test Description";
        ApplicationContainerObject applicationContainerObject = new ApplicationContainerObject<KeyrockApplication>();
        applicationContainerObject.application = keyrockApplication;

        HttpResponse<String> appCreateResponse = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .POST(HttpRequest.BodyPublishers.ofString(OBJECT_MAPPER.writeValueAsString(applicationContainerObject)))
                        .uri(URI.create(String.format("%s/v1/applications", KEYROCK_ADDRESS)))
                        .version(HttpClient.Version.HTTP_1_1)
                        .setHeader("Content-Type", "application/json")
                        .header("X-Auth-Token", adminToken)
                        .build(), HttpResponse.BodyHandlers.ofString());
        ApplicationContainerObject createdApplication = OBJECT_MAPPER.readValue(appCreateResponse.body(), ApplicationContainerObject.class);
        KeyrockApplicationResponse keyrockApplicationResponse = OBJECT_MAPPER.convertValue(createdApplication.application, KeyrockApplicationResponse.class);
        HttpResponse<String> roleCreateResponse = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .POST(HttpRequest.BodyPublishers.ofString("{\"role\": { \"name\":\"Admin\"}}"))
                        .uri(URI.create(String.format("%s/v1/applications/%s/roles", KEYROCK_ADDRESS, keyrockApplicationResponse.id)))
                        .version(HttpClient.Version.HTTP_1_1)
                        .setHeader("Content-Type", "application/json")
                        .header("X-Auth-Token", adminToken)
                        .build(), HttpResponse.BodyHandlers.ofString());
        RoleContainer roleContainer = OBJECT_MAPPER.readValue(roleCreateResponse.body(), RoleContainer.class);

        PermissionContainer permissionContainer = new PermissionContainer();
        KeyrockPermission keyrockPermission = new KeyrockPermission();
        keyrockPermission.action = "GET";
        keyrockPermission.name = "Test";
        keyrockPermission.isRegex = true;
        keyrockPermission.resource = "/*";
        permissionContainer.permission = keyrockPermission;

        HttpResponse<String> permissionCreateResponse = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .POST(HttpRequest.BodyPublishers.ofString(OBJECT_MAPPER.writeValueAsString(permissionContainer)))
                        .uri(URI.create(String.format("%s/v1/applications/%s/permissions", KEYROCK_ADDRESS, keyrockApplicationResponse.id)))
                        .version(HttpClient.Version.HTTP_1_1)
                        .setHeader("Content-Type", "application/json")
                        .header("X-Auth-Token", adminToken)
                        .build(), HttpResponse.BodyHandlers.ofString());
        keyrockPermission = OBJECT_MAPPER.readValue(permissionCreateResponse.body(), PermissionContainer.class).permission;

        HttpResponse<String> addPermissionToRole = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .uri(URI.create(String.format("%s/v1/applications/%s/roles/%s/permissions/%s", KEYROCK_ADDRESS, keyrockApplicationResponse.id, roleContainer.role.id, keyrockPermission.id)))
                        .version(HttpClient.Version.HTTP_1_1)
                        .setHeader("Content-Type", "application/json")
                        .header("X-Auth-Token", adminToken)
                        .build(), HttpResponse.BodyHandlers.ofString());

        HttpResponse<String> userIdResponse = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .GET()
                        .uri(URI.create(String.format("%s/v1/users", KEYROCK_ADDRESS)))
                        .version(HttpClient.Version.HTTP_1_1)
                        .header("X-Auth-Token", adminToken)
                        .build(), HttpResponse.BodyHandlers.ofString());

        UserList useList = OBJECT_MAPPER.readValue(userIdResponse.body(), UserList.class);
        String userId = useList.users.stream().filter(u -> u.email.equals(ADMIN_EMAIL)).map(u -> u.id).findFirst().get();
        HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .POST(HttpRequest.BodyPublishers.noBody())
                        .uri(URI.create(String.format("%s/v1/applications/%s/users/%s/roles/%s", KEYROCK_ADDRESS, keyrockApplicationResponse.id, userId, roleContainer.role.id)))
                        .version(HttpClient.Version.HTTP_1_1)
                        .setHeader("Content-Type", "application/json")
                        .header("X-Auth-Token", adminToken)
                        .build(), HttpResponse.BodyHandlers.ofString());

        // GET BEARER TOKEN
        String authHeader = Base64.getEncoder().encodeToString(String.format("%s:%s", keyrockApplicationResponse.id, keyrockApplicationResponse.secret).getBytes());

        Map<String, String> parameters = new HashMap<>();
        parameters.put("username", ADMIN_EMAIL);
        parameters.put("password", ADMIN_PASSWORD);
        parameters.put("scope", "bearer");
        parameters.put("grant_type", "password");

        String form = parameters.entrySet()
                .stream()
                .map(e -> e.getKey() + "=" + URLEncoder.encode(e.getValue(), StandardCharsets.UTF_8))
                .collect(Collectors.joining("&"));
        HttpResponse<String> tokenResponse = HttpClient.newHttpClient().send(
                HttpRequest.newBuilder()
                        .POST(HttpRequest.BodyPublishers.ofString(form))
                        .uri(URI.create(String.format("%s/oauth2/token", KEYROCK_ADDRESS)))
                        .version(HttpClient.Version.HTTP_1_1)
                        .setHeader("Content-Type", "application/x-www-form-urlencoded")
                        .header("Authorization", String.format("Basic %s", authHeader))
                        .build(), HttpResponse.BodyHandlers.ofString());
        BearerToken bearerToken = OBJECT_MAPPER.readValue(tokenResponse.body(), BearerToken.class);

        HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(String.format("%s%s/version", KONG_ADDRESS, ORION_PATH)))
                .version(HttpClient.Version.HTTP_1_1)
                .header("Authorization", bearerToken.accessToken)
                .build(), HttpResponse.BodyHandlers.ofString());

        assertEquals(200, response.statusCode(), "The request should have been allowed.");
    }

    private String getAdminToken() throws Exception {

        HttpResponse<String> authResponse = HttpClient.newHttpClient()
                .send(
                        HttpRequest.newBuilder()
                                .POST(HttpRequest.BodyPublishers
                                        .ofString(String.format("{\"name\": \"%s\", \"password\":\"%s\"}", ADMIN_EMAIL, ADMIN_PASSWORD)))
                                .uri(URI.create(String.format("%s/v1/auth/tokens", KEYROCK_ADDRESS)))
                                .version(HttpClient.Version.HTTP_1_1)
                                .setHeader("Content-Type", "application/json")
                                .build(),
                        HttpResponse.BodyHandlers.ofString());

        return authResponse.headers().map().get("X-Subject-Token").get(0);
    }

}
