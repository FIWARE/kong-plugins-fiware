package org.fiware.kong.pep;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.awaitility.Awaitility;
import org.fiware.kong.pep.model.BearerToken;
import org.fiware.kong.pep.model.TokenResponse;
import org.fiware.kong.pep.model.ishare.BackendInfo;
import org.fiware.kong.pep.model.ishare.DelegationEvidence;
import org.fiware.kong.pep.model.ishare.Policy;
import org.fiware.kong.pep.model.ishare.PolicyCreate;
import org.fiware.kong.pep.model.ishare.PolicyResource;
import org.fiware.kong.pep.model.ishare.PolicyRule;
import org.fiware.kong.pep.model.ishare.PolicySet;
import org.fiware.kong.pep.model.ishare.PolicyTarget;
import org.fiware.kong.pep.model.ishare.Target;
import org.fiware.kong.pep.model.vc.ConnectionString;
import org.fiware.kong.pep.model.vc.CredentialHolder;
import org.fiware.kong.pep.model.vc.VerifiableCredential;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.MethodOrderer;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Slf4j
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
public class VCKongPepIT {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private static final String PACKET_DELIVERY_EORI = "EU.EORI.PACKETDELIVERY";

    private static final String ISSUER_ADDRESS = "http://localhost:3000";
    private static final String VERIFIER_ADDRESS = "http://localhost:3001";
    private static final String KONG_ADDRESS = "http://localhost:8070";
    private static final String TOKEN_HELPER_ADDRESS = "http://localhost:5060";
    private static final String PACKET_DELIVERY_AR_ADDRESS = "http://localhost:8050";
    private static final String ORION_PATH = "/orion-ext-authz";

    @BeforeAll
    public static void waitForComponents() throws Exception {
        Awaitility.await().atMost(Duration.of(2, ChronoUnit.MINUTES))
                .until(() -> {
                    try {
                        return HttpClient.newHttpClient()
                                .send(HttpRequest.newBuilder()
                                        .GET()
                                        .uri(URI.create(VERIFIER_ADDRESS))
                                        .build(), HttpResponse.BodyHandlers.ofString()).statusCode() == 200;
                    } catch (Exception e) {
                        return false;
                    }
                });
        Awaitility.await().atMost(Duration.of(2, ChronoUnit.MINUTES))
                .until(() -> {
                    try {
                        return HttpClient.newHttpClient()
                                .send(HttpRequest.newBuilder()
                                        .GET()
                                        .uri(URI.create(ISSUER_ADDRESS))
                                        .build(), HttpResponse.BodyHandlers.ofString()).statusCode() == 200;
                    } catch (Exception e) {
                        return false;
                    }
                });
        Awaitility.await().atMost(Duration.of(2, ChronoUnit.MINUTES))
                .until(() -> {
                    try {
                        return HttpClient.newHttpClient()
                                .send(HttpRequest.newBuilder()
                                        .GET()
                                        .uri(URI.create(PACKET_DELIVERY_AR_ADDRESS))
                                        .build(), HttpResponse.BodyHandlers.ofString()).statusCode() == 200;
                    } catch (Exception e) {
                        return false;
                    }
                });
    }

    @Order(2)
    @DisplayName("Request the entity successfully with a VC.")
    @Test
    public void requestWithVC() throws Exception {
        String role = "GOLD_CUSTOMER";

        BackendInfo issuerInfo = getBackendInfo(ISSUER_ADDRESS);
        setupIssuerPolicyInAR(issuerInfo.issuerDid, List.of(role));
        setupRolePolicyInAR(role);

        VerifiableCredential verifiableCredential = getCredential(role);

        String connectionString = startSiopFlow();
        ConnectionString parsedString = parseConnectionString(connectionString);

        assertTrue(sendCredential(parsedString, verifiableCredential), "The credential should have been successfully accepted.");

        String jwt = getJwt(parsedString.state);
        HttpResponse<String> response = requestContextBroker(jwt, "urn:ngsi-ld:DELIVERYORDER:1")
        assertEquals(404, response.statusCode(), String.format("The request should have been allowed. But was: %s", response.body()));
    }

    @Order(3)
    @DisplayName("Request the entity with a none existent role.")
    @Test
    public void requestWithNonExistentRoleVC() throws Exception {

        BackendInfo issuerInfo = getBackendInfo(ISSUER_ADDRESS);
        // GOLD_CUSTOMER role will exist and can be issued
        setupIssuerPolicyInAR(issuerInfo.issuerDid, List.of("GOLD_CUSTOMER"));
        setupRolePolicyInAR("GOLD_CUSTOMER");

        // get a credential with a role that is not existent
        VerifiableCredential verifiableCredential = getCredential("NON_EXISTENT_ROLE");

        String connectionString = startSiopFlow();
        ConnectionString parsedString = parseConnectionString(connectionString);

        assertTrue(sendCredential(parsedString, verifiableCredential), "The credential should have been successfully accepted.");

        String jwt = getJwt(parsedString.state);
        assertEquals(403, requestContextBroker(jwt, "urn:ngsi-ld:DELIVERYORDER:1").statusCode(), "The request should have been allowed.");
    }

    @Order(4)
    @DisplayName("Request entity not covered by the role with a VC.")
    @Test
    public void requestUncoveredEntityVC() throws Exception {

        BackendInfo issuerInfo = getBackendInfo(ISSUER_ADDRESS);
        // GOLD_CUSTOMER role will exist and can be issued
        setupIssuerPolicyInAR(issuerInfo.issuerDid, List.of("GOLD_CUSTOMER"));
        setupRolePolicyInAR("GOLD_CUSTOMER");

        // get a credential with a role that is not existent
        VerifiableCredential verifiableCredential = getCredential("NON_EXISTENT_ROLE");

        String connectionString = startSiopFlow();
        ConnectionString parsedString = parseConnectionString(connectionString);

        assertTrue(sendCredential(parsedString, verifiableCredential), "The credential should have been successfully accepted.");

        String jwt = getJwt(parsedString.state);
        assertEquals(403, requestContextBroker(jwt, "urn:ngsi-ld:SOME_THING_ELSE:1").statusCode(), "The request should have been allowed.");
    }

    // we wont this to run first, so that no policies are setup
    @Order(1)
    @DisplayName("Deny the request if no policies are setup.")
    @Test
    public void requestWithoutThePolicies() throws Exception {
        VerifiableCredential verifiableCredential = getCredential("GOLD_CUSTOMER");

        String connectionString = startSiopFlow();
        ConnectionString parsedString = parseConnectionString(connectionString);

        assertTrue(sendCredential(parsedString, verifiableCredential), "The credential should have been successfully accepted.");

        String jwt = getJwt(parsedString.state);
        assertEquals(403, requestContextBroker(jwt, "urn:ngsi-ld:DELIVERYORDER:1").statusCode(), "Without the policies, the request should be denied.");
    }

    private BackendInfo getBackendInfo(String address) throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(String.format("%s/info", address)))
                .version(HttpClient.Version.HTTP_1_1)
                .build(), HttpResponse.BodyHandlers.ofString());
        return OBJECT_MAPPER.readValue(response.body(), BackendInfo.class);
    }

    private void setupRolePolicyInAR(String roleName) throws Exception {
        String policyCreateToken = getAccessToken(PACKET_DELIVERY_AR_ADDRESS, PACKET_DELIVERY_EORI, PACKET_DELIVERY_EORI);

        PolicyCreate goldCustomerCreate = getRole(roleName);

        HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(OBJECT_MAPPER.writeValueAsString(goldCustomerCreate)))
                .uri(URI.create(String.format("%s/ar/policy", PACKET_DELIVERY_AR_ADDRESS)))
                .header("Content-Type", "application/json")
                .header("Authorization", String.format("Bearer %s", policyCreateToken))
                .version(HttpClient.Version.HTTP_1_1)
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), "The role policy should have been created.");

    }

    private void setupIssuerPolicyInAR(String issuerId, List<String> allowedRoles) throws Exception {
        String policyCreateToken = getAccessToken(PACKET_DELIVERY_AR_ADDRESS, PACKET_DELIVERY_EORI, PACKET_DELIVERY_EORI);

        PolicyCreate issuerPolicy = getIssuerPolicy(issuerId, allowedRoles);
        HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(OBJECT_MAPPER.writeValueAsString(issuerPolicy)))
                .uri(URI.create(String.format("%s/ar/policy", PACKET_DELIVERY_AR_ADDRESS)))
                .header("Content-Type", "application/json")
                .header("Authorization", String.format("Bearer %s", policyCreateToken))
                .version(HttpClient.Version.HTTP_1_1)
                .build(), HttpResponse.BodyHandlers.ofString());
        assertEquals(200, response.statusCode(), "The role policy should have been created.");
    }

    private PolicyCreate getIssuerPolicy(String issuerDid, List<String> allowedRoles) {
        DelegationEvidence delegationEvidence = new DelegationEvidence();
        delegationEvidence.notBefore = Instant.now().getEpochSecond();
        // very short run times will allow repeated test runs
        delegationEvidence.notOnOrAfter = Instant.now().plus(Duration.of(10, ChronoUnit.SECONDS)).getEpochSecond();
        delegationEvidence.policyIssuer = PACKET_DELIVERY_EORI;
        Target target = new Target();
        target.accessSubject = issuerDid;
        delegationEvidence.target = target;

        PolicyResource policyResource = new PolicyResource();
        policyResource.attributes = allowedRoles;
        policyResource.identifiers = List.of("*");
        policyResource.type = "PacketDeliveryService";

        PolicyTarget policyTarget = new PolicyTarget();
        policyTarget.resource = policyResource;
        policyTarget.actions = List.of("ISSUE");

        Policy rolePolicy = new Policy();
        rolePolicy.rules = List.of(new PolicyRule());
        rolePolicy.target = policyTarget;

        PolicySet policySet = new PolicySet();
        policySet.policies = List.of(rolePolicy);

        delegationEvidence.policySets = List.of(policySet);

        PolicyCreate roleCreate = new PolicyCreate();
        roleCreate.delegationEvidence = delegationEvidence;
        return roleCreate;
    }

    private PolicyCreate getRole(String roleName) {
        DelegationEvidence delegationEvidence = new DelegationEvidence();
        delegationEvidence.notBefore = Instant.now().getEpochSecond();
        delegationEvidence.notOnOrAfter = Instant.now().plus(Duration.of(10, ChronoUnit.MINUTES)).getEpochSecond();
        delegationEvidence.policyIssuer = PACKET_DELIVERY_EORI;
        Target target = new Target();
        target.accessSubject = roleName;
        delegationEvidence.target = target;

        PolicyResource policyResource = new PolicyResource();
        policyResource.attributes = List.of("*");
        policyResource.identifiers = List.of("*");
        policyResource.type = "DELIVERYORDER";

        PolicyTarget policyTarget = new PolicyTarget();
        policyTarget.resource = policyResource;
        policyTarget.actions = List.of("GET", "PUT", "PATCH");

        Policy rolePolicy = new Policy();
        rolePolicy.rules = List.of(new PolicyRule());
        rolePolicy.target = policyTarget;

        PolicySet policySet = new PolicySet();
        policySet.policies = List.of(rolePolicy);

        delegationEvidence.policySets = List.of(policySet);

        PolicyCreate roleCreate = new PolicyCreate();
        roleCreate.delegationEvidence = delegationEvidence;
        return roleCreate;
    }

    private String getAccessToken(String idpAddress, String idpId, String clientId) throws Exception {
        HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(String.format("%s/token?clientId=%s&idpId=%s", TOKEN_HELPER_ADDRESS, clientId, idpId)))
                .version(HttpClient.Version.HTTP_1_1)
                .build(), HttpResponse.BodyHandlers.ofString());
        String iShareToken = OBJECT_MAPPER.readValue(response.body(), TokenResponse.class).token;

        Map<String, String> formData = Map.of(
                "grant_type", "client_credentials",
                "scope", "iSHARE",
                "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion", iShareToken,
                "client_id", clientId);

        response = HttpClient.newHttpClient().send(HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(getFormDataAsString(formData)))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .uri(URI.create(String.format("%s/oauth2/token", idpAddress, clientId, idpId)))
                .version(HttpClient.Version.HTTP_1_1)
                .build(), HttpResponse.BodyHandlers.ofString());

        return OBJECT_MAPPER.readValue(response.body(), BearerToken.class).accessToken;
    }

    private HttpResponse<String> requestContextBroker(String jwt, String entityId) throws Exception {
        return HttpClient.newHttpClient().send(HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(String.format("%s%s/ngsi-ld/v1/entities/%s", KONG_ADDRESS, ORION_PATH, entityId)))
                .version(HttpClient.Version.HTTP_1_1)
                .header("Authorization", String.format("Bearer %s", jwt))
                .build(), HttpResponse.BodyHandlers.ofString());
    }

    private String getJwt(String state) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(String.format("%s/verifier/api/v1/token/%s", VERIFIER_ADDRESS, state)))
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }

    private boolean sendCredential(ConnectionString connectionString, VerifiableCredential verifiableCredential) throws Exception {
        String address = String.format("%s?state=%s", connectionString.redirectURI, connectionString.state);

        HttpRequest request = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(OBJECT_MAPPER.writeValueAsString(new CredentialHolder(verifiableCredential))))
                .uri(URI.create(address))
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());
        return response.statusCode() == 200;
    }

    private ConnectionString parseConnectionString(String connectionString) {
        String[] parts = connectionString.split(Pattern.quote("?"));

        ConnectionString parsedString = new ConnectionString();
        assertEquals("openid://", parts[0], String.format("The received schema %s is not supported.", parts[0]));
        parsedString.schema = parts[0];
        List<String> valuePairs = List.of(parts[1].split("&"));
        valuePairs.stream().map(vp -> vp.split("="))
                .peek(splitted -> assertEquals(2, splitted.length, "It should be a pair"))
                .forEach(vp -> {
                    switch (vp[0]) {
                        case "scope" -> parsedString.scope = vp[1];
                        case "response_type" -> parsedString.responseType = vp[1];
                        case "response_mode" -> parsedString.responseMode = vp[1];
                        case "client_id" -> parsedString.clientId = vp[1];
                        case "redirect_uri" -> parsedString.redirectURI = vp[1];
                        case "state" -> parsedString.state = vp[1];
                        case "nonce" -> parsedString.nonce = vp[1];
                        default -> fail(String.format("Received an unexpected value-pair %s:%s in connection string %s.", vp[0], vp[1], connectionString));
                    }
                });
        return parsedString;
    }

    private String startSiopFlow() throws Exception {
        String state = UUID.randomUUID().toString();
        HttpRequest request = HttpRequest.newBuilder()
                .GET()
                .uri(URI.create(String.format("%s/verifier/api/v1/startsiop?state=%s", VERIFIER_ADDRESS, state)))
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());
        return response.body();
    }

    private VerifiableCredential getCredential(String credentialRole) throws Exception {
        Map<String, String> formData = Map.of(
                "email", "test@test.org",
                "firstName", "Test",
                "familyName", "User",
                "target", PACKET_DELIVERY_EORI,
                "roles", credentialRole);

        HttpRequest request = HttpRequest.newBuilder()
                .POST(HttpRequest.BodyPublishers.ofString(getFormDataAsString(formData)))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .uri(URI.create(String.format("%s/issuer/api/v1/credential", ISSUER_ADDRESS)))
                .build();
        HttpResponse<String> response = HttpClient.newHttpClient()
                .send(request, HttpResponse.BodyHandlers.ofString());
        return OBJECT_MAPPER.readValue(response.body(), VerifiableCredential.class);
    }

    private static String getFormDataAsString(Map<String, String> formData) {
        StringBuilder formBodyBuilder = new StringBuilder();
        for (Map.Entry<String, String> singleEntry : formData.entrySet()) {
            if (formBodyBuilder.length() > 0) {
                formBodyBuilder.append("&");
            }
            formBodyBuilder.append(URLEncoder.encode(singleEntry.getKey(), StandardCharsets.UTF_8));
            formBodyBuilder.append("=");
            formBodyBuilder.append(URLEncoder.encode(singleEntry.getValue(), StandardCharsets.UTF_8));
        }
        return formBodyBuilder.toString();
    }
}
