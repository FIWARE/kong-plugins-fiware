package org.fiware.kong.pep;

import org.awaitility.Awaitility;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.token.TokenManager;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.temporal.ChronoUnit;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class KeycloakKongPepIT {


	private static final String KONG_ADDRESS = "http://localhost:8070";
	private static final String KEYCLOAK_ADDRESS = "http://localhost:8090";
	private static final String ORION_PATH = "/orion-keycloak";
	private static final String ADMIN_USER = "admin-user";
	private static final String ADMIN_PASSWORD = "admin-user";
	private static final String NOT_ALLOWED_USER = "not-allowed-user";
	private static final String NOT_ALLOWED_PASSWORD = "not-allowed-user";
	private static final String REALM= "fiware-server";

	@BeforeAll
	public static void waitForKeycloak() throws Exception {
		Awaitility.await().atMost(Duration.of(2, ChronoUnit.MINUTES))
				.until(() -> {
						return HttpClient.newHttpClient()
								.send(HttpRequest.newBuilder()
										.GET()
										.uri(URI.create(KEYCLOAK_ADDRESS))
										.build(), HttpResponse.BodyHandlers.ofString()).statusCode() == 200;
				});
		//wait for the config to be present
		Thread.sleep(30000);
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

	@DisplayName("Kong should reject calls without a bearer-token to a secured path.")
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

	@DisplayName("Kong should reject calls without a bearer-token that does not have sufficient permissions.")
	@Test
	public void rejectWithoutValidTokenToLittlePermission() throws Exception {

		HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder()
				.GET()
				.uri(URI.create(String.format("%s%s/v2/entities", KONG_ADDRESS, ORION_PATH)))
				.version(HttpClient.Version.HTTP_1_1)
				.header("Authorization", getNotAllowedToken())
				.build(), HttpResponse.BodyHandlers.ofString());
		assertEquals(403, response.statusCode(), "Requests without a valid token should be rejected.");
	}
	@DisplayName("Kong should allow requests with valid tokens.")
	@Test
	public void requestWithValidToken() throws Exception {

		HttpResponse<String> response = HttpClient.newHttpClient().send(HttpRequest.newBuilder()
				.GET()
				.uri(URI.create(String.format("%s%s/v2/entities", KONG_ADDRESS, ORION_PATH)))
				.version(HttpClient.Version.HTTP_1_1)
				.header("Authorization", getAdminToken())
				.header("fiware-service", "")
				.header("fiware-servicepath", "/")
				.build(), HttpResponse.BodyHandlers.ofString());
		assertEquals(200, response.statusCode(), "Requests with a valid token should be allowed.");
	}

	private String getAdminToken() {
		TokenManager tokenManager = KeycloakBuilder.builder()
				.username(ADMIN_USER)
				.password(ADMIN_PASSWORD)
				.realm(REALM)
				.clientSecret("978ad148-d99b-406d-83fc-578597290a79")
				.clientId("orion-pep")
				.grantType("password")
				.serverUrl(KEYCLOAK_ADDRESS)
				.build()
				.tokenManager();
		return tokenManager.getAccessToken().getToken();
	}

	private String getNotAllowedToken() {
		TokenManager tokenManager = KeycloakBuilder.builder()
				.username(NOT_ALLOWED_USER)
				.password(NOT_ALLOWED_PASSWORD)
				.realm(REALM)
				.clientSecret("978ad148-d99b-406d-83fc-578597290a79")
				.clientId("orion-pep")
				.grantType("password")
				.serverUrl(KEYCLOAK_ADDRESS)
				.build()
				.tokenManager();
		return tokenManager.getAccessToken().getToken();
	}
}
