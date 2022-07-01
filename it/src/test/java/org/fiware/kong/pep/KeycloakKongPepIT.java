package org.fiware.kong.pep;

import org.junit.jupiter.api.Test;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.token.TokenManager;

public class KeycloakKongPepIT {


	private static final String KONG_ADDRESS = "http://localhost:8070";
	private static final String KEYCLOAK_ADDRESS = "http://localhost:8090";
	private static final String ORION_PATH = "/orion";
	private static final String ADMIN_USER = "admin-user";
	private static final String ADMIN_PASSWORD = "admin-user";
	private static final String REALM= "fiware-server";

	@Test
	void test() {
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
		tokenManager.getAccessToken();
	}
}
