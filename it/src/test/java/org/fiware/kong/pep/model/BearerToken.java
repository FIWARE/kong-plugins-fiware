package org.fiware.kong.pep.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class BearerToken {

	@JsonProperty("access_token")
	public String accessToken;
	@JsonProperty("token_type")
	public String tokenType;
}
