package org.fiware.kong.pep.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.ArrayList;
import java.util.List;

public class KeyrockApplication {

	public String id = "7c902139-d4d0-461a-bb14-7fa29aa143fe";
	public String name;
	public String description;
	@JsonProperty("redirect_uri")
	public String redirectUri;
	@JsonProperty("grant_type")
	public List<String> grantType = new ArrayList<>();
	@JsonProperty("token_types")
	public List<String> tokenTypes = new ArrayList<>();

}
