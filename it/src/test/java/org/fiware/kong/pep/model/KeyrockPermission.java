package org.fiware.kong.pep.model;

import com.fasterxml.jackson.annotation.JsonProperty;

public class KeyrockPermission {

	public String id;
	public String name;
	public String action;
	public String resource;
	@JsonProperty("is_regex")
	public boolean isRegex;

}
