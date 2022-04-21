local typedefs = require "kong.db.schema.typedefs"

return {
   name = "ngsi-ishare-policies",
   fields = {
      {
	 -- this plugin will only be applied to Services or Routes
	 consumer = typedefs.no_consumer
      },
      {
	 -- this plugin will only run within Nginx HTTP module
	 protocols = typedefs.protocols_http
      },
      {
	 -- Config schema
	 config = {
	    type = "record",
	    fields = {
	       -- Location of iSHARE JWT access token in requests
	       {
		  access_token = {
		     type = "record",
		     fields = {
			-- URI parameter names
			{ uri_param_names = {
			     type = "set",
			     elements = { type = "string" },
			     default = { "jwt" },
			}, },
			-- Header names
			{ header_names = {
			     type = "set",
			     elements = { type = "string" },
			     default = { "authorization" },
			}, },
			-- Cookie names
			{ cookie_names = {
			     type = "set",
			     elements = { type = "string" },
			     default = {}
			}, }
		     }
		  }
	       },
	       -- JWS config
	       {
		  jws = {
		     type = "record",
		     fields = {
			-- Identifier/EORI of local authority
			{ identifier = {
			     type = "string",
			     required = true,
			},  },
			-- Private key (PEM format)
			{ private_key = {
			     type = "string",
			     required = true,
			},  },
			-- x5c chain (array of certificates in PEM format)
			{ x5c = {
			     type = "array",
			     required = true,
			     elements = { type = "string" },
			},  },
			-- Path to Root CA file (required if no iSHARE Satellite information is provided)
			{ root_ca_file = {
			     type = "string",
			     required = false,
			     default = nil
			},  },
		     }
		  }
	       },
	       -- Authorisation Registry (AR) config
	       {
		  ar = {
		     type = "record",
		     fields = {
			-- Identifier/EORI of AR
			{ identifier = {
			     type = "string",
			     required = true,
			},  },
			-- Host of AR
			{ host = {
			     type = "string",
			     required = true,
			},  },
			-- Token endpoint of AR
			-- e.g., https://my-keyrock/oauth2/token
			{ token_endpoint = {
			     type = "string",
			     required = true,
			},  },
			-- Delegation endpoint of AR
			-- e.g., https://my-keyrock/ar/policy
			{ delegation_endpoint = {
			     type = "string",
			     required = true,
			},  },
		     }
		  }
	       },
	       -- iSHARE Satellite config
	       -- Required, if no Root CA file is given.
	       -- Preferred way for verification of iSHARE JWTs.
	       {
		  satellite = {
		     type = "record",
		     fields = {
			-- Identifier/EORI of Satellite
			{ identifier = {
			     type = "string",
			     required = false,
			},  },
			-- Host of Satellite
			{ host = {
			     type = "string",
			     required = false,
			},  },
			-- Token endpoint of Satellite
			-- e.g., https://scheme.isharetest.net/connect/token
			{ token_endpoint = {
			     type = "string",
			     required = false,
			},  },
			-- Trusted list endpoint of Satellite
			-- e.g., https://scheme.isharetest.net/trusted_list
			{ trusted_list_endpoint = {
			     type = "string",
			     required = false,
			},  }
		     }
		  }
	       }
	    }
	 }
      }
   },
   -- Validation rules
   entity_checks = {
      -- Satellite config is mandatory, if no Root CA File is given
      { conditional = {
	   if_field = "config.jws.root_ca_file", if_match = { eq = nil },
	   then_field = "config.satellite.identifier", then_match = { required = true },
      } },
      { conditional = {
	   if_field = "config.jws.root_ca_file", if_match = { eq = nil },
	   then_field = "config.satellite.host", then_match = { required = true },
      } }
      { conditional = {
	   if_field = "config.jws.root_ca_file", if_match = { eq = nil },
	   then_field = "config.satellite.token_endpoint", then_match = { required = true },
      } }
      { conditional = {
	   if_field = "config.jws.root_ca_file", if_match = { eq = nil },
	   then_field = "config.satellite.trusted_list_endpoint", then_match = { required = true },
      } }
  },
}
