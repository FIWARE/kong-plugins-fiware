-- Schema tests

local PLUGIN_NAME = "ngsi-ishare-policies"
local schema_def = require("kong.plugins."..PLUGIN_NAME..".schema")
local v = require("spec.helpers").validate_plugin_config_schema

describe("Plugin: " .. PLUGIN_NAME .. " (schema), ", function()

   it("Full config with satellite validates", function()
      assert(v({
	access_token = {
	   header_names = {"authorization", "Authorization"}
	},
	jws = {
	   identifier = "EU.EORI.TEST",
	   private_key = "XXXX",
	   x5c = "YYYY",
	},
	ar = {
	   identifier = "EU.EORI.TESTAR",
	   host = "AR_HOST",
	   token_endpoint = "AR_TOKEN",
	   delegation_endpoint = "AR_DELEGATION"
	},
	satellite = {
	   identifier = "EU.EORI.TESTSAT",
	   host = "SAT_HOST",
	   token_endpoint = "SAT_TOKEN",
	   trusted_list_endpoint = "SAT_TRUSTED_LIST"
	},
      }, schema_def))
   end)

   describe("Errors", function()

      it("jws.identifier required", function()
	 local config = {
	    access_token = {
	       header_names = {"authorization", "Authorization"}
	    },
	    jws = {
	       private_key = "XXXX",
	       x5c = "YYYY",
	    },
	    ar = {
	       identifier = "EU.EORI.TESTAR",
	       host = "AR_HOST",
	       token_endpoint = "AR_TOKEN",
	       delegation_endpoint = "AR_DELEGATION"
	    },
	    satellite = {
	       identifier = "EU.EORI.TESTSAT",
	       host = "SAT_HOST",
	       token_endpoint = "SAT_TOKEN",
	       trusted_list_endpoint = "SAT_TRUSTED_LIST"
	    },
	 }
	 local ok, err = v(config, schema_def)
	 assert.falsy(ok)
	 assert.same({
	       jws = {
		  identifier = 'required field missing'
	       }
	 }, err.config)
      end)

      it("ar.identifier required", function()
	 local config = {
	    access_token = {
	       header_names = {"authorization", "Authorization"}
	    },
	    jws = {
	       identifier = "EU.EORI.TEST",
	       private_key = "XXXX",
	       x5c = "YYYY",
	    },
	    ar = {
	       host = "AR_HOST",
	       token_endpoint = "AR_TOKEN",
	       delegation_endpoint = "AR_DELEGATION"
	    },
	    satellite = {
	       identifier = "EU.EORI.TESTSAT",
	       host = "SAT_HOST",
	       token_endpoint = "SAT_TOKEN",
	       trusted_list_endpoint = "SAT_TRUSTED_LIST"
	    },
	 }
	 local ok, err = v(config, schema_def)
	 assert.falsy(ok)
	 assert.same({
	       ar = {
		  identifier = 'required field missing'
	       }
	 }, err.config)
      end)
      
   end)
   
end)
