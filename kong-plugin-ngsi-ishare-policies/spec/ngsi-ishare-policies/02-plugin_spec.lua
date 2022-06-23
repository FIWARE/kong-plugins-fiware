-- Simple tests to check for loading of plugin

local PLUGIN_NAME = "ngsi-ishare-policies"

local helpers = require "spec.helpers"
local cjson   = require "cjson"

for _, strategy in helpers.each_strategy() do

   describe("Plugin: " .. PLUGIN_NAME .. ": (access) [#" .. strategy .. "]", function()
      local client

      lazy_setup(function()

	    local bp = helpers.get_db_utils(strategy == "off" and "postgres" or strategy, nil, { PLUGIN_NAME })
	    
	    local route1 = bp.routes:insert({
		  hosts = { "test1.com" },
	    })
	    -- add the plugin with dummy config
	    bp.plugins:insert {
	       name = PLUGIN_NAME,
	       route = { id = route1.id },
	       config = {
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
		  }
	       },
	    }
	    
	    -- start kong
	    assert(helpers.start_kong({
			 -- set the strategy
			 database   = strategy,
			 -- use the custom test template to create a local mock server
			 nginx_conf = "spec/fixtures/custom_nginx.template",
			 -- make sure our plugin gets loaded
			 plugins = "bundled," .. PLUGIN_NAME,
			 -- write & load declarative config, only if 'strategy=off'
			 declarative_config = strategy == "off" and helpers.make_yaml_file() or nil,
	    }))
      end)

      lazy_teardown(function()
	    helpers.stop_kong(nil, true)
      end)
      
      before_each(function()
	    client = helpers.proxy_client()
      end)
      
      after_each(function()
	    if client then client:close() end
      end)

      -- Simple tests
      describe("Simple tests for loading plugin", function()

	 it("fails with missing access_token", function()

	    local r = client:get("/request", {
		headers = {
		   host = "test1.com"
		}
	    })
	    local res = assert(r)

	    -- Assert failed request and get body
	    local body = assert.res_status(401, res)
	    local json = cjson.decode(body)

	    -- Assert message
	    assert.same({ message = "Unauthorized" }, json)
	    
	 end)
	 
      end)
      
   end)
   
end
