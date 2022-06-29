local cjson = require "cjson"
local re_gmatch = ngx.re.gmatch
local re_match = ngx.re.match

-- lua FIWARE lib: iSHARE handler
local ishare = require "fiware.ishare.ishare_handler"

-- Kong
local jwt_decoder = require "kong.plugins.jwt.jwt_parser"
local constants = require "kong.constants"
local BasePlugin = require "kong.plugins.base_plugin"
local kong = kong

-- Init
local NgsiIshareHandler = BasePlugin:extend()
NgsiIshareHandler.PRIORITY = 1010
NgsiIshareHandler.VERSION = "0.0.1"

function NgsiIshareHandler:new()
  NgsiIshareHandler.super.new(self, "ngsi-ishare-policies")
end

--- Read the JWT access token of the request.
-- Checks for the JWT in URI parameters, then in cookies, and finally
-- in the configured header_names (defaults to `[Authorization]`).
-- @param request ngx request object
-- @param conf Plugin configuration
-- @return token JWT token contained in request (can be a table) or nil
-- @return err
local function read_token(conf)

   local args = kong.request.get_query()
   for _, v in ipairs(conf.access_token.uri_param_names) do
      if args[v] then
	 return args[v]
      end
   end

   local var = ngx.var
   for _, v in ipairs(conf.access_token.cookie_names) do
      local cookie = var["cookie_" .. v]
      if cookie and cookie ~= "" then
	 return cookie
      end
   end

   local request_headers = kong.request.get_headers()
   for _, v in ipairs(conf.access_token.header_names) do
      local token_header = request_headers[v]
      if token_header then
	 if type(token_header) == "table" then
	    token_header = token_header[1]
	 end

	 local iterator, iter_err = re_gmatch(token_header, "\\s*[Bb]earer\\s+(.+)")
	 if not iterator then
	    kong.log.err(iter_err)
	    break
	 end

	 local m, err = iterator()
	 if err then
	    kong.log.err(err)
	    break
	 end

	 if m and #m > 0 then
	    return m[1]
	 end
      end
   end
end

-- Handle error
-- Codes:
--   * 401: Unauthorized
local function handle_error(code, msg) -- key
   kong.log.debug("Returning HTTP code ", code, ": ", msg)
   return kong.response.exit(code, { message = msg })
end

-- Executed for every request from a client and before it is being proxied to the upstream service.
function NgsiIshareHandler:access(config)
   NgsiIshareHandler.super.access(self)
   kong.log.debug(" *** NGSI-iSHARE-Policies plugin access() function entered ***")
   
   -- Get JWT from request
   kong.log.debug("Reading access token from request")
   local req_token, err = read_token(config)
   if err then
      return handle_error(401, err)
   end
   local token_type = type(req_token)
   if token_type ~= "string" then
      if token_type == "nil" then
	 kong.log.debug("No access token provided")
	 return handle_error(401, "Unauthorized")
      elseif token_type == "table" then
	 return handle_error(401, "Multiple tokens provided")
      else
	 return handle_error(401, "Unrecognizable token")
      end
   end
   -- kong.log.debug("Retrieved token: ", req_token)

   -- Build config object
   local proxy_config = {
      jws = {},
      authorisation_registry = {},
      satellite = {}
   }
   proxy_config.jws = config.jws
   proxy_config.authorisation_registry = config.ar
   proxy_config.satellite = config.satellite

   -- Check for JWS parameters (key/x5c) as ENVs
   local env_key = os.getenv("FIWARE_JWS_PRIVATE_KEY")
   local env_x5c = os.getenv("FIWARE_JWS_X5C")
   if not config.jws.private_key then
      if env_key then
	 kong.log.debug("Reading private key from ENV 'FIWARE_JWS_PRIVATE_KEY'")
	 proxy_config.jws.private_key = env_key
      else
	 kong.log.error("No private key configured")
	 return handle_error(500, "Internal error")
      end
   end
   if not config.jws.x5c then
      if env_x5c then
	 kong.log.debug("Reading x5c certificate chain from ENV 'FIWARE_JWS_X5C'")
	 proxy_config.jws.x5c = env_x5c
      else
	 kong.log.error("No x5c certificate chain configured")
	 return handle_error(500, "Internal error")
      end
   end
   
   -- Build request dict
   local req_dict = {}
   req_dict.token = req_token
   req_dict.method = string.upper(kong.request.get_method())
   req_dict.request_uri = kong.request.get_path()
   req_dict.request_headers = kong.request.get_headers()
   req_dict.body_data = kong.request.get_raw_body()
   req_dict.post_args = kong.request.get_query()
   req_dict.uri_args = kong.request.get_query()

   -- Call iSHARE handler
   local err = ishare.handle_ngsi_request(proxy_config, req_dict)
   if err then
      -- Access not granted
      return handle_error(401, err)
   end

   -- Access granted
   kong.log.debug("*** Access granted ***")
   return
end


return NgsiIshareHandler



