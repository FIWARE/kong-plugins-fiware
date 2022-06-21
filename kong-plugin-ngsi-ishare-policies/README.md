# kong-plugin-ngsi-ishare-policies

Kong plugin to support attribute-based access management for NGSI requests with the iSHARE scheme. 

This requires the availability of an iSHARE-compliant authorisation registry (AR) and an 
iSHARE satellite, where the participant has been registered with it's EORI.


## Installation

Follow the Kong manual for the installation of plugins: 
<https://docs.konghq.com/gateway/latest/plugin-development/distribution/>

The plugin is available 
on [luarocks](https://luarocks.org/modules/fiware/kong-plugin-ngsi-ishare-policies).


## Configuration

The following gives an example on how to configure an endpoint with this plugin 
using the declarative setup:
```yaml
services:
    # Host of the actual service endpoint to be protected, e.g., a context broker instance
  - host: "<SERVICE_HOST>"
    # Service name (only internal purpose)
    name: "my-service"
	# Port of the actual service endpoint
    port: <SERVICE_PORT>
	# Protocol of actual service endpoint, e.g. "http" if no SSL is used
    protocol: <SERVICE_PROTOCOL>
	# Routes config
    routes:
      - name: my-route
		# Path for this route for the gateway, endpoint then would be "https://my-kong-host/my-service"
        paths:
          - /my-service
        strip_path: true
	# Plugin config
    plugins:
      - name: ngsi-ishare-policies
        config:
		  # Where to look for access tokens (allowed: uri_param_names, header_names, cookie_names)
          access_token:
            header_names:
              - "authorization"
              - "Authorization"
		  # Config of authorisation registry to be used to retrieve access policies
          ar:
            identifier: "<AR_EORI>"
            host: "<AR_HOST>"
            token_endpoint: "<AR_TOKEN_ENDPOINT>"
            delegation_endpoint: "<AR_DELEGATION_ENDPOINT>"
		  # Config of iSHARE satellite to be used to verify incoming requests
          satellite:
            identifier: "<SATELLITE_EORI>"
            host: "<SATELLITE_HOST>"
            token_endpoint: "<SATELLITE_TOKEN_ENDPOINT>"
            trusted_list_endpoint: "<SATELLITE_TRUSTED_LIST_ENDPOINT>"
		  # EORI, key and certs of service provider hosting this Kong instance
          jws:
		    # EORI of service provider
            identifier: "<SERVICE_PROVIDER_EORI>"
			# Private key
			private_key: |
			  -----BEGIN PRIVATE KEY-----
			  <SERVICE_PROVIDER_PRIVATE_KEY>
			  -----END PRIVATE KEY-----
			# Put full x5c certificate chain
			x5c: |
			  -----BEGIN CERTIFICATE-----
			  <SERVICE_PROVIDER_CERT>
			  -----END CERTIFICATE-----
			  ...<INTERMEDIATES>...
			  -----BEGIN CERTIFICATE-----
			  <ROOT_CA_CERT>
			  -----END CERTIFICATE-----
```
