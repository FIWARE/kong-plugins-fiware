# kong-plugin-auth-endpoint-config-ishare

Kong plugin to support access management for the 
[FIWARE Sidecar-Proxy auth endpoint config service](https://github.com/FIWARE/endpoint-auth-service/tree/main/src/endpoint-configuration-service) using 
the [iSHARE scheme](https://dev.ishareworks.org/index.html).

This PEP/PDP functionality is also described in 
the [i4Trust Building Blocks](https://github.com/i4Trust/building-blocks).

Usage requires the availability of an iSHARE-compliant authorisation registry (AR) and an 
iSHARE satellite, where the participant has been registered with it's EORI.


## Installation

Follow the Kong manual for the installation of plugins: 
<https://docs.konghq.com/gateway/latest/plugin-development/distribution/>

The plugin is available 
on [luarocks](https://luarocks.org/modules/fiware/kong-plugin-auth-endpoint-config-ishare).



## Configuration

The following gives an example on how to configure an endpoint with this plugin 
using the declarative setup:
```yaml
services:
    # Host of the actual configuration service endpoint to be protected
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
      - name: auth-endpoint-config-ishare
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



## Policies

The following gives an example of an iSHARE-compliant delegation evidence 
representing an access policy issued by the service provider to a specific 
service consumer. The delegation evidence would need to be stored at the 
connected AR of the service provider in order that the plugin would grant access on the 
authorisation endpoint configuration service to the specified service consumer.

```json
{
  "delegationEvidence": {
    "policyIssuer": "<SERVICE_PROVIDER_EORI>",
    "target": {
      "accessSubject": "<SERVICE_CONSUMER_EORI>"
    },
    "policySets": [
      {
        "policies": [
          {
            "target": {
              "resource": {
                "type": "EndpointConfig",
                "identifiers": [
                  "*"
                ],
                "attributes": [
                  "*"
                ]
              },
              "actions": [
                "POST"
              ],
            },
            "rules": [
              {
                "effect": "Permit"
              }
            ]
          }
        ]
      }
    ]
  }
}
```

In order to identify, the consumer needs to obtain an access token before sending the 
request to the API-Gateway. This must be obtained at an iSHARE-compliant 
`/token` endpoint provided by the service provider. The issued (decoded) iSHARE JWT access token 
would then have the following structure
```json
{
    "iss": "<SERVICE_PROVIDER_EORI>",
    "sub": "<SERVICE_CONSUMER_EORI>",
    "jti": "99ab5bca41bb45b78d242a46f0157b7d",
    "iat": 1540827435,
    "exp": 1540827465,
    "nbf": 1540827435,
    "aud": "<SERVICE_PROVIDER_EORI>",
}
```
and must be send (encoded) along with the request (e.g., in the `Authorization` header, depending on 
the configuration of the plugin) for the authorisation endpoint configuration service.
