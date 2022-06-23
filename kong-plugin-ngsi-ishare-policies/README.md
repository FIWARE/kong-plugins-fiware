# kong-plugin-ngsi-ishare-policies

Kong plugin to support attribute-based access management 
for [NGSI-LD](https://www.etsi.org/committee/cim?jjj=1655886425084) requests with 
the [iSHARE scheme](https://dev.ishareworks.org/index.html). 

This PEP/PDP functionality is described in 
the [i4Trust Building Blocks](https://github.com/i4Trust/building-blocks).

Usage requires the availability of an iSHARE-compliant authorisation registry (AR) and an 
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


## Policies

The following gives an example of an iSHARE-compliant delegation evidence 
representing a set of access policies issued by the service provider to a specific 
service consumer. The delegation evidence would need to be stored at the 
connected AR of the service provider in order that the plugin would grant access for these specific NGSI-LD 
operations by the specified service consumer.  
In this case, this would allow two different operations of NGSI-LD requests:
* A `PATCH` (Update Entity) request, only for a specific entity `type` and `ID` and only for the attributes `attr1` and `attr2`
* A `GET` (Read Entity) request, allowing to read the full entities of a specific `type` but with any `ID`

```json
{
	"delegationEvidence": {
        "notBefore": 1541058939,
        "notOnOrAfter": 2147483647,
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
								"type": "<ENTITY_TYPE>",
								"identifiers": [
									"urn:ngsi-ld:ENTITY_TYPE:ENTITY_ID"
								],
								"attributes": [
									"attr1", "attr2"
								]
							},
							"actions": [
								"PATCH"
							]
						},
						"rules": [
							{
								"effect": "Permit"
							}
						]
					},
					{
						"target": {
							"resource": {
								"type": "<ENTITY_TYPE>",
								"identifiers": [
									"*"
								],
								"attributes": [
									"*"
								]
							},
							"actions": [
								"GET"
							]
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
Using such policies, access can be controlled on a fine-granular basis. The policy parameters match to 
the following characteristics of NGSI-LD requests:
* `type`: Entity type
  - In the case of subscriptions, this specifies the entity types that are being watched for (only for `POST:Subscription` and `PATCH:Subscription`)
* `identifiers`: Entity IDs (array), wildcard `*` allowed
  - In the case of a notification this could specify the corresponding `subscriptionId`
  - In the case of subscriptions this could specify the ID of the subscription
* `attributes`: Entity attributes (array), wildcard `*` allowed
  - In the case of subscriptions, this specifies the entity attributes for the subscribed notification (only for `POST:Subscription` and `PATCH:Subscription`)
* `actions`: Type of method
  - `GET`: Read entity
  - `POST`: Create entity
  - `PATCH`: Update entity
  - `DELETE`: Delete entity
  - `GET:Subscription`: Read subscription
  - `POST:Subscription`: Create subscription
  - `PATCH:Subscription`: Update subscription
  - `DELETE:Subscription`: Delete subscription
  - `POST:Notification`: Allow for a notification based on a subscription send by a FIWARE Context Broker. Note, that in this case the service endpoint does not need to be a context broker instance but rather can be any service capable of receiving such notifications 

In order to identify, the consumer needs to obtain an access token before sending the 
NGSI-LD request to the API-Gateway. This must be obtained at an iSHARE-compliant 
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
and must be send (encoded) along with the NGSI-LD request (e.g., in the `Authorization` header, depending on 
the configuration of the plugin).


### User policies

Above policy is on an organisational level. This means, that in this case the service provider's 
AR contains an access policy issued by the service provider to a specific service consumer's organisation 
with EORI `<SERVICE_CONSUMER_EORI>`. 

In general, the service consumer organisation can delagate these access rights further, e.g., to a specific 
user within their Identity Management System (IDP). This allows the user to send requests directly to the 
service provider's endpoint.

In this case, the user would be issued the iSHARE JWT access token by the service consumer's IDP during 
the login process. The (decoded) JWT would have the following structure at least:
```json
{
   "iss": "<SERVICE_CONSUMER_EORI>",
   "sub": "<SERVICE_CONSUMER_USER_ID>",
   "jti": "d8a7fd7465754a4a9117ee28f5b7fb60",
   "iat": 1591966224,
   "exp": 1591966254,
   "aud": "<SERVICE_PROVIDER_EORI>",
   "authorisationRegistry": {}
   "delegationEvidence": {
       "notBefore": 1541058939,
       "notOnOrAfter": 2147483647,
       "policyIssuer": "<SERVICE_CONSUMER_EORI>",
       "target": {
         "accessSubject": "<SERVICE_CONSUMER_USER_ID>",
       },
       "policySets": [
         {
            "policies": [
            {
              "target": {
                "resource": {
                  "type": "<ENTITY_TYPE>",
                  "identifiers": [
                    "urn:ngsi-ld:ENTITY_TYPE:ENTITY_ID"
                  ],
                  "attributes": [
                    "*"
                  ]
                },
                "actions": [
                  "GET"
                ]
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
This would allow the user to read the full entities of a specific type and ID at the service provider. 
The (encoded) JWT must be send by the user along with the NGSI-LD request (e.g., in the `Authorization` header, depending on 
the configuration of the plugin).  
The plugin would then verify both policies, from the user send with the request and from the consumer's organisation stored 
in the provider's AR, whether these allow this operation and whether the consumer organisation can delegate these access rights. 

Alternatively, instead of providing the user's policies in the iSHARE JWT access token directly, the JWT can also contain information 
about the AR where the plugin can request for the user's policies. In this case, the (decoded) JWT would look like the following:
```json
{
    "iss": "<SERVICE_CONSUMER_EORI>",
    "sub": "<SERVICE_CONSUMER_USER_ID>",
    "jti": "d8a7fd7465754a4a9117ee28f5b7fb60",
    "iat": 1591966224,
    "exp": 1591966254,
    "aud": "<SERVICE_PROVIDER_EORI>",
    "authorisationRegistry": {
        "url": "<CONSUMER_AR_URL>",
        "identifier": "<CONSUMER_AR_EORI>",
        "token_endpoint": "<CONSUMER_AR_TOKEN_ENDPOINT>",
        "delegation_endpoint": "<CONSUMER_AR_DELEGATION_ENDPOINT>"
    },
    "delegationEvidence": {}
}
```
