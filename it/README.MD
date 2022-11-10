# Test the pdp setup

1. run `mvn clean install -Pdev`
2. execute:
```shell
curl --location --request GET 'localhost:8070/orion-ext-authz/ngsi-ld/v1/entities?type=DELIVERYORDER' \
     --header 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJkaWQ6ZWxzaTpwYWNrZXRkZWxpdmVyeSIsImlhdCI6MTY2NzU0NTExMiwiZXhwIjoxNjk5MDgxMTEyLCJhdWQiOiJFVS5FT1JJLlBBQ0tFVERFTElWRVJZIiwic3ViIjoiZGlkOnBlZXI6OTlhYjViY2E0MWJiNDViNzhkMjQyYTQ2ZjAxNTdiN2QiLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaGFwcHlwZXRzLmZpd2FyZS5pby8yMDIyL2NyZWRlbnRpYWxzL2VtcGxveWVlL3YxIl0sImlkIjoiaHR0cHM6Ly9oYXBweXBldHMuZml3YXJlLmlvL2NyZWRlbnRpYWwvMjUxNTkzODktOGRkMTdiNzk2YWMwIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkN1c3RvbWVyQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOnsiaWQiOiJkaWQ6ZWxzaTpoYXBweXBldHMifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6cGVlcjo5OWFiNWJjYTQxYmI0NWI3OGQyNDJhNDZmMDE1N2I3ZCIsImF1dGhvcml6YXRpb25SZWdpc3RyeSI6eyJpZCI6IkVVLkVPUkkuSEFQUFlQRVRTIiwiaG9zdCI6Imh0dHA6Ly9rZXlyb2NrOjYwODAiLCJ0b2tlblBhdGgiOiIvb2F1dGgyL3Rva2VuIiwiZGVsZWdhdGlvblBhdGgiOiIvYXIvZGVsZWdhdGlvbiJ9LCJuYW1lIjoiVXNlckEiLCJnaXZlbl9uYW1lIjoiVXNlciIsImZhbWlseV9uYW1lIjoiQSIsInByZWZlcnJlZF91c2VybmFtZSI6InVzZXItYSIsImVtYWlsIjoidXNlckBhLm9yZyIsInJvbGVzIjpbeyJuYW1lIjoiR09MRF9DVVNUT01FUiJ9XX19fQ.A9SrFxrZcDwEAwDgzSk0E4gV5DAGJTO2TiUbus6RL20'
```
The VC inside the token is: 
```json
{
   "@context": [
      "https://www.w3.org/2018/credentials/v1",
      "https://happypets.fiware.io/2022/credentials/employee/v1"
   ],
   "id": "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
   "type": [
      "VerifiableCredential",
      "CustomerCredential"
   ],
   "issuer": {
      "id": "did:elsi:happypets"
   },
   "credentialSubject": {
      "id": "did:peer:99ab5bca41bb45b78d242a46f0157b7d",
      "authorizationRegistry": {
         "id": "EU.EORI.HAPPYPETS",
         "host": "http://keyrock:6080",
         "tokenPath": "/oauth2/token",
         "delegationPath": "/ar/delegation"
      },
      "name": "UserA",
      "given_name": "User",
      "family_name": "A",
      "preferred_username": "user-a",
      "email": "user@a.org",
      "roles": [{
         "name": "GOLD_CUSTOMER"
      }]
   }
}
```
And the request will be denied by the AR from the PDP(e.g. the data-provider).
3. Setup a policy, that allows HappyPets(Consumer) Customers to access PackeDelivery(Provider)
3.1. Generate a token to access the PackeDelivery AR:
```shell
    docker run -v $(pwd)/src/test/resources/packetdelivery:/certificates -e I_SHARE_CLIENT_ID="EU.EORI.PACKETDELIVERY" -e I_SHARE_IDP_ID="EU.EORI.PACKETDELIVERY"  quay.io/wi_stefan/ishare-jwt-helper:0.2.1
```
3.2. Get an access-token from the AR, by using the generated token:
```shell
curl --location --request POST 'http://localhost:8050/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
--data-urlencode 'scope=iSHARE' \
--data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
--data-urlencode 'client_assertion=<THE_GENERATED_TOKEN>' \
--data-urlencode 'client_id=EU.EORI.PACKETDELIVERY'
```
3.3. Use the access-token to create the policy
```shell
curl --location --request POST 'http://localhost:8050/ar/policy' \
--header 'Authorization: Bearer <THE_RETRIEVED_TOKEN>' \
--header 'Content-Type: application/json' \
--data-raw '{
	"delegationEvidence": {
		"notBefore": 1667823272,
		"notOnOrAfter": 1767909833,
		"policyIssuer": "EU.EORI.PACKETDELIVERY",
		"target": {
			"accessSubject": "did:elsi:happypets"
		},
		"policySets": [
			{
				"target": {
					"environment": {
						"licenses": [
							"ISHARE.0001"
						]
					}
				},
				"policies": [
					{
						"target": {
							"resource": {
								"type": "DELIVERYORDER",
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
}'
```
4. Rerun the initial get and check the logs of the dsba-pdp. You will see that its now allowed by the AR of PacketDelivery and denied by the AR of HappyPets.
5. Configure the role at HappyPets:
   5.1. Generate a token to access the HappyPets AR:
   ```shell
       docker run -v $(pwd)/src/test/resources/happypets:/certificates -e I_SHARE_CLIENT_ID="EU.EORI.HAPPYPETS" -e I_SHARE_IDP_ID="EU.EORI.HAPPYPETS"  quay.io/wi_stefan/ishare-jwt-helper:0.2.1
   ```
   3.2. Get an access-token from the AR, by using the generated token:
   ```shell
   curl --location --request POST 'http://localhost:8080/oauth2/token' \
   --header 'Content-Type: application/x-www-form-urlencoded' \
   --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
   --data-urlencode 'scope=iSHARE' \
   --data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
   --data-urlencode 'client_assertion=<THE_GENERATED_TOKEN>' \
   --data-urlencode 'client_id=EU.EORI.HAPPYPETS'
   ```
   5.3. Use the access-token to create the policy
   ```shell
   curl --location --request POST 'http://localhost:8080/ar/policy' \
   --header 'Authorization: Bearer <THE_RETRIEVED_TOKEN>' \
   --header 'Content-Type: application/json' \
   --data-raw '{
       "delegationEvidence": {
           "notBefore": 1667823272,
           "notOnOrAfter": 1767909833,
           "policyIssuer": "EU.EORI.HAPPYPETS",
           "target": {
               "accessSubject": "GOLD_CUSTOMER"
           },
           "policySets": [
               {
                   "target": {
                       "environment": {
                           "licenses": [
                               "ISHARE.0001"
                           ]
                       }
                   },
                   "policies": [
                       {
                           "target": {
                               "resource": {
                                   "type": "DELIVERYORDER",
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
   }'
   ```
6. Now you can rerun the original request and will get a 200 response. 



