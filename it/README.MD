# PDP integration for VerifiableCredentials

The test setup includes an implementation of the [DSBA-PDP](https://github.com/wistefan/dsba-pdp), implementing steps 24-28 of the proposed 
[DSBA-MVF](https://hesusruiz.github.io/dsbamvf/).

# Test the pdp setup 

To get a working setup with all components required, run

```shell 
   mvn clean install -Pdev`
```   
Since the PDP supports 2 types of credentials(```CustomerCredential``` and ```IShareCustomerCredential```), two request flows are described.

##  CustomerCredential

Using ```CustomerCredentials``` means, that the VC assigns a role defined by the data-provider(e.g. PacketDelivery). To allow requests with such credential, we have to 
* create a trusted issuer with the capabilities to assign the VC and the role
* create the role in the authorization registry of PacketDelivery

Use the following steps to configure and test the setup:

1. Execute:
   ```shell
   curl --location --request GET 'localhost:8070/orion-ext-authz/ngsi-ld/v1/entities?type=DELIVERYORDER' \
        --header 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJkaWQ6ZWxzaTpwYWNrZXRkZWxpdmVyeSIsImlhdCI6MTY2NzU0NTExMiwiZXhwIjoxNjk5MDgxMTEyLCJhdWQiOiJFVS5FT1JJLlBBQ0tFVERFTElWRVJZIiwic3ViIjoiZGlkOnBlZXI6OTlhYjViY2E0MWJiNDViNzhkMjQyYTQ2ZjAxNTdiN2QiLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaGFwcHlwZXRzLmZpd2FyZS5pby8yMDIyL2NyZWRlbnRpYWxzL2VtcGxveWVlL3YxIl0sImlkIjoiaHR0cHM6Ly9oYXBweXBldHMuZml3YXJlLmlvL2NyZWRlbnRpYWwvMjUxNTkzODktOGRkMTdiNzk2YWMwIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIkN1c3RvbWVyQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOnsiaWQiOiJkaWQ6ZWxzaTpoYXBweXBldHMifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6cGVlcjo5OWFiNWJjYTQxYmI0NWI3OGQyNDJhNDZmMDE1N2I3ZCIsInJvbGVzIjpbeyJuYW1lIjoiR09MRF9DVVNUT01FUiJ9XX19fQ.oonPkIK5-pmUMA7-HXuyvbLxRfXsp9DrkzrTMZorkwI'
   ```
   The VC inside the token is: 
   ```json
   {
      "iss": "did:elsi:packetdelivery",
      "iat": 1667545112,
      "exp": 1699081112,
      "aud": "EU.EORI.PACKETDELIVERY",
      "sub": "did:peer:99ab5bca41bb45b78d242a46f0157b7d",
      "verifiableCredential": {
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
            "roles": [
               {
                  "name": "GOLD_CUSTOMER"
               }
            ]
         }
      }
   }
   ```
   And the request will be denied, since nothing is configured.


2. Setup ```happypets``` as a trusted-issuer, allowed to issue CustomerCredential's and assign the role ```GOLD_CUSTOMER```
```shell
   curl --location --request POST 'localhost:8040/issuer' \
   --header 'Content-Type: application/json' \
   --data-raw '{
     "id": "did:elsi:happypets",
     "capabilities": [
       {
         "validFor": {
           "from": "2017-07-21T17:32:28Z",
           "to": "2023-07-21T17:32:28Z"
         },
         "credentialsType": "CustomerCredential",
         "claims": [
           {
             "name": "roles",
             "allowedValues": [
               "GOLD_CUSTOMER",
               "STANDARD_CUSTOMER"
             ]
           }
         ],
         "policy": {}
       }
     ]
   }'
```


3. Create a policy for the role ```GOLD_CUSTOMER``` at PacketDelivery(e.g. the Provider)

   1. Generate a token to access the PackeDelivery AR:
   ```shell
    docker run -v $(pwd)/src/test/resources/packetdelivery:/certificates -e I_SHARE_CLIENT_ID="EU.EORI.PACKETDELIVERY" -e I_SHARE_IDP_ID="EU.EORI.PACKETDELIVERY"  quay.io/wi_stefan/ishare-jwt-helper:0.2.1
   ```
   2. Get an access-token from the AR, by using the generated token:
   ```shell
   curl --location --request POST 'http://localhost:8050/oauth2/token' \
   --header 'Content-Type: application/x-www-form-urlencoded' \
   --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
   --data-urlencode 'scope=iSHARE' \
   --data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
   --data-urlencode 'client_assertion=<THE_GENERATED_TOKEN>' \
   --data-urlencode 'client_id=EU.EORI.PACKETDELIVERY'
   ```
   3. Use the access-token to create the policy
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
                                   "GET",
                                   "POST",
                                   "PUT"
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
4. Rerun the initial get and check the logs of the dsba-pdp. You will see that it's now allowed by PacketDelivery.

## IShareCustomerCredential

Using the IShareCustomerCredential allows the consumer(e.g. HappyPets) to define roles different from the provider. The setup therefore requires the following configuration:
* create a trusted issuer with tha capabilities to assign the VC and define a different AR
* create the allowing policy in the authorization registry of PacketDelivery
* create the role in the authorization registry of HappyPets


1. Execute:
   ```shell
   curl --location --request GET 'localhost:8070/orion-ext-authz/ngsi-ld/v1/entities?type=DELIVERYORDER' \
        --header 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJkaWQ6ZWxzaTpwYWNrZXRkZWxpdmVyeSIsImlhdCI6MTY2NzU0NTExMiwiZXhwIjoxNjk5MDgxMTEyLCJhdWQiOiJFVS5FT1JJLlBBQ0tFVERFTElWRVJZIiwic3ViIjoiZGlkOnBlZXI6OTlhYjViY2E0MWJiNDViNzhkMjQyYTQ2ZjAxNTdiN2QiLCJ2ZXJpZmlhYmxlQ3JlZGVudGlhbCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSIsImh0dHBzOi8vaGFwcHlwZXRzLmZpd2FyZS5pby8yMDIyL2NyZWRlbnRpYWxzL2VtcGxveWVlL3YxIl0sImlkIjoiaHR0cHM6Ly9oYXBweXBldHMuZml3YXJlLmlvL2NyZWRlbnRpYWwvMjUxNTkzODktOGRkMTdiNzk2YWMwIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIklTaGFyZUN1c3RvbWVyQ3JlZGVudGlhbCJdLCJpc3N1ZXIiOnsiaWQiOiJkaWQ6ZWxzaTpoYXBweXBldHMifSwiY3JlZGVudGlhbFN1YmplY3QiOnsiaWQiOiJkaWQ6cGVlcjo5OWFiNWJjYTQxYmI0NWI3OGQyNDJhNDZmMDE1N2I3ZCIsImF1dGhvcml6YXRpb25SZWdpc3RyeSI6eyJpZCI6IkVVLkVPUkkuSEFQUFlQRVRTIiwiaG9zdCI6Imh0dHA6Ly9rZXlyb2NrOjYwODAiLCJ0b2tlblBhdGgiOiIvb2F1dGgyL3Rva2VuIiwiZGVsZWdhdGlvblBhdGgiOiIvYXIvZGVsZWdhdGlvbiJ9LCJuYW1lIjoiVXNlckEiLCJnaXZlbl9uYW1lIjoiVXNlciIsImZhbWlseV9uYW1lIjoiQSIsInByZWZlcnJlZF91c2VybmFtZSI6InVzZXItYSIsImVtYWlsIjoidXNlckBhLm9yZyIsInJvbGVzIjpbeyJuYW1lIjoiSEFQUFlQRVRTX1NUQU5EQVJEIn1dfX19.bnrOIT0sGDqcKkQIF66rXKO99gemjz19d7IJg9sjr20'
   ```
   The VC inside the token is:
```json
{
   "iss": "did:elsi:packetdelivery",
   "iat": 1667545112,
   "exp": 1699081112,
   "aud": "EU.EORI.PACKETDELIVERY",
   "sub": "did:peer:99ab5bca41bb45b78d242a46f0157b7d",
   "verifiableCredential": {
      "@context": [
         "https://www.w3.org/2018/credentials/v1",
         "https://happypets.fiware.io/2022/credentials/employee/v1"
      ],
      "id": "https://happypets.fiware.io/credential/25159389-8dd17b796ac0",
      "type": [
         "VerifiableCredential",
         "IShareCustomerCredential"
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
            "name": "HAPPYPETS_STANDARD"
         }]
      }
   }
}
```
   And the request will be denied, since nothing is configured.

2. Setup ```happypets``` as a trusted-issuer, allowed to issue IShareCustomerCredential's and assign its own AR:
```shell
   curl --location --request POST 'localhost:8040/issuer' \
   --header 'Content-Type: application/json' \
   --data-raw '{
     "id": "did:elsi:happypets",
     "capabilities": [
       {
         "validFor": {
           "from": "2017-07-21T17:32:28Z",
           "to": "2023-07-21T17:32:28Z"
         },
         "credentialsType": "IShareCustomerCredential",
         "claims": [
           {
             "name": "authorizationRegistry",
             "allowedValues": [
               "EU.EORI.HAPPYPETS"
             ]
           }
         ],
         "policy": {}
       }
     ]
   }'
```

3. Create a policy for the HappyPets at PacketDelivery(e.g. the Provider)

   1. Generate a token to access the PackeDelivery AR:
```shell
 docker run -v $(pwd)/src/test/resources/packetdelivery:/certificates -e I_SHARE_CLIENT_ID="EU.EORI.PACKETDELIVERY" -e I_SHARE_IDP_ID="EU.EORI.PACKETDELIVERY"  quay.io/wi_stefan/ishare-jwt-helper:0.2.1
```
   2. Get an access-token from the AR, by using the generated token:
```shell
curl --location --request POST 'http://localhost:8050/oauth2/token' \
--header 'Content-Type: application/x-www-form-urlencoded' \
--data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
--data-urlencode 'scope=iSHARE' \
--data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
--data-urlencode 'client_assertion=<THE_GENERATED_TOKEN>' \
--data-urlencode 'client_id=EU.EORI.PACKETDELIVERY'
```
   3. Use the access-token to create the policy
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
                                "GET",
                                "POST",
                                "PUT"
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

4. Configure the role "HAPPYPETS_STANDARD" at HappyPets:
   1. Generate a token to access the HappyPets AR:
   ```shell
       docker run -v $(pwd)/src/test/resources/happypets:/certificates -e I_SHARE_CLIENT_ID="EU.EORI.HAPPYPETS" -e I_SHARE_IDP_ID="EU.EORI.HAPPYPETS"  quay.io/wi_stefan/ishare-jwt-helper:0.2.1
   ```
   2. Get an access-token from the AR, by using the generated token:
   ```shell
   curl --location --request POST 'http://localhost:8080/oauth2/token' \
   --header 'Content-Type: application/x-www-form-urlencoded' \
   --data-urlencode 'grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer' \
   --data-urlencode 'scope=iSHARE' \
   --data-urlencode 'client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
   --data-urlencode 'client_assertion=<THE_GENERATED_TOKEN>' \
   --data-urlencode 'client_id=EU.EORI.HAPPYPETS'
   ```
   3. Use the access-token to create the policy
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
               "accessSubject": "HAPPYPETS_STANDARD"
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
5. Now you can rerun the original request and will get a 200 response. 



