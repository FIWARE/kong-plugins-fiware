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
        --header 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJkaWQ6ZWJzaTpoYXBweXBldHMiLCJpYXQiOjE2Njc1NDUxMTIsImV4cCI6MTY5OTA4MTExMiwiYXVkIjoiRVUuRU9SSS5QQUNLRVRERUxJVkVSWSIsInN1YiI6ImRpZDpwZWVyOjk5YWI1YmNhNDFiYjQ1Yjc4ZDI0MmE0NmYwMTU3YjdkIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL2hhcHB5cGV0cy5maXdhcmUuaW8vMjAyMi9jcmVkZW50aWFscy9lbXBsb3llZS92MSJdLCJpZCI6Imh0dHBzOi8vaGFwcHlwZXRzLmZpd2FyZS5pby9jcmVkZW50aWFsLzI1MTU5Mzg5LThkZDE3Yjc5NmFjMCIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJDdXN0b21lckNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOmVic2k6aGFwcHlwZXRzIiwiaXNzdWFuY2VEYXRlIjoiMjAyMi0xMS0yM1QxNToyMzoxM1oiLCJ2YWxpZEZyb20iOiIyMDIyLTExLTIzVDE1OjIzOjEzWiIsImV4cGlyYXRpb25EYXRlIjoiMjAzMi0xMS0yM1QxNToyMzoxM1oiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDpwZWVyOjk5YWI1YmNhNDFiYjQ1Yjc4ZDI0MmE0NmYwMTU3YjdkIiwicm9sZXMiOlt7Im5hbWUiOlsiR09MRF9DVVNUT01FUiJdLCJ0YXJnZXQiOiJkaWQ6ZWJzaTpwYWNrZXRkZWxpdmVyeSJ9XX19fQ.R_RmlFkFaeYVR6DHzDr8_K2EpJMOL9oIsABBJuIK1QQ'
   ```
   The VC inside the token is: 
   ```json
   {
      "iss": "did:ebsi:happypets",
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
         "issuer": "did:ebsi:happypets",
         "issuanceDate": "2022-11-23T15:23:13Z",
         "validFrom": "2022-11-23T15:23:13Z",
         "expirationDate": "2032-11-23T15:23:13Z",
         "credentialSubject": {
            "id": "did:peer:99ab5bca41bb45b78d242a46f0157b7d",
            "roles": [
               {
                  "name": ["GOLD_CUSTOMER"],
                  "target": "did:ebsi:packetdelivery"
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
        --header 'Authorization: Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJkaWQ6ZWxzaTpoYXBweXBldHMiLCJpYXQiOjE2Njc1NDUxMTIsImV4cCI6MTY5OTA4MTExMiwiYXVkIjoiRVUuRU9SSS5QQUNLRVRERUxJVkVSWSIsInN1YiI6ImRpZDpwZWVyOjk5YWI1YmNhNDFiYjQ1Yjc4ZDI0MmE0NmYwMTU3YjdkIiwidmVyaWZpYWJsZUNyZWRlbnRpYWwiOnsiQGNvbnRleHQiOlsiaHR0cHM6Ly93d3cudzMub3JnLzIwMTgvY3JlZGVudGlhbHMvdjEiLCJodHRwczovL2hhcHB5cGV0cy5maXdhcmUuaW8vMjAyMi9jcmVkZW50aWFscy9lbXBsb3llZS92MSJdLCJpZCI6Imh0dHBzOi8vaGFwcHlwZXRzLmZpd2FyZS5pby9jcmVkZW50aWFsLzI1MTU5Mzg5LThkZDE3Yjc5NmFjMCIsInR5cGUiOlsiVmVyaWZpYWJsZUNyZWRlbnRpYWwiLCJDdXN0b21lckNyZWRlbnRpYWwiXSwiaXNzdWVyIjoiZGlkOmVic2k6aGFwcHlwZXRzIiwiaXNzdWFuY2VEYXRlIjoiMjAyMi0xMS0yM1QxNToyMzoxM1oiLCJ2YWxpZEZyb20iOiIyMDIyLTExLTIzVDE1OjIzOjEzWiIsImV4cGlyYXRpb25EYXRlIjoiMjAzMi0xMS0yM1QxNToyMzoxM1oiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJpZCI6ImRpZDpwZWVyOjk5YWI1YmNhNDFiYjQ1Yjc4ZDI0MmE0NmYwMTU3YjdkIiwiYXV0aG9yaXphdGlvblJlZ2lzdHJ5Ijp7IkVVLkVPUkkuSEFQUFlQRVRTIjp7Imhvc3QiOiJodHRwOi8va2V5cm9jazo2MDgwIiwidG9rZW5QYXRoIjoiL29hdXRoMi90b2tlbiIsImRlbGVnYXRpb25QYXRoIjoiL2FyL2RlbGVnYXRpb24ifX0sInJvbGVzIjpbeyJuYW1lIjpbIkdPTERfQ1VTVE9NRVIiXSwidGFyZ2V0IjoiZGlkOmVic2k6cGFja2V0ZGVsaXZlcnkiLCJwcm92aWRlciI6IkVVLkVPUkkuSEFQUFlQRVRTIn1dfX19.zqLI-vwBCveZTnpECAAKtGoOtkWM3LwKackWYye_CwE'
   ```
   The VC inside the token is:
```json
{
   "iss": "did:elsi:happypets",
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
      "issuer": "did:ebsi:happypets",
      "issuanceDate": "2022-11-23T15:23:13Z",
      "validFrom": "2022-11-23T15:23:13Z",
      "expirationDate": "2032-11-23T15:23:13Z",
      "credentialSubject": {
         "id": "did:peer:99ab5bca41bb45b78d242a46f0157b7d",
         "authorizationRegistry": {
            "EU.EORI.HAPPYPETS": {
               "host": "http://keyrock:6080",
               "tokenPath": "/oauth2/token",
               "delegationPath": "/ar/delegation"
            }
         },
         "roles": [
            {
               "name": ["GOLD_CUSTOMER"],
               "target": "did:ebsi:packetdelivery",
               "provider": "EU.EORI.HAPPYPETS"
            }
         ]
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
         "credentialsType": "CustomerCredential",
         "claims": [
           {
             "name": "authorizationRegistry",
             "allowedValues": [
               "EU.EORI.HAPPYPETS"
             ]
           },
           {
             "name": "roles.provider",
             "allowedValues": [
               "EU.EORI.HAPPYPETS"
             ]
           },
           {
            "name" : "roles",
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

# Issue a VC

1. Create the issuer did:
   
```shell
curl --location --request POST 'localhost:7002/did/create' \
   --header 'Content-Type: application/json' \
   --data-raw '{
       "method": "ebsi"
   }'
```

2. Issue the vc, the issuer id needs to be the one created in the step before:

```shell
curl --location --request POST 'localhost:7001/v1/credentials/issue' \
--header 'Content-Type: application/json' \
--data-raw '{
    "templateId": "CustomerCredential",
    "config":
    {   
        "issuerDid": "did:ebsi:zxcWtX2Xb9aZRTmiweYcu4d",
        "subjectDid": "did:peer:someone"
    },
    "credentialData":
    {
        "credentialSubject":
        {
          "id": "did:peer:99ab5bca41bb45b78d242a46f0157b7d",
            "roles": [
                {
                    "name": [
                        "GOLD_CUSTOMER"
                    ],
                    "target": "did:ebsi:packetdelivery"
                }
            ]
        }
    }
}'
```

3. Verify the credential:
```shell
curl --location --request POST 'localhost:7003/v1/verify' \
--header 'Content-Type: application/json' \
--data-raw '{
    "policies": [
        {
            "policy": "SignaturePolicy"
        },{
            "policy": "TrustedIssuerDidPolicy"
        },{
            "policy": "IssuedDateBeforePolicy"
        },{
            "policy": "ValidFromBeforePolicy"
        },{
            "policy": "ExpirationDateAfterPolicy"
        }
    ],
    "credentials":
    [
        {
            "@context": [
                "https://www.w3.org/2018/credentials/v1",
                "https://w3id.org/security/suites/jws-2020/v1"
            ],
            "credentialSchema": {
                "id": "https://raw.githubusercontent.com/walt-id/waltid-ssikit-vclib/master/src/test/resources/schemas/CustomerCredential.json",
                "type": "JsonSchemaValidator2018"
            },
            "credentialSubject": {
                "id": "did:peer:someone",
                "roles": [
                    {
                        "name": [
                            "GOLD_CUSTOMER"
                        ],
                        "target": "did:ebsi:packetdelivery"
                    }
                ]
            },
            "id": "urn:uuid:b12235da-404b-4dc5-a87a-20a5d2585585",
            "issued": "2022-11-23T15:23:13Z",
            "issuer": "did:ebsi:zxcWtX2Xb9aZRTmiweYcu4d",
            "validFrom": "2022-11-23T15:23:13Z",
            "issuanceDate": "2022-11-23T15:23:13Z",
            "type": [
                "VerifiableCredential",
                "CustomerCredential"
            ],
            "proof": {
                "type": "JsonWebSignature2020",
                "creator": "did:ebsi:zxcWtX2Xb9aZRTmiweYcu4d",
                "created": "2022-11-23T15:23:13Z",
                "verificationMethod": "did:ebsi:zxcWtX2Xb9aZRTmiweYcu4d#12c54fc7572745deb55043f56033471f",
                "jws": "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJFZERTQSJ9..c-5dyQMwBJG7yxgpClw_uxcDHdfPUo_sAdAyQt8gAm-IN9YUIK0drHRF_XSFUpXB8VmHn-lCh1OPpNr4e-7ECA"
            }
        }
    ]
}'
```