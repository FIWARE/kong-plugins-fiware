# Kong PEP-Plugin

Plugin for [Kong](https://konghq.com/) to support the usage of Kong as a [PEP-Proxy](https://github.com/FIWARE/tutorials.PEP-Proxy). The current implementation supports [Keyrock](https://github.com/ging/fiware-idm) as descion point.

## How it works.

![PEP-Plugin](./doc/pep-plugin.png)

The Kong plugin can be configured to work with different policy decision points(PDP). It will translate the request into the expected format and enrich it with required information(f.e. app-id). The request-info will be forwarded to the PDP. The plugin interprets the response, depending on the type and provides a decision. For better performance, this decision can be cached. The Kong-PEP-Plugin does only handle bearer-tokens in the ```Authorization```-header. 

## Configuration

| Key| Description | Default |Required|Allowed values|
|----|-------------|---------|--------|--------------|
|authorizationendpointtype| Type of the decision point. Either ```Keyrock``` or ```Keycloak``` | ```nil```| ```true```| ```Keyrock, Keycloak``` |
|authorizationendpointaddress| Url to be contacted for authorization. F.e. https://keyrock.dev/users | ```nil```| ```true```| type.URL |   
|pathprefix| Prefix used at the configured path. Will be stripped before requesting the PDP. | ```nil```| ```false```| type.String |
|keyrockappid| Id of the app in Keyrock that should be checked. | ```nil```| ```true``` in case of type ``Keyrock```| type.String |
|decisioncacheexpiryins| How fast should the decision cache expire? Caching is disabled if set to -1 | ```60``` | ```false``` | type.Int64 |   
|keycloakrealm| Realm to be used incase of Keycloak. | ```nil``` | ```false``` | type.String |   
|keycloakclientid| Client ID to be used in case of Keycloak | ```nil``` | ```false``` | type.String |   
|keycloakclientsecret| Client Secret to be used in case of Keycloak | ```nil``` | ```false``` | type.String |   
|keycloackadditionalclaims| Claims to add when authorizing at Keycloak. Key is the claim, value the header to get the claim from | ```nil``` | ```false``` | type.Map[string]string | 
|keycloakresourcecacheexpiryins| Expiry for the resource cache. Only applies for Keycloak| ```60``` | ```false``` | type.Int64 |


### Keyrock example

```yaml
    services:
      - host: "orion-ld"
        name: "orion-oidc"
        port: 1026
        protocol: http

        routes:
          - name: orion-oidc
            paths:
              - /orion
            strip_path: true

        plugins:
          - name: pep-plugin
            config:
              authorizationendpointtype: Keyrock
              authorizationendpointaddress: https://keyrock.fiware.dev/user
              keyrockappid: 7c902139-d4d0-461a-bb14-7fa29aa143fe
              decisioncacheexpiryins: 20
              pathprefix: /orion
```

The configuration above will apply the plugin to all requests on path ```/orion```. The requests will be authorized using Keyrock, running at ```https://keyrock.fiware.dev/user```. The ID of the secured app(```orion-ld```) is set in ```keyrockappid``` and the decisions will be cached for 20s. THe ```pathprefix: /orion``` will be removed before the authorization is requested at Keyrock.

### Keycloak example

```yaml
    services:
      - host: "orion-ld"
        name: "orion-oidc"
        port: 1026
        protocol: http

        routes:
          - name: orion-oidc
            paths:
              - /orion-keycloak
            strip_path: true

        plugins:
          - name: pep-plugin
            config:
              authorizationendpointtype: Keycloak
              authorizationendpointaddress: https://keycloak.fiware.dev
              keycloakrealm: test-realm
              keycloakclientid: test-id
              keycloakclientsecret: test-secret
              keycloackadditionalclaims:
                "http.fiware-service": "fiware-service"
              decisioncacheexpiryins: 20
              keycloakresourcecacheexpiryins: 120
              pathprefix: /orion-keycloak
```

The configuration above will apply the plugin to all requests on path ```/orion-keycloak```. The requests will be authorized using Keycloak, running at ```https://keycloak.fiware.dev```. The ID of the secured app(```orion-ld```) is set in ```keycloakclientid``` and keycloak will authenticate itself with the secret ```keycloakclientsecret: test-secret``` in realm ```test-realm```. The decisions will be cached for 20s and all requested resources(e.g. [resource-permissions defined in keycloak](https://www.keycloak.org/docs/latest/authorization_services/index.html#_permission_overview0)) will be cached for 120s. The authorization request will include the claim ```http.fiware-service``` with the value of the request-header ```fiware-service```. Requests without that header will be rejected.

The ```pathprefix: /orion-keycloak``` will be removed before the authorization is requested at Keyrock.

## Build 

In order to provide a functional kong-plugin, the [kong/go-plugin-tool](https://hub.docker.com/r/kong/go-plugin-tool/tags) should be used. 
Build the plugin via:

```shell
  docker run -v $(pwd):/temp/ --workdir="/temp" golang:1.18.3-alpine go mod tidy && GOOS=linux GOARCH=amd64 go build -o pep-plugin .
```

## Decision caching

Decision caching is a mechanism to improve performance for requests from the same client to the same endpoint, as for example IOT-Sensors updating their values. If enabled, the proxy will keep positive(e.g. allowed) decision in cache for a configured time and does not request a new decision on the PDP for such calls. It only holds positive decisions, to not cache (in-correct) denies on f.e. connection issues. 

### Security considerations

From a security perspective, the usage of the cache needs to be carefully considered. The authz information will not be reevaluated in the frequence configured in the token, but instead based on the cache-configuration. If the cache-expiry is set to high, this will diminish the strength of the token-based security, since a stolen token can be reused longer than configured inside the IDM-system. Changed permissions on a role(f.e. permit write to certain accounts) will not immediatly take place, but only after cache-expiry. 
Immediate effect with caching can be achived with a downtime. Since the cache exists in-memory, reloading Kong will expire all decisions and can be used in such cases. 