package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v11"
	cache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

// implementation of the PDP-interface for keycloak
type KeycloakPDP struct{}

// shadow interface for the GoCloak-client to enable better testability
type KeycloackClientI interface {
	LoginClient(ctx context.Context, clientID, clientSecret, realm string) (*gocloak.JWT, error)
	GetResourcesClient(ctx context.Context, token, realm string, params gocloak.GetResourceParams) ([]*gocloak.ResourceRepresentation, error)
	GetRequestingPartyPermissionDecision(ctx context.Context, token, realm string, options gocloak.RequestingPartyTokenOptions) (*gocloak.RequestingPartyPermissionDecision, error)
}

type KeycloakClient struct {
	goCloakClient gocloak.GoCloak
}

func (kc KeycloakClient) LoginClient(ctx context.Context, clientID, clientSecret, realm string) (*gocloak.JWT, error) {
	return kc.goCloakClient.LoginClient(ctx, clientID, clientSecret, realm)
}

func (kc KeycloakClient) GetResourcesClient(ctx context.Context, token, realm string, params gocloak.GetResourceParams) ([]*gocloak.ResourceRepresentation, error) {
	return kc.goCloakClient.GetResourcesClient(ctx, token, realm, params)
}

func (kc KeycloakClient) GetRequestingPartyPermissionDecision(ctx context.Context, token, realm string, options gocloak.RequestingPartyTokenOptions) (*gocloak.RequestingPartyPermissionDecision, error) {
	return kc.goCloakClient.GetRequestingPartyPermissionDecision(ctx, token, realm, options)
}

// keycloak interface to allow replacement of KeycloakClient in the test
type KeycloakClientFactoryI interface {
	NewKeycloakClient(conf *Config) KeycloackClientI
}

type KeycloackClientFactory struct{}

func (kf KeycloackClientFactory) NewKeycloakClient(conf *Config) KeycloackClientI {
	return &KeycloakClient{gocloak.NewClient(conf.AuthorizationEndpointAddress, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms"))}
}

// struct to represent an authorization request to keyrock, will be used as cache-key
type KeycloackRequest struct {
	method string
	path   string
	token  string
	claims string
}

// is the decision cache enabled?
var keycloakCacheEnabled bool = true

// decision cache to be used
var keycloakDecisionCache *cache.Cache = cache.New(time.Duration(DefaultExpiry)*time.Second, time.Duration(2*DefaultExpiry)*time.Second)

// expiry for decision cache entries
var decisionExpiry int

// is the resources cache enabled?
var keycloakResourcesCacheEnabled bool = true

// resources cache to be used
var keycloakResourcesCache *cache.Cache = cache.New(time.Duration(DefaultExpiry)*time.Second, time.Duration(2*DefaultExpiry)*time.Second)

// expiry for resources cache entries
var resourcesExpiry int

// factory instance for the client
var keycloakClientFactory KeycloakClientFactoryI = &KeycloackClientFactory{}

// keycloak client to be used
var keycloakClient KeycloackClientI

func (KeycloakPDP) Authorize(conf *Config, requestInfo *RequestInfo) (decision *bool) {

	// false until proven otherwise.
	decision = getNegativeDecision()

	// build directly, so that it can serve as part of the cache-key
	claimToken, err := buildClaimToken(conf, requestInfo)

	if err != nil {
		log.Errorf("[Keycloak] Was not able to build claim token. Err: %v", err)
		return
	}

	var keycloackRequest KeycloackRequest = KeycloackRequest{method: requestInfo.Method, path: requestInfo.Path, token: requestInfo.AuthorizationHeader, claims: claimToken}
	var cacheKey = fmt.Sprint(keycloackRequest)

	initKeycloakDecisionCache(conf)
	var exists bool = false
	if keycloakCacheEnabled {
		_, exists = keycloakDecisionCache.Get(cacheKey)
	}

	if exists {
		log.Debugf("[Keycloak] Found cached decision.")
		// we only cache success, thus dont care about the cache value
		return getPositveDecision()
	}

	keycloakClient = keycloakClientFactory.NewKeycloakClient(conf)
	token, err := getServiceAccountToken(conf)
	if err != nil {
		log.Errorf("[Keycloak] Could not get resources. Err: %v", err)
		return
	}

	krl, err := getResourcesFromKeycloak(conf, requestInfo.Path, requestInfo.AuthorizationHeader, &token)
	if err != nil {
		log.Errorf("[Keycloak] Failed to get resources. Err: %v", err)
		return
	}

	decision, err = checkPermission(conf, requestInfo, krl, &claimToken)
	if err != nil {
		log.Errorf("[Keycloak] Failed to check permissions")
		return
	}
	if *decision && keyrockCacheEnabled {
		keycloakDecisionCache.Add(cacheKey, true, time.Duration(decisionExpiry)*time.Second)
	}
	return
}

// get a service account token to be used on connections to keycloak
func getServiceAccountToken(conf *Config) (tokenString string, err error) {
	if conf.KeycloakClientID == "" || conf.KeycloakClientSecret == "" || conf.KeycloakRealm == "" {
		log.Errorf("[Keycloak] No proper config provided. Conf: %v", conf)
		return tokenString, errors.New("no proper keycloak config")
	}

	ctx := context.Background()
	token, err := keycloakClient.LoginClient(ctx, conf.KeycloakClientID, conf.KeycloakClientSecret, conf.KeycloakRealm)
	if err != nil {
		log.Errorf("[Keycloak] Was not able to get a token. Err: %v", err)
		return
	}

	return token.AccessToken, err
}

// retrieve all resources for the given path from keycloak
func getResourcesFromKeycloak(conf *Config, path string, tokenHeader string, serviceAccountToken *string) (resourceRepresentation []*gocloak.ResourceRepresentation, err error) {

	initKeycloackResourcesCache(conf)

	if keycloakResourcesCacheEnabled {
		resourceRepresentation, exists := keycloakResourcesCache.Get(path)
		if exists {
			return resourceRepresentation.([]*gocloak.ResourceRepresentation), err
		}
	}
	matchingUri := true
	max := -1
	params := gocloak.GetResourceParams{URI: &path, Max: &max, MatchingURI: &matchingUri}

	resourceRepresentation, err = keycloakClient.GetResourcesClient(
		context.Background(),
		*serviceAccountToken,
		conf.KeycloakRealm,
		params,
	)

	if err != nil {
		log.Errorf("[Keycloak] Was not able to call resources endpoint. Err: %v", err)
		return
	}

	log.Debugf("[Keycloak] Received resources diff: %v", resourceRepresentation)
	if keycloakResourcesCacheEnabled {
		keycloakResourcesCache.Add(path, resourceRepresentation, time.Duration(resourcesExpiry)*time.Second)
	}
	return
}

// request the authorization decision from keycloak for the required permissions(based on the resource-representations) and claims
func checkPermission(conf *Config, requestInfo *RequestInfo, kl []*gocloak.ResourceRepresentation, claimToken *string) (decision *bool, err error) {

	decision = getNegativeDecision()

	grant_type := "urn:ietf:params:oauth:grant-type:uma-ticket"
	claim_token_format := "urn:ietf:params:oauth:token-type:jwt"
	permissions, err := buildPermissionsParameter(kl)
	if err != nil {
		log.Errorf("[Keycloak] Wasnt able to build the permission parameter. Err: %v", err)
		return
	}
	subject_token := cleanAuthHeader(requestInfo.AuthorizationHeader)
	requestParams := &gocloak.RequestingPartyTokenOptions{
		GrantType:        &grant_type,
		Audience:         &conf.KeycloakClientID,
		ClaimToken:       claimToken,
		ClaimTokenFormat: &claim_token_format,
		Permissions:      permissions,
	}

	keycloakDecision, err := keycloakClient.GetRequestingPartyPermissionDecision(context.Background(), subject_token, conf.KeycloakRealm, *requestParams)

	if err != nil {
		log.Errorf("[Keycloak] Was not able to get decision. Err: %v", err)
		return
	}

	log.Debugf("[Keycloak] Request was allowed by keycloak.")
	return keycloakDecision.Result, err
}

// build the permission parameter(e.g. list of premission ids) from the resources
func buildPermissionsParameter(kl []*gocloak.ResourceRepresentation) (permissions *[]string, err error) {

	resourceIds := []string{}
	for _, resource := range kl {
		if resource.ID == nil || *resource.ID == "" {
			log.Errorf("[Keycloak] Received a resource without an id.")
			return permissions, errors.New("received resource without an id")
		}
		resourceIds = append(resourceIds, *resource.ID)
	}
	log.Debugf("[Keycloak] Request permissions: %v", resourceIds)
	return &resourceIds, err
}

// build the token containing the requested claims(e.g. path and method + additional claims from the headers)
func buildClaimToken(conf *Config, requestInfo *RequestInfo) (token string, err error) {

	if requestInfo.Method == "" {
		log.Error("[Keycloak] Did not receive valid request info. Method missing.")
		return token, errors.New("did not receive valid request info. method missing")
	}

	if requestInfo.Path == "" {
		log.Errorf("[Keycloak] Did not receive valid request info. Path missing.")
		return token, errors.New("did not receive valid request info. path missing")
	}

	manadatoryClaims := []string{fmt.Sprintf("\"http.method\":[\"%s\"]", requestInfo.Method), fmt.Sprintf("\"http.uri\":[\"%s\"]", requestInfo.Path)}
	optionalClaims := []string{}

	for claim, header := range conf.KeycloackAdditionalClaims {
		headerValues := requestInfo.Headers[header]
		if headerValues == nil {
			log.Errorf("[Keycloak] Header %s for additional claim %s is not present.", header, claim)
			return token, errors.New("expected header is not present")
		}
		headerValue := requestInfo.Headers[header][0]
		optionalClaims = append(optionalClaims, fmt.Sprintf("\"%s\": [\"%s\"]", claim, headerValue))
	}
	allClaims := append(manadatoryClaims, optionalClaims...)
	allClaimsString := strings.Join(allClaims, ",")
	unencodedClaims := fmt.Sprintf("{ %s }", allClaimsString)

	log.Debugf("[Keycloak] All claims: %s", unencodedClaims)

	// jwt uses url encoding, do not change to StdEncoding
	return base64.URLEncoding.EncodeToString([]byte(unencodedClaims)), err
}

func initKeycloackResourcesCache(config *Config) {
	resourcesExpiry = config.DecisionCacheExpiryInS
	if resourcesExpiry == -1 {
		log.Debugf("[Keycloak] Resource caching is disabled.")
		keycloakResourcesCacheEnabled = false
		return
	}
	if resourcesExpiry == 0 {
		resourcesExpiry = DefaultExpiry
	}
}

func initKeycloakDecisionCache(config *Config) {
	decisionExpiry = config.DecisionCacheExpiryInS
	if decisionExpiry == -1 {
		log.Debugf("[Keycloak] Decision caching is disabled.")
		keycloakCacheEnabled = false
		return
	}
	if decisionExpiry == 0 {
		decisionExpiry = DefaultExpiry
	}
}
