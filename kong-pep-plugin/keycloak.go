package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/Nerzal/gocloak/v11"
	cache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

type KeycloakPDP struct{}

type KeycloackRequest struct {
	method string
	path   string
	token  string
	claims string
}

type KeycloackDesicionResponse struct {
	Result bool `json:"result"`
}

type KeycloackResources struct {
	// all fields that we dont need are ignored.
	Name string `json:"name"`
	Type string `json:"type"`
	Id   string `json:"_id"`
}

var keycloakCacheEnabled bool = true
var keycloakDesicionCache *cache.Cache = cache.New(time.Duration(DefaultExpiry)*time.Second, time.Duration(2*DefaultExpiry)*time.Second)

var keycloakResourcesCacheEnabled bool = true
var keycloakResourcesCache *cache.Cache = cache.New(time.Duration(DefaultExpiry)*time.Second, time.Duration(2*DefaultExpiry)*time.Second)

var keycloakClient gocloak.GoCloak
var expiry int64

func (KeycloakPDP) Authorize(conf *Config, requestInfo *RequestInfo) (desicion *bool) {

	// false until proven otherwise.
	desicion = getNegativeDesicion()

	// build directly, so that it can serve as part of the cache-key
	claimToken := buildClaimToken(conf, requestInfo)

	var keycloackRequest KeycloackRequest = KeycloackRequest{method: requestInfo.Method, path: requestInfo.Path, token: requestInfo.AuthorizationHeader, claims: claimToken}
	var cacheKey = fmt.Sprint(keycloackRequest)

	initKeycloakDesicionCache(conf)
	var exists bool = false
	if keycloakCacheEnabled {
		_, exists = keycloakDesicionCache.Get(cacheKey)
	}

	if exists {
		log.Debugf("[Keycloak] Found cached desicion.")
		// we only cache success, thus dont care about the cache value
		return getPositveDesicion()
	}

	keycloakClient = gocloak.NewClient(conf.AuthorizationEndpointAddress, gocloak.SetAuthAdminRealms("admin/realms"), gocloak.SetAuthRealms("realms"))
	token, err := getServiceAccountToken(conf)
	if err != nil {
		log.Errorf("[Keycloak] Could not get resources. Err: %v", err)
	}

	krl, err := getResourcesFromKeycloak(conf, requestInfo.Path, requestInfo.AuthorizationHeader, &token)
	if err != nil {
		log.Errorf("[Keycloak] Failed to get resources. Err: %v", err)
		return
	}

	desicion, err = checkPermission(conf, requestInfo, krl, &claimToken)
	if err != nil {
		log.Errorf("[Keycloak] Failed to check permissions")
		return
	}
	if *desicion && keyrockCacheEnabled {
		keycloakDesicionCache.Add(cacheKey, true, time.Duration(expiry)*time.Second)
	}
	return
}

func getServiceAccountToken(conf *Config) (tokenString string, err error) {
	ctx := context.Background()
	token, err := keycloakClient.LoginClient(ctx, conf.KeycloakClientID, conf.KeycloakClientSecret, conf.KeycloakRealm)
	if err != nil {
		log.Errorf("[Keycloak] Was not able to get a token. Err: %v", err)
		return
	}

	return token.AccessToken, err
}

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
		keycloakResourcesCache.Add(path, resourceRepresentation, time.Duration(expiry)*time.Second)
	}
	return
}

func checkPermission(conf *Config, requestInfo *RequestInfo, kl []*gocloak.ResourceRepresentation, claimToken *string) (desicion *bool, err error) {

	desicion = getNegativeDesicion()

	grant_type := "urn:ietf:params:oauth:grant-type:uma-ticket"
	claim_token_format := "urn:ietf:params:oauth:token-type:jwt"
	permissions := buildPermissionsParameter(kl)
	subject_token := cleanAuthHeader(requestInfo.AuthorizationHeader)
	requestParams := &gocloak.RequestingPartyTokenOptions{
		GrantType:        &grant_type,
		Audience:         &conf.KeycloakClientID,
		ClaimToken:       claimToken,
		ClaimTokenFormat: &claim_token_format,
		Permissions:      permissions,
	}

	keycloakDesicion, err := keycloakClient.GetRequestingPartyPermissionDecision(context.Background(), subject_token, conf.KeycloakRealm, *requestParams)

	if err != nil {
		log.Errorf("[Keycloak] Was not able to get desicion. Err: %v", err)
		return
	}

	log.Debugf("[Keycloak] Request was allowed by keycloak.")
	return keycloakDesicion.Result, err
}

func buildPermissionsParameter(kl []*gocloak.ResourceRepresentation) *[]string {

	resourceIds := []string{}
	for _, resource := range kl {
		resourceIds = append(resourceIds, *resource.ID)
	}
	log.Debugf("[Keycloak] Request permissions: %v", resourceIds)
	return &resourceIds
}

func buildClaimToken(conf *Config, requestInfo *RequestInfo) string {

	manadatoryClaims := []string{fmt.Sprintf("\"http.method\":[\"%s\"]", requestInfo.Method), fmt.Sprintf("\"http.uri\":[\"%s\"]", requestInfo.Path)}
	optionalClaims := []string{}
	for claim, header := range conf.KeycloackAdditionalClaims {
		headerValue := requestInfo.Headers[header][0]
		optionalClaims = append(optionalClaims, fmt.Sprintf("\"%s\": [\"%s\"]", claim, headerValue))
	}
	allClaims := append(manadatoryClaims, optionalClaims...)
	allClaimsString := strings.Join(allClaims, ",")
	unencodedClaims := fmt.Sprintf("{ %s }", allClaimsString)

	log.Debugf("[Keycloak] All claims: %s", unencodedClaims)

	return base64.StdEncoding.EncodeToString([]byte(unencodedClaims))
}

func initKeycloackResourcesCache(config *Config) {
	expiry = config.DecisionCacheExpiryInS
	if expiry == -1 {
		log.Debugf("[Keycloak] Resource caching is disabled.")
		keycloakResourcesCacheEnabled = false
		return
	}
	if expiry == 0 {
		expiry = DefaultExpiry
	}
}

func initKeycloakDesicionCache(config *Config) {
	expiry = config.DecisionCacheExpiryInS
	if expiry == -1 {
		log.Debugf("[Keycloak] Decision caching is disabled.")
		keycloakCacheEnabled = false
		return
	}
	if expiry == 0 {
		expiry = DefaultExpiry
	}
}
