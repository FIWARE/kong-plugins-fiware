package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

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

type KeycloackResourcesList struct {
	Resources []KeycloackResources
}

type KeycloackResources struct {
	// all fields that we dont need are ignored.
	Name string `json:"name"`
	Type string `json:"type"`
	Id   string `json:"_id"`
}

var keycloakCacheEnabled bool = true
var keycloakDesicionCache *cache.Cache

var keycloakResourcesCacheEnabled bool = true
var keycloakResourcesCache *cache.Cache

func (KeycloakPDP) Authorize(conf Config, requestInfo RequestInfo) (desicion bool) {
	// its false until proven otherwise.
	desicion = false

	// build directly, so that it can serve as part of the cache-key
	claimToken := buildClaimToken(conf, requestInfo)

	var keycloackRequest KeycloackRequest = KeycloackRequest{method: requestInfo.Method, path: requestInfo.Path, token: requestInfo.AuthorizationHeader, claims: claimToken}
	var cacheKey = fmt.Sprint(keycloackRequest)
	if keyrockDesicionCache == nil {
		initKeycloakDesicionCache(conf)
	}
	var exists bool = false
	if keycloakCacheEnabled {
		_, exists = keycloakDesicionCache.Get(cacheKey)
	}

	if exists {
		log.Infof("[Keycloak] Found cached desicion.")
		// we only cache success, thus dont care about the cache value
		return true
	}

	krl, err := getResourcesFromKeycloak(conf, requestInfo.Path, requestInfo.AuthorizationHeader)
	if err != nil {
		log.Errorf("[Keycloak] Failed to get resources. Err: %v", err)
		return
	}
	desicion, err = checkPermission(conf, requestInfo, krl, claimToken)
	if err != nil {
		log.Errorf("[Keycloak] Failed to check permissions")
		return
	}
	if desicion && keyrockCacheEnabled {
		keycloakDesicionCache.Add(cacheKey, true, cache.DefaultExpiration)
	}
	return
}

func getResourcesFromKeycloak(conf Config, path string, tokenHeader string) (krl KeycloackResourcesList, err error) {

	if keycloakResourcesCache == nil {
		initKeycloackResourcesCache(conf)
	}
	if keycloakResourcesCacheEnabled {
		krl, exists := keycloakResourcesCache.Get(path)
		if exists {
			return krl.(KeycloackResourcesList), err
		}
	}

	resourcesRequest, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/realms/%s/authz/protection/resource_set", conf.AuthorizationEndpointAddress, conf.KeycloakRealm), nil)
	if err != nil {
		log.Errorf("[Keycloak] Was not able to create resources-request to %s. Err: %v", conf.AuthorizationEndpointAddress, err)
		return
	}

	// create the query for matching resources
	query := resourcesRequest.URL.Query()
	query.Add("matchingUri", "true")
	query.Add("deep", "true")
	query.Add("max", "-1")
	query.Add("exactName", "false")
	query.Add("uri", path)
	resourcesRequest.URL.RawQuery = query.Encode()

	// add the auth header
	resourcesRequest.Header.Add("Authorization", tokenHeader)

	log.Infof("Request: %v", resourcesRequest)

	response, err := authorizationHttpClient.Do(resourcesRequest)
	if err != nil {
		log.Errorf("[Keycloak] Was not able to call resources endpoint. Err: %v", err)
		return
	}
	if response.StatusCode != 200 {
		log.Errorf("[Keycloak] Did not receive a successfull response. Status: %v", response.StatusCode)
		return krl, errors.New("No succesfull response from keycloak.")
	}

	err = json.NewDecoder(response.Body).Decode(&krl)
	if err != nil {
		log.Errorf("[Keycloak] Resources Response body was not valid. Err: %v", err)
		return
	}
	log.Debugf("[Keycloak] Received resources: %v", krl)
	if keycloakResourcesCacheEnabled {
		keycloakResourcesCache.Add(path, krl, cache.DefaultExpiration)
	}
	return
}

func checkPermission(conf Config, requestInfo RequestInfo, krl KeycloackResourcesList, claimToken string) (desicion bool, err error) {
	// its false until proven otherwise.
	desicion = false

	// create the form data
	form := url.Values{}
	form.Add("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	form.Add("audience", conf.KeycloakClientID)
	form.Add("claim_token", claimToken)
	form.Add("permission", buildPermissionsParameter(krl))
	form.Add("subject_token", cleanAuthHeader(requestInfo.AuthorizationHeader))
	// we are only interested in the result, not the details
	form.Add("response_mode", "decision")

	tokenRequest, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", conf.AuthorizationEndpointAddress, conf.KeycloakRealm),
		strings.NewReader(form.Encode()))
	if err != nil {
		log.Errorf("[Keycloak] Was not able to create token-request to %s. Err: %v", conf.AuthorizationEndpointAddress, err)
		return
	}

	basicAuthHeaderToken := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", conf.KeycloakClientID, conf.KeycloakClientSecret)))
	tokenRequest.Header.Add("Authorization", fmt.Sprintf("Basic: %s", basicAuthHeaderToken))

	response, err := authorizationHttpClient.Do(tokenRequest)
	if err != nil {
		log.Errorf("[Keycloak] Was not able to call token endpoint. Err: %v", err)
		return
	}
	if response.StatusCode != 200 {
		log.Errorf("[Keycloak] Did not receive a successfull response. Status: %v", response.StatusCode)
		return
	}

	var desicionResponse KeycloackDesicionResponse

	err = json.NewDecoder(response.Body).Decode(&desicionResponse)
	if err != nil {
		log.Errorf("[Keycloak] Did not receive a valid response. Err: %v", err)
		return
	}

	if !desicionResponse.Result {
		log.Infof("[Keycloak] Request was not allowed by keycloak.")
		return
	}
	log.Debugf("[Keycloak] Request was allowed by keycloak.")
	return true, err
}

func buildPermissionsParameter(krl KeycloackResourcesList) string {
	resourceIds := []string{}
	for _, resource := range krl.Resources {
		resourceIds = append(resourceIds, resource.Id)
	}
	permissionsString := strings.Join(resourceIds, ", ")
	log.Debugf("[Keycloak] Request permissions: %s", permissionsString)
	return permissionsString
}

func buildClaimToken(conf Config, requestInfo RequestInfo) string {
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

func initKeycloackResourcesCache(config Config) {
	var expiry = config.KeycloakResourceCacheExpiryInS
	if expiry == -1 {
		log.Infof("[Keycloak] Resource caching is disabled.")
		keycloakResourcesCacheEnabled = false
		return
	}
	if expiry == 0 {
		log.Infof("[Keycloak] Use default expiry of %vs.", DefaultExpiry)
		expiry = DefaultExpiry
	}
	keycloakResourcesCache = cache.New(time.Duration(expiry)*time.Second, time.Duration(2*expiry)*time.Second)
}

func initKeycloakDesicionCache(config Config) {
	var expiry = config.DecisionCacheExpiryInS
	if expiry == -1 {
		log.Infof("[Keycloak] Decision caching is disabled.")
		keycloakCacheEnabled = false
		return
	}
	if expiry == 0 {
		log.Infof("[Keycloak] Use default expiry of %vs.", DefaultExpiry)
		expiry = DefaultExpiry
	}
	keycloakDesicionCache = cache.New(time.Duration(expiry)*time.Second, time.Duration(2*expiry)*time.Second)
}
