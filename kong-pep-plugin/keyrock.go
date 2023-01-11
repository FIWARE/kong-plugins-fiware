package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"time"

	cache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

// implementation of the PDP-inteface for keyrock
type KeyrockPDP struct{}

// struct to represent the body of an authorization request to keyrock
type KeyrockRequest struct {
	method string
	path   string
	token  string
}

// struct to represent the response of a authorization request to keyrock.
// only contains the information interesting in our current context
type KeyrockResponse struct {
	// we are only interested in that
	AuthorizationDecision string `json:"authorization_decision"`
}

// decision cache used by keyrock
var keyrockDecisionCache *cache.Cache

// is caching enabled?
var keyrockCacheEnabled bool = true

func (KeyrockPDP) Authorize(conf *Config, requestInfo *RequestInfo) (decision *bool) {

	// false until proven otherwise.
	decision = getNegativeDecision()

	// generate request to keyrock
	authzRequest, err := http.NewRequest(http.MethodGet, conf.AuthorizationEndpointAddress, nil)
	if err != nil {
		log.Errorf("[Keyrock] Was not able to create authz request to %s. Err: %v", conf.AuthorizationEndpointAddress, err)
		return
	}

	// remove bearer prefix
	authHeader := cleanAuthHeader(requestInfo.AuthorizationHeader)

	// build the cache key and check if a decision is available
	var keyrockRequest KeyrockRequest = KeyrockRequest{method: requestInfo.Method, path: requestInfo.Path, token: authHeader}
	var cacheKey = fmt.Sprint(keyrockRequest)
	if keyrockDecisionCache == nil {
		initKeyrockCache(conf)
	}
	var exists bool = false
	if keyrockCacheEnabled {
		_, exists = keyrockDecisionCache.Get(cacheKey)
	}

	if exists {
		log.Infof("[Keyrock] Found cached decision.")
		// we only cache success, thus dont care about the cache value
		return getPositveDecision()
	}

	query := authzRequest.URL.Query()
	query.Add("action", requestInfo.Method)
	query.Add("resource", requestInfo.Path)
	query.Add("access_token", authHeader)
	query.Add("app_id", conf.KeyrockAppId)
	query.Add("app-id", conf.KeyrockAppId)
	authzRequest.URL.RawQuery = query.Encode()

	// request a decision from keyrock
	response, err := authorizationHttpClient.Do(authzRequest)
	if err != nil {
		log.Errorf("[Keyrock] Was not able to call authorization endpoint. Err: %v", err)
		return
	}
	if response.StatusCode != 200 {

		log.Errorf("[Keyrock] Did not receive a successful response. Status: %v, Body: %v", response.StatusCode, response.Body)
		return
	}

	// analyze and potentially cache the response
	var authzResponse KeyrockResponse
	err = json.NewDecoder(response.Body).Decode(&authzResponse)
	if err != nil {
		log.Errorf("[Keyrock] Response body was not valid. Err: %v", err)
		return
	}
	if authzResponse.AuthorizationDecision == "Permit" {
		log.Debugf("[Keyrock] Successfully authorized the request.")
		if keyrockCacheEnabled {
			keyrockDecisionCache.Add(cacheKey, true, cache.DefaultExpiration)
		}
		return getPositveDecision()
	} else {
		log.Infof("[Keyrock] Request was not allowed. Response was %v.", response.Body)
		return
	}
}

func initKeyrockCache(config *Config) {
	var expiryStr = config.DecisionCacheExpiryInS
	expiry, err := strconv.Atoi(expiryStr)
	if err != nil {
		log.Warnf("[Keyrock] Decision cache not properly configured: %s", expiryStr)
		keyrockCacheEnabled = false
		return
	}
	if expiry == -1 {
		log.Info("[Keyrock] Decision caching is disabled.")
		keyrockCacheEnabled = false
		return
	}
	if expiry == 0 {
		log.Infof("[Keyrock] Use default expiry of %vs.", DefaultExpiry)
		expiry = DefaultExpiry
	}
	keyrockCacheEnabled = true
	keyrockDecisionCache = cache.New(time.Duration(expiry)*time.Second, time.Duration(2*expiry)*time.Second)
}
