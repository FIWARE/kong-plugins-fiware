package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	cache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

type KeyrockPDP struct{}

type KeyrockRequest struct {
	method string
	path   string
	token  string
}

type KeyrockResponse struct {
	// we are only interested in that
	AuthorizationDecision string `json:"authorization_decision"`
}

var keyrockDesicionCache *cache.Cache
var keyrockCacheEnabled bool = true

func (KeyrockPDP) Authorize(conf Config, requestInfo RequestInfo) (desicion bool) {

	// its false until proven otherwise.
	desicion = false

	authzRequest, err := http.NewRequest(http.MethodGet, conf.AuthorizationEndpointAddress, nil)
	if err != nil {
		log.Errorf("[Keyrock] Was not able to create authz request to %s. Err: %v", conf.AuthorizationEndpointAddress, err)
		return
	}

	authHeader := cleanAuthHeader(requestInfo.AuthorizationHeader)

	var keyrockRequest KeyrockRequest = KeyrockRequest{method: requestInfo.Method, path: requestInfo.Path, token: authHeader}
	var cacheKey = fmt.Sprint(keyrockRequest)
	if keyrockDesicionCache == nil {
		initKeyrockCache(conf)
	}
	var exists bool = false
	if keyrockCacheEnabled {
		_, exists = keyrockDesicionCache.Get(cacheKey)
	}

	if exists {
		log.Infof("[Keyrock] Found cached desicion.")
		// we only cache success, thus dont care about the cache value
		return true
	}

	query := authzRequest.URL.Query()
	query.Add("action", requestInfo.Method)
	query.Add("resource", requestInfo.Path)
	query.Add("access_token", authHeader)
	query.Add("app-id", conf.KeyrockAppId)
	authzRequest.URL.RawQuery = query.Encode()

	response, err := authorizationHttpClient.Do(authzRequest)
	if err != nil {
		log.Errorf("[Keyrock] Was not able to call authorization endpoint. Err: %v", err)
		return
	}
	if response.StatusCode != 200 {
		log.Errorf("[Keyrock] Did not receive a successfull response. Status: %v", response.StatusCode)
		return
	}

	var authzResponse KeyrockResponse
	err = json.NewDecoder(response.Body).Decode(&authzResponse)
	if err != nil {
		log.Errorf("[Keyrock] Response body was not valid. Err: %v", err)
		return
	}
	if authzResponse.AuthorizationDecision == "Permit" {
		log.Debugf("[Keyrock] Successfully authorized the request.")
		if keyrockCacheEnabled {
			keyrockDesicionCache.Add(cacheKey, true, cache.DefaultExpiration)
		}
		return true
	} else {
		log.Infof("[Keyrock] Request was not allowed.")
		return
	}
}

func initKeyrockCache(config Config) {
	var expiry = config.DecisionCacheExpiryInS
	if expiry == -1 {
		log.Infof("[Keyrock] Decision caching is disabled.")
		keyrockCacheEnabled = false
		return
	}
	if expiry == 0 {
		log.Infof("[Keyrock] Use default expiry of %vs.", DefaultExpiry)
		expiry = DefaultExpiry
	}
	keyrockDesicionCache = cache.New(time.Duration(expiry)*time.Second, time.Duration(2*expiry)*time.Second)
}
