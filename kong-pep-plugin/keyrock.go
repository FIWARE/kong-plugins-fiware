package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/Kong/go-pdk/request"
	cache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

type KeyrockRequest struct {
	method string
	path   string
	token  string
}

var DefaultExpiry int64 = 60
var keyrockDesicionCache *cache.Cache
var keyrockCacheEnabled bool = true

func authorizeAtKeyrock(conf Config, request request.Request) (desicion bool) {

	authzRequest, err := http.NewRequest(http.MethodGet, conf.AuthorizationEndpointAddress, nil)
	// its false until proven otherwise.
	desicion = false
	if err != nil {
		log.Errorf("[Keyrock] Was not able to create authz request to %s. Err: %v", conf.AuthorizationEndpointAddress, err)
		return
	}

	requestMethod, err := request.GetMethod()
	if err != nil {
		log.Errorf("[Keyrock] Was not able to retrieve method from request. Err: %v", err)
		return
	}
	requestPath, err := request.GetPath()
	if err != nil {
		log.Errorf("[Keyrock] Was not able to retrieve path from request. Err: %v", err)
		return
	}
	hs, _ := request.GetHeaders(40)
	log.Errorf("Headers: %v", hs)
	authHeader, err := request.GetHeader("authorization")
	if err != nil {
		log.Errorf("[Keyrock] No auth header was provided. Err: %v", err)
		return
	}
	authHeader = cleanAuthHeader(authHeader)

	var keyrockRequest KeyrockRequest = KeyrockRequest{method: requestMethod, path: requestPath, token: authHeader}
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
	query.Add("action", requestMethod)
	query.Add("resource", requestPath)
	query.Add("access_token", authHeader)
	query.Add("app-id", conf.KeyrockAppId)
	authzRequest.URL.RawQuery = query.Encode()

	response, err := authorizationHttpClient.Do(authzRequest)
	if err != nil {
		log.Errorf("[Keyrock] Was not able to call authorization endpoint. Err: %v", err)
		return
	}
	if response.StatusCode != 200 {
		log.Errorf("[Keyrock] Did not receive a successfull response. %v", response)
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
		log.Infof("[Keyrock] Request was not allowed: %v.", response.Body)
		return
	}
}

func cleanAuthHeader(authHeader string) (cleanedHeader string) {
	cleanedHeader = strings.ReplaceAll(authHeader, "Bearer ", "")
	cleanedHeader = strings.ReplaceAll(cleanedHeader, "bearer ", "")

	return cleanedHeader
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
