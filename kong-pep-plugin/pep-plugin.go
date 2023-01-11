package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	log "github.com/sirupsen/logrus"
)

// declarative config
type Config struct {
	// type of the authorization endpoint, e.g. Keyrock or Keycloak
	AuthorizationEndpointType string
	// address of the authorzation endpoint, f.e. http://keyrock.org/users or http://keycloak.org/
	AuthorizationEndpointAddress string
	// app id of the secured app in keyrock
	KeyrockAppId string
	// realm to be used in keycloak
	KeycloakRealm string
	// string of the secured client in keycloak
	KeycloakClientID string
	// secret to be used for accessing keycloak
	KeycloakClientSecret string
	// optional claims to be added when accessing keycloak. key is the claim to be used, value the header to get the claim from
	KeycloackAdditionalClaims map[string]string
	// expiry time for keycloaks resource cache
	KeycloakResourceCacheExpiryInS string
	// expiry time for the decision cache, -1 disables the cache
	DecisionCacheExpiryInS string
	// path prefix used, will be removed before handling
	PathPrefix string
}

// represents the neccessary info about a request to be forwarded to PDP
type RequestInfo struct {
	Method              string
	Path                string
	AuthorizationHeader string
	Headers             map[string][]string
	Body                []byte
	PathWithQuery       string
}

// Interface to the http-client
type httpClient interface {
	Get(url string) (*http.Response, error)
	Do(req *http.Request) (*http.Response, error)
}

// PDP interface, needs to be implemented for connection to the concret PDPs like Keyrock or Keycloak.
type PDP interface {
	Authorize(conf *Config, requestInfo *RequestInfo) *bool
}

// interface to kong for better testability
type KongI interface {
	GetPath() (string, error)
	GetHeader(key string) (string, error)
	GetHeaders(maxHeaders int) (map[string][]string, error)
	GetMethod() (string, error)
	GetBody() ([]byte, error)
	GetPathWithQuery() (string, error)
	Exit(code int, msg string)
}

// wrapper struct to abstract away the pointer to the kong pdk. Improves testability
type Kong struct {
	pdk *pdk.PDK
}

func (k Kong) GetPath() (string, error) {
	return k.pdk.Request.GetPath()
}

func (k Kong) GetHeader(key string) (string, error) {
	return k.pdk.Request.GetHeader(key)
}

func (k Kong) GetHeaders(maxHeaders int) (map[string][]string, error) {
	return k.pdk.Request.GetHeaders(maxHeaders)
}

func (k Kong) GetMethod() (string, error) {
	return k.pdk.Request.GetMethod()
}

func (k Kong) GetBody() ([]byte, error) {
	return k.pdk.Request.GetRawBody()
}

func (k Kong) GetPathWithQuery() (string, error) {
	return k.pdk.Request.GetPathWithQuery()
}

func (k Kong) Exit(code int, msq string) {
	k.pdk.Response.Exit(code, msq, make(map[string][]string))
}

// version of the plugin to be presented - should be set at build time
var Version string

// we want to be executed before the request transformer(801) can strip the token, but allow verfication of the token(e.g. jwt(1005) or oauth(1004) plugin before)
// see current order: https://docs.konghq.com/gateway/latest/plugin-development/custom-logic/#plugins-execution-order
var DefaultPriority = 805

// default expiry for decision caching
var DefaultExpiry int = 60

// pdp implementation for keyrock
var keyrockPDP PDP = &KeyrockPDP{}

// pdp implementation for keycloak
var keycloakPDP PDP = &KeycloakPDP{}

// pdp implementation for external authz
var extAuthzPDP PDP = &ExtAuthzPDP{}

// http client to be used for accessing external services
var authorizationHttpClient httpClient = &http.Client{}

// entrypoint for the plugin-server in Kong. Reads the priority and version of the plugin and starts the server.
func main() {
	log.SetLevel(log.DebugLevel)

	pepPluginPriorityEnv := os.Getenv("PEP_PLUGIN_PRIORITY")
	if pepPluginPriorityEnv != "" {
		log.Infof("Set priority for PEP-Plugin to %s", pepPluginPriorityEnv)
		priority, err := strconv.Atoi(pepPluginPriorityEnv)
		if err != nil {
			log.Fatalf("Invalid PEP-Priority configured: %v. Err: %v", pepPluginPriorityEnv, err)
		}
		log.Infof("Starting with configured priority: %v", priority)
		server.StartServer(New, Version, priority)
	} else {
		log.Infof("Starting with default priority: %v", DefaultPriority)
		server.StartServer(New, Version, DefaultPriority)
	}
}

func New() interface{} {
	return &Config{}
}

// mandatory entry method for request handling in a Kong plugin.
func (conf Config) Access(kong *pdk.PDK) {

	// hand over to the interface
	handleRequest(Kong{pdk: kong}, &conf)
}

// acutal request handler
func handleRequest(kong KongI, conf *Config) {

	// false until proven otherwise.
	decision := getNegativeDecision()

	// Catch all for fatal runtime errors. The plugin should reject all requests in this case.
	// ATTENTION: Without that handling, kong will pass through all requests in case of a crashing plugin,
	// thus creating a security hole without that.
	defer func() {
		if err := recover(); err != nil {
			log.Errorf("Panic occured: Err: %v", err)
			kong.Exit(403, "Request forbidden due to internal errors")
		}
	}()

	requestInfo, err := parseKongRequest(kong, &conf.PathPrefix)
	if err != nil {
		log.Errorf("Was not able to parse the request. Err: %v", err)
		kong.Exit(400, "Request rejected due to unparsable request.")
		return
	}

	if conf.AuthorizationEndpointType == "Keyrock" {
		log.Debug("Delegate decision to Keyrock.")
		decision = keyrockPDP.Authorize(conf, &requestInfo)
	} else if conf.AuthorizationEndpointType == "Keycloak" {
		log.Debug("Delegate decision to Keycloak.")
		decision = keycloakPDP.Authorize(conf, &requestInfo)
	} else if conf.AuthorizationEndpointType == "ExtAuthz" {
		log.Debug("Delegate decision to ExtAuthz service.")
		decision = extAuthzPDP.Authorize(conf, &requestInfo)
	}

	if !*decision {
		log.Infof("Request was not allowed.")
		kong.Exit(403, fmt.Sprintf("Request forbidden by authorization service %s.", conf.AuthorizationEndpointType))
		return
	}
	log.Debugf("Request was allowed.")
}

// Parse the request provided through the pdk wrapper and translate it into the internal model
// strips the pathPrefix from the received path
func parseKongRequest(kong KongI, pathPrefix *string) (requestInfo RequestInfo, err error) {
	requestMethod, err := kong.GetMethod()
	if err != nil {
		log.Errorf("Was not able to retrieve method from request. Err: %v", err)
		return requestInfo, err
	}

	requestPath, err := kong.GetPath()
	if err != nil {
		log.Errorf("Was not able to retrieve path from request. Err: %v", err)
		return requestInfo, err
	}
	requestPath = stripPrefix(*pathPrefix, requestPath)

	authHeader, err := kong.GetHeader("authorization")
	if err != nil {
		log.Errorf("No auth header was provided. Err: %v", err)
		return requestInfo, err
	}
	// we only support up to 20 headers for now.
	headers, err := kong.GetHeaders(20)
	if err != nil {
		log.Errorf("Was not able to retrieve headers. Err: %v", err)
		return requestInfo, err
	}

	var body []byte
	if requestMethod != http.MethodGet && requestMethod != http.MethodDelete {
		// only get body if there is one
		body, err = kong.GetBody()
		if err != nil {
			log.Errorf("Was not able to retrieve the request body.")
			return requestInfo, err
		}
	}

	// we restrict to 20 params for now.
	pathWithQuery, err := kong.GetPathWithQuery()
	if err != nil {
		log.Errorf("Was not able to retrieve path with query. Err: %v", err)
		return requestInfo, err
	}

	pathWithQuery = stripPrefix(*pathPrefix, pathWithQuery)

	return RequestInfo{Method: requestMethod, Path: requestPath, AuthorizationHeader: authHeader, Headers: headers, Body: body, PathWithQuery: pathWithQuery}, err
}

// remove prefix from the given path-string
func stripPrefix(pathPrefix string, requestPath string) (strippedPath string) {
	return strings.Replace(requestPath, pathPrefix, "", 1)
}

// remove the "bearer" prefix from the received auth header
func cleanAuthHeader(authHeader string) (cleanedHeader string) {
	cleanedHeader = strings.ReplaceAll(authHeader, "Bearer ", "")
	cleanedHeader = strings.ReplaceAll(cleanedHeader, "bearer ", "")
	return cleanedHeader
}

// helper function to get a "true"-pointer
func getPositveDecision() *bool {
	b := true
	return &b
}

// helper function to get a "false"-pointer
func getNegativeDecision() *bool {
	b := false
	return &b
}
