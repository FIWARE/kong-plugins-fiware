package main

import (
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/Kong/go-pdk"
	"github.com/Kong/go-pdk/server"
	log "github.com/sirupsen/logrus"
)

// declarative config
type Config struct {
	AuthorizationEndpointType    string
	AuthorizationEndpointAddress string
	KeyrockAppId                 string
	KeycloakRealm                string
	DecisionCacheExpiryInS       int64
}

// represents the neccessary info about a request to be forwarded to PDP
type RequestInfo struct {
	Method              string
	Path                string
	AuthorizationHeader string
}

// Interface to the http-client
type httpClient interface {
	Get(url string) (*http.Response, error)
	Do(req *http.Request) (*http.Response, error)
}

// PDP interface, needs to be implemented for connection to the concret PDP like Keyrock.
type PDP interface {
	Authorize(conf Config, requestInfo RequestInfo) bool
}

// inteface to kong for better testability
type KongI interface {
	GetPath() (string, error)
	GetHeader(key string) (string, error)
	GetMethod() (string, error)
	Exit(code int, msg string)
}

type Kong struct {
	pdk *pdk.PDK
}

func (k Kong) GetPath() (string, error) {
	return k.pdk.Request.GetPath()
}

func (k Kong) GetHeader(key string) (string, error) {
	return k.pdk.Request.GetHeader(key)
}

func (k Kong) GetMethod() (string, error) {
	return k.pdk.Request.GetMethod()
}

func (k Kong) Exit(code int, msq string) {
	k.pdk.Response.Exit(code, msq, make(map[string][]string))
}

// version of the plugin to be presented - should be set at build time
var Version string

// we want to be executed before the request transformer(801) can strip the token, but allow verfication of the token(e.g. jwt(1005) or oauth(1004) plugin before)
// see current order: https://docs.konghq.com/gateway/latest/plugin-development/custom-logic/#plugins-execution-order
var DefaultPriority = 805

var authorizationHttpClient httpClient = &http.Client{}
var keyrockPDP PDP = &KeyrockPDP{}

func main() {

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

func (conf Config) Access(kong *pdk.PDK) {
	// hand over to the interface
	handleRequest(Kong{pdk: kong}, conf)
}

func handleRequest(kong KongI, conf Config) {
	var desicion = false

	requestInfo, err := parseKongRequest(kong)
	if err != nil {
		log.Errorf("Was not able to parse the request. Err: %v", err)
		kong.Exit(400, "Request rejected due to unparsable request.")
		return
	}

	if conf.AuthorizationEndpointType == "Keyrock" {
		desicion = keyrockPDP.Authorize(conf, requestInfo)
	}
	if !desicion {
		log.Infof("Request was not allowed.")
		kong.Exit(403, fmt.Sprintf("Request forbidden by authorization service %s.", conf.AuthorizationEndpointType))
	}
	log.Debugf("Request was allowed.")
}

func parseKongRequest(kong KongI) (requestInfo RequestInfo, err error) {
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

	authHeader, err := kong.GetHeader("authorization")
	if err != nil {
		log.Errorf("No auth header was provided. Err: %v", err)
		return requestInfo, err
	}

	return RequestInfo{Method: requestMethod, Path: requestPath, AuthorizationHeader: authHeader}, err
}
