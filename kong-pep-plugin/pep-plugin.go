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

// Interface to the http-client
type httpClient interface {
	Get(url string) (*http.Response, error)
	Do(req *http.Request) (*http.Response, error)
}

type KeyrockResponse struct {
	// we are only interested in that
	AuthorizationDecision string `json:"authorization_decision"`
}

var Version = "0.0.1"

// we want to be executed before the request transformer(801) can strip the token, but allow verfication of the token(e.g. jwt(1005) or oauth(1004) plugin before)
// see current order: https://docs.konghq.com/gateway/latest/plugin-development/custom-logic/#plugins-execution-order
var DefaultPriority = 805

var authorizationHttpClient httpClient = &http.Client{}

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
	request := kong.Request
	var desicion = false
	if conf.AuthorizationEndpointType == "Keyrock" {
		desicion = authorizeAtKeyrock(conf, request)
	}
	if !desicion {
		log.Infof("Request %v was not allowed.", request)
		kong.Response.Exit(403, fmt.Sprintf("Request forbidden by authorization service %s.", conf.AuthorizationEndpointType), make(map[string][]string))
	}
	log.Debugf("Request was allowed.")
}
