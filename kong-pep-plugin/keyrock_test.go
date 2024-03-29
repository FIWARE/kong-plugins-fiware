package main

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

var requestCounter int = 0

type mockHttpClient struct {
	mockGetResponse *http.Response
	mockDoResponse  *http.Response
	mockError       error
}

func (mhc mockHttpClient) Get(url string) (response *http.Response, err error) {
	requestCounter = requestCounter + 1
	return mhc.mockGetResponse, mhc.mockError
}

func (mhc mockHttpClient) Do(req *http.Request) (*http.Response, error) {
	requestCounter = requestCounter + 1
	return mhc.mockDoResponse, mhc.mockError
}

func TestKeyrockAuthorize(t *testing.T) {
	type test struct {
		testName         string
		testConfig       Config
		testRequest      RequestInfo
		mockResponse     *http.Response
		mockError        error
		expectedDecision bool
	}

	tests := []test{
		{testName: "Permit requests with proper information",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockResponse:     getPermitResponse(),
			expectedDecision: true,
		},
		{testName: "Deny requests on keyrock internal error.",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockResponse:     getNonOkResponse(500),
			expectedDecision: false,
		},
		{testName: "Deny requests on keyrock forbidden error.",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockResponse:     getNonOkResponse(403),
			expectedDecision: false,
		},
		{testName: "Deny requests on keyrock deny-response.",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockResponse:     getDenyResponse(),
			expectedDecision: false,
		},
		{testName: "Deny requests on keyrock invalid response.",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockResponse:     getNonJsonResponse(),
			expectedDecision: false,
		},
		{testName: "Deny requests on keyrock invalid response.",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockResponse:     getInvalidResponse(),
			expectedDecision: false,
		},
		{testName: "Deny requests on keyrock request errors.",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockError:        errors.New("Something went wrong"),
			expectedDecision: false,
		},
	}

	for _, tc := range tests {
		log.Info("TestKeyrockAuthorize +++++++++++++++++ Running test: ", tc.testName)
		authorizationHttpClient = &mockHttpClient{mockDoResponse: tc.mockResponse, mockError: tc.mockError}

		// initialize the cache before every test to not interfer with the results
		keyrockDecisionCache = nil
		decision := keyrockPDP.Authorize(&tc.testConfig, &tc.testRequest)

		if *decision != tc.expectedDecision {
			t.Errorf("%s: Decision was not as expected. Expected: %v, Actual: %v", tc.testName, tc.expectedDecision, decision)
		}
	}
}

func TestDescisionCaching(t *testing.T) {
	type test struct {
		testName         string
		testConfig       Config
		testRequest      RequestInfo
		mockResponse     *http.Response
		mockError        error
		expectCacheHit   bool
		expectedDecision bool
	}

	tests := []test{
		{testName: "Successful requests should be served from the cache",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId", DecisionCacheExpiryInS: "10", KeycloakResourceCacheExpiryInS: "10"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockResponse:     getPermitResponse(),
			expectCacheHit:   true,
			expectedDecision: true,
		},
		{testName: "Unsuccessful requests should not be cached - Deny requests on keyrock internal error.",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId", DecisionCacheExpiryInS: "10", KeycloakResourceCacheExpiryInS: "10"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockResponse:     getNonOkResponse(500),
			expectedDecision: false,
			expectCacheHit:   false,
		},
		{testName: "Unsuccessful requests should not be cached - Deny requests on keyrock forbidden error.",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId", DecisionCacheExpiryInS: "10", KeycloakResourceCacheExpiryInS: "10"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockResponse:     getNonOkResponse(403),
			expectedDecision: false,
			expectCacheHit:   false,
		},
		{testName: "Unsuccessful requests should not be cached - Deny requests on keyrock deny-response.",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId", DecisionCacheExpiryInS: "10", KeycloakResourceCacheExpiryInS: "10"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockResponse:     getDenyResponse(),
			expectedDecision: false,
			expectCacheHit:   false,
		},
		{testName: "Unsuccessful requests should not be cached - Deny requests on keyrock invalid response.",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId", DecisionCacheExpiryInS: "10", KeycloakResourceCacheExpiryInS: "10"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockResponse:     getNonJsonResponse(),
			expectedDecision: false,
			expectCacheHit:   false,
		},
		{testName: "Unsuccessful requests should not be cached - Deny requests on keyrock invalid response.",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId", DecisionCacheExpiryInS: "10", KeycloakResourceCacheExpiryInS: "10"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockResponse:     getInvalidResponse(),
			expectedDecision: false,
			expectCacheHit:   false,
		},
		{testName: "Unsuccessful requests should not be cached - Deny requests on keyrock request errors.",
			testConfig:       Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId", DecisionCacheExpiryInS: "10", KeycloakResourceCacheExpiryInS: "10"},
			testRequest:      RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockError:        errors.New("Something went wrong"),
			expectedDecision: false,
			expectCacheHit:   false,
		},
	}

	for _, tc := range tests {
		log.Info("TestDescisionCaching +++++++++++++++++ Running test: ", tc.testName)
		// null the counter
		requestCounter = 0
		authorizationHttpClient = &mockHttpClient{mockDoResponse: tc.mockResponse, mockError: tc.mockError}

		// initialize the cache before every test to not interfer with the results
		keyrockDecisionCache = nil

		// first call
		keyrockPDP.Authorize(&tc.testConfig, &tc.testRequest)
		// second call
		decision := keyrockPDP.Authorize(&tc.testConfig, &tc.testRequest)

		if tc.expectCacheHit && requestCounter > 1 {
			t.Errorf("%s: Request was expected to be served from cache. Counter is: %v", tc.testName, requestCounter)
		}
		if *decision != tc.expectedDecision {
			t.Errorf("%s: Decision was not as expected. Expected: %v, Actual: %v", tc.testName, tc.expectedDecision, decision)
		}

	}
}

func TestCacheExpiry(t *testing.T) {

	// initialize the cache before every test to not interfer with the results
	keyrockDecisionCache = nil
	// null the counter
	requestCounter = 0

	authorizationHttpClient = &mockHttpClient{mockDoResponse: getPermitResponse()}
	// config with expiry 1s, to not let the test run to long
	testConfig := Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId", DecisionCacheExpiryInS: "1"}
	testRequest := RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"}

	// first call
	keyrockPDP.Authorize(&testConfig, &testRequest)

	// wait for cache to expire(twice the expiry)
	time.Sleep(2 * time.Second)

	// second call
	keyrockPDP.Authorize(&testConfig, &testRequest)

	if requestCounter != 2 {
		t.Errorf("TestCacheExpiry: Cache should have been expired, but counter was: %v", requestCounter)
	}
}

func TestCacheDisabled(t *testing.T) {
	// initialize the cache before every test to not interfer with the results
	keyrockDecisionCache = nil
	// null the counter
	requestCounter = 0

	authorizationHttpClient = &mockHttpClient{mockDoResponse: getPermitResponse()}
	// config with expiry -1s, e.g. caching disable
	testConfig := Config{AuthorizationEndpointType: "Keyrock", KeyrockAppId: "AppId", DecisionCacheExpiryInS: "-1"}
	testRequest := RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"}

	// first call
	keyrockPDP.Authorize(&testConfig, &testRequest)
	// second call
	keyrockPDP.Authorize(&testConfig, &testRequest)
	// third call
	keyrockPDP.Authorize(&testConfig, &testRequest)

	if requestCounter != 3 {
		t.Errorf("TestCacheExpiry: Cache should have been disabled, everything should have been served from the cache. Counter was %v.", requestCounter)
	}
}

func getPermitResponse() *http.Response {
	return &http.Response{Body: io.NopCloser(strings.NewReader("{\"authorization_decision\": \"Permit\"}")), StatusCode: 200}
}

func getDenyResponse() *http.Response {
	return &http.Response{Body: io.NopCloser(strings.NewReader("{\"authorization_decision\": \"Denied\"}")), StatusCode: 200}
}

func getNonJsonResponse() *http.Response {
	return &http.Response{Body: io.NopCloser(strings.NewReader("no-json")), StatusCode: 200}
}

func getInvalidResponse() *http.Response {
	return &http.Response{Body: io.NopCloser(strings.NewReader("{\"some_other\": \"json\"}")), StatusCode: 200}
}

func getNonOkResponse(code int) *http.Response {
	return &http.Response{StatusCode: code}
}
