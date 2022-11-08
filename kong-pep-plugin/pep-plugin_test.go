package main

import (
	"errors"
	"testing"

	log "github.com/sirupsen/logrus"
)

var responseCode int = 0

type mockPDP struct {
	descision bool
}

type panicPDP struct{}

func (mPDP panicPDP) Authorize(conf *Config, requestInfo *RequestInfo) (decision *bool) {
	panic("Some disater happend.")
}

func (mPDP mockPDP) Authorize(conf *Config, requestInfo *RequestInfo) (decision *bool) {
	return &mPDP.descision
}

type mockKong struct {
	method             string
	methodError        error
	path               string
	pathError          error
	header             string
	headerError        error
	body               []byte
	bodyError          error
	pathWithQuery      string
	pathWithQueryError error
	headers            map[string][]string
	headersError       error
}

func (mk mockKong) GetHeader(k string) (string, error) {
	return mk.header, mk.headerError
}

func (mk mockKong) GetHeaders(max int) (map[string][]string, error) {
	return mk.headers, mk.headersError
}

func (mk mockKong) GetPath() (string, error) {
	return mk.path, mk.pathError
}

func (mk mockKong) GetMethod() (string, error) {
	return mk.method, mk.methodError
}

func (mk mockKong) GetBody() ([]byte, error) {
	return mk.body, mk.bodyError
}

func (mk mockKong) GetPathWithQuery() (string, error) {
	return mk.pathWithQuery, mk.pathWithQueryError
}

func (mk mockKong) Exit(code int, msg string) {
	responseCode = code
}

func TestPanicCatchAll(t *testing.T) {

	log.Info("TestPanicCatchAll +++++++++++++++++")
	responseCode = 0
	keyrockPDP = panicPDP{}

	handleRequest(mockKong{method: "GET", path: "/test-path", header: "Bearer myToken"}, &Config{AuthorizationEndpointType: "Keyrock"})

	if responseCode != 403 {
		t.Errorf("TestPanicCatchAll: Request should be denied on panic. Expected: %v, Actual: %v", 403, responseCode)
	}
}

func TestHandleRequest(t *testing.T) {
	type test struct {
		testName       string
		testConfig     Config
		mockKong       mockKong
		pdpDecision    bool
		expectedStatus int
	}

	tests := []test{
		{testName: "Get successfull auth from Keyrcok",
			pdpDecision: true,
			testConfig:  Config{AuthorizationEndpointType: "Keyrock"},
			mockKong:    mockKong{method: "GET", path: "/test-path", header: "Bearer myToken"},
			// success is 0, since the request is forwarded to its intentional target
			expectedStatus: 0,
		},
		{testName: "Reject for bad authorization endpoint config.",
			pdpDecision: true,
			testConfig:  Config{AuthorizationEndpointType: "Not-Implemented"},
			mockKong:    mockKong{method: "GET", path: "/test-path", header: "Bearer myToken"},
			// success is 0, since the request is forwarded to its intentional target
			expectedStatus: 403,
		},
		{testName: "Reject when PDP rejects.",
			pdpDecision: false,
			testConfig:  Config{AuthorizationEndpointType: "Keyrock"},
			mockKong:    mockKong{method: "GET", path: "/test-path", header: "Bearer myToken"},
			// success is 0, since the request is forwarded to its intentional target
			expectedStatus: 403,
		},
		{testName: "Reject when request is invalid - broken header.",
			testConfig: Config{AuthorizationEndpointType: "Keyrock"},
			mockKong:   mockKong{method: "GET", path: "/test-path", headerError: errors.New("Broken headers")},
			// success is 0, since the request is forwarded to its intentional target
			expectedStatus: 400,
		},
		{testName: "Reject when request is invalid - broken path.",
			testConfig: Config{AuthorizationEndpointType: "Keyrock"},
			mockKong:   mockKong{method: "GET", pathError: errors.New("Broken path.")},
			// success is 0, since the request is forwarded to its intentional target
			expectedStatus: 400,
		},
		{testName: "Reject when request is invalid - broken method.",
			testConfig: Config{AuthorizationEndpointType: "Keyrock"},
			mockKong:   mockKong{methodError: errors.New("Broken method.")},
			// success is 0, since the request is forwarded to its intentional target
			expectedStatus: 400,
		},
	}

	for _, tc := range tests {
		log.Info("TestHandleRequest +++++++++++++++++ Running test: ", tc.testName)

		// reset response holder
		responseCode = 0
		keyrockPDP = mockPDP{descision: tc.pdpDecision}

		handleRequest(tc.mockKong, &tc.testConfig)

		if responseCode != tc.expectedStatus {
			t.Errorf("%s: Did not get expected response status. Expected: %v, Actual: %v", tc.testName, tc.expectedStatus, responseCode)
		}
	}

}
