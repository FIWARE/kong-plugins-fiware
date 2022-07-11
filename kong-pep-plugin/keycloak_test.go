package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/Nerzal/gocloak/v11"
	cache "github.com/patrickmn/go-cache"
	log "github.com/sirupsen/logrus"
)

var keycloakRequestCounter int = 0

type mockKeycloakFactory struct {
	mockClient KeycloackClientI
}

func (mkf mockKeycloakFactory) NewKeycloakClient(conf *Config) KeycloackClientI {
	log.Info("Provide client")
	return mkf.mockClient
}

type mockKeycloakClient struct {
	loginToken     gocloak.JWT
	loginError     error
	resources      []*gocloak.ResourceRepresentation
	resourcesError error
	decision       gocloak.RequestingPartyPermissionDecision
	decisionError  error
}

func (mkc mockKeycloakClient) LoginClient(ctx context.Context, clientID, clientSecret, realm string) (*gocloak.JWT, error) {
	log.Info("Login")
	return &mkc.loginToken, mkc.loginError
}

func (mkc mockKeycloakClient) GetResourcesClient(ctx context.Context, token, realm string, params gocloak.GetResourceParams) ([]*gocloak.ResourceRepresentation, error) {
	keycloakRequestCounter = keycloakRequestCounter + 1
	return mkc.resources, mkc.resourcesError
}

func (mkc mockKeycloakClient) GetRequestingPartyPermissionDecision(ctx context.Context, token, realm string, options gocloak.RequestingPartyTokenOptions) (*gocloak.RequestingPartyPermissionDecision, error) {
	return &mkc.decision, mkc.decisionError
}

func TestKeycloakAuthorize(t *testing.T) {
	type test struct {
		testName           string
		testConfig         Config
		testRequest        RequestInfo
		mockKeycloakClient mockKeycloakClient
		expectedDecision   bool
	}

	tests := []test{
		{testName: "Allow requests with proper information",
			testConfig:         Config{AuthorizationEndpointType: "Keycloak", KeycloakRealm: "Test", KeycloakClientID: "Test-Client", KeycloakClientSecret: "Test-Secret"},
			testRequest:        RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockKeycloakClient: mockKeycloakClient{loginToken: gocloak.JWT{AccessToken: "valid-token"}, resources: []*gocloak.ResourceRepresentation{getResource("test")}, decision: getPositiveDescision()},
			expectedDecision:   true,
		}, {testName: "Deny requests if keycloak says so.",
			testConfig:         Config{AuthorizationEndpointType: "Keycloak", KeycloakRealm: "Test", KeycloakClientID: "Test-Client", KeycloakClientSecret: "Test-Secret"},
			testRequest:        RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockKeycloakClient: mockKeycloakClient{loginToken: gocloak.JWT{AccessToken: "valid-token"}, resources: []*gocloak.ResourceRepresentation{getResource("test")}, decision: getNegativeDescision()},
			expectedDecision:   false,
		}, {testName: "Deny requests if keycloak throws error.",
			testConfig:         Config{AuthorizationEndpointType: "Keycloak", KeycloakRealm: "Test", KeycloakClientID: "Test-Client", KeycloakClientSecret: "Test-Secret"},
			testRequest:        RequestInfo{Method: "GET", Path: "/my-path", AuthorizationHeader: "Bearer myToken"},
			mockKeycloakClient: mockKeycloakClient{loginToken: gocloak.JWT{AccessToken: "valid-token"}, resources: []*gocloak.ResourceRepresentation{getResource("test")}, decisionError: errors.New("keycloak unavailable")},
			expectedDecision:   false,
		},
	}

	for _, tc := range tests {
		log.Info("TestKeycloakAuthorize +++++++++++++++++ Running test: ", tc.testName)
		keycloakClientFactory = &mockKeycloakFactory{mockClient: tc.mockKeycloakClient}

		// initialize the cache before every test to not interfer with the results
		keycloakDecisionCache = cache.New(time.Duration(DefaultExpiry)*time.Second, time.Duration(2*DefaultExpiry)*time.Second)
		keycloakResourcesCache = cache.New(time.Duration(DefaultExpiry)*time.Second, time.Duration(2*DefaultExpiry)*time.Second)

		decision := keycloakPDP.Authorize(&tc.testConfig, &tc.testRequest)

		if *decision != tc.expectedDecision {
			t.Errorf("%s: Decision was not as expected. Expected: %v, Actual: %v", tc.testName, tc.expectedDecision, decision)
		}

	}
}

func TestBuildPermissionParameter(t *testing.T) {
	type test struct {
		testName                 string
		resourcesRepresentations []*gocloak.ResourceRepresentation
		expectedPermissions      []string
		expectError              bool
	}

	tests := []test{
		{testName: "Build single permission string.",
			resourcesRepresentations: []*gocloak.ResourceRepresentation{getResource("test")},
			expectedPermissions:      []string{"test"},
		},
		{testName: "Build multi permission string.",
			resourcesRepresentations: []*gocloak.ResourceRepresentation{getResource("test"), getResource("test-id-3"), getResource("yet-another-one")},
			expectedPermissions:      []string{"test", "test-id-3", "yet-another-one"},
		},
		{testName: "Build empty permission string.",
			resourcesRepresentations: []*gocloak.ResourceRepresentation{},
			expectedPermissions:      []string{},
		},
		{testName: "Fail on empty id string.",
			resourcesRepresentations: []*gocloak.ResourceRepresentation{getResource("")},
			expectError:              true,
		},
		{testName: "Fail on nil id.",
			resourcesRepresentations: []*gocloak.ResourceRepresentation{{}},
			expectError:              true,
		},
	}

	for _, tc := range tests {
		log.Info("TestBuildPermissionParameter +++++++++++++++++ Running test: ", tc.testName)

		permissionString, err := buildPermissionsParameter(tc.resourcesRepresentations)

		if err != nil && tc.expectError {
			log.Debugf("%s: Expected error.", tc.testName)
			continue
		}

		if err != nil && !tc.expectError {
			t.Errorf("%s: Building permission string failed unexpectedly. Err: %v", tc.testName, err)
		}

		if err == nil && tc.expectError {
			t.Errorf("%s: Building permission string should have failed.", tc.testName)
		}

		if fmt.Sprintf("%v", tc.expectedPermissions) != fmt.Sprintf("%v", *permissionString) {
			t.Errorf("%s: Permissions not build as expected. Expected: %v, Actual: %v", tc.testName, tc.expectedPermissions, permissionString)
		}
	}
}

func TestGetResourcesFromKeycloak(t *testing.T) {
	type test struct {
		testName           string
		testConfig         Config
		testPath           string
		testTokenHeader    string
		testServiceAccount string
		resourcesResponse  []*gocloak.ResourceRepresentation
		keycloakError      error
		expectError        bool
	}

	tests := []test{
		{testName: "Successfully get resource.",
			testConfig:         Config{KeycloakRealm: "test"},
			testPath:           "/test",
			testTokenHeader:    "auth-jwt",
			testServiceAccount: "sa-jwt",
			resourcesResponse:  []*gocloak.ResourceRepresentation{getResource("test")}},
		{testName: "Successfully get multipe resources.",
			testConfig:         Config{KeycloakRealm: "test"},
			testPath:           "/test",
			testTokenHeader:    "auth-jwt",
			testServiceAccount: "sa-jwt",
			resourcesResponse:  []*gocloak.ResourceRepresentation{getResource("test"), getResource("test-2")}},
		{testName: "Fail on keycloak error.",
			testConfig:         Config{KeycloakRealm: "test"},
			testPath:           "/test",
			testTokenHeader:    "auth-jwt",
			testServiceAccount: "sa-jwt",
			keycloakError:      errors.New("keycloak not available"),
			expectError:        true},
	}

	for _, tc := range tests {

		// no caching for this test
		keycloakResourcesCache = cache.New(time.Duration(DefaultExpiry)*time.Second, time.Duration(2*DefaultExpiry)*time.Second)

		log.Info("TestGetResourcesFromKeycloak +++++++++++++++++ Running test: ", tc.testName)
		keycloakClient = mockKeycloakClient{resources: tc.resourcesResponse, resourcesError: tc.keycloakError}

		resources, err := getResourcesFromKeycloak(&tc.testConfig, tc.testPath, tc.testTokenHeader, &tc.testServiceAccount)

		if err != nil && tc.expectError {
			log.Debugf("%s: Expected error.", tc.testName)
			continue
		}

		if err != nil && !tc.expectError {
			t.Errorf("%s: Getting service account token failed unexpectedly. Err: %v", tc.testName, err)
		}

		if err == nil && tc.expectError {
			t.Errorf("%s: Getting service account token should have failed.", tc.testName)
		}

		if fmt.Sprintf("%v", resources) != fmt.Sprintf("%v", tc.resourcesResponse) {
			t.Errorf("%s: Resources was not as expected. Expected: %v, Actual: %v", tc.testName, tc.resourcesResponse, resources)
		}
	}

}

func TestGetServiceAccountToken(t *testing.T) {
	type test struct {
		testName      string
		testConfig    Config
		tokenResponse gocloak.JWT
		tokenError    error
		expectedToken string
		expectError   bool
	}

	tests := []test{
		{testName: "Successfully get token.",
			testConfig:    Config{KeycloakRealm: "test", KeycloakClientID: "test", KeycloakClientSecret: "test"},
			tokenResponse: gocloak.JWT{AccessToken: "myToken"},
			expectedToken: "myToken"},
		{testName: "Fail with no realm.",
			testConfig:  Config{KeycloakClientID: "test", KeycloakClientSecret: "test"},
			expectError: true},

		{testName: "Fail with no clientID.",
			testConfig:  Config{KeycloakRealm: "test", KeycloakClientSecret: "test"},
			expectError: true},
		{testName: "Fail with no clientSecret.",
			testConfig:  Config{KeycloakClientID: "test", KeycloakRealm: "test"},
			expectError: true},
		{testName: "Fail with no realm and id.",
			testConfig:  Config{KeycloakClientSecret: "test"},
			expectError: true},
		{testName: "Fail with no realm and secret.",
			testConfig:  Config{KeycloakClientID: "test"},
			expectError: true},
		{testName: "Fail with no id and secret.",
			testConfig:  Config{KeycloakRealm: "test"},
			expectError: true},
		{testName: "Fail with no config values",
			testConfig:  Config{},
			expectError: true},
		{testName: "Fail with keycloak error",
			testConfig:  Config{KeycloakRealm: "test", KeycloakClientID: "test", KeycloakClientSecret: "test"},
			tokenError:  errors.New("keycloak not available"),
			expectError: true},
	}

	for _, tc := range tests {

		log.Info("TestGetServiceAccountToken +++++++++++++++++ Running test: ", tc.testName)

		keycloakClient = mockKeycloakClient{loginToken: tc.tokenResponse, loginError: tc.tokenError}

		token, err := getServiceAccountToken(&tc.testConfig)

		if err != nil && tc.expectError {
			log.Debugf("%s: Expected error.", tc.testName)
			continue
		}

		if err != nil && !tc.expectError {
			t.Errorf("%s: Getting service account token failed unexpectedly. Err: %v", tc.testName, err)
		}

		if err == nil && tc.expectError {
			t.Errorf("%s: Getting service account token should have failed.", tc.testName)
		}
		if token != tc.expectedToken {
			t.Errorf("%s: Token was not as expected. Expected: %v, Actual: %v", tc.testName, tc.expectedToken, token)
		}
	}
}

func TestBuildClaimToken(t *testing.T) {
	type test struct {
		testName      string
		testConfig    Config
		testRequest   RequestInfo
		expectedToken string
		expectError   bool
	}

	tests := []test{
		{testName: "Build token with method and uri",
			testConfig:    Config{},
			testRequest:   RequestInfo{Method: "GET", Path: "/test/path"},
			expectedToken: "{\"http.method\":[\"GET\"], \"http.uri\":[\"/test/path\"]}",
		},
		{testName: "Build token with additional claims.",
			testConfig:    Config{KeycloackAdditionalClaims: map[string]string{"http.fiware-service": "fiware-service", "http.fiware-servicepath": "fiware-servicepath"}},
			testRequest:   RequestInfo{Method: "GET", Path: "/test/path", Headers: map[string][]string{"fiware-service": {"test-service"}, "fiware-servicepath": {"/"}}},
			expectedToken: "{\"http.method\":[\"GET\"], \"http.uri\":[\"/test/path\"], \"http.fiware-service\": [\"test-service\"], \"http.fiware-servicepath\": [\"/\"]}",
		},
		{testName: "Fail without method.",
			testConfig:  Config{},
			testRequest: RequestInfo{Path: "/test/path"},
			expectError: true},
		{testName: "Fail without path.",
			testConfig:  Config{},
			testRequest: RequestInfo{Method: "GET"},
			expectError: true},
		{testName: "Fail without expected claimn.",
			testConfig:  Config{KeycloackAdditionalClaims: map[string]string{"http.fiware-service": "fiware-service"}},
			testRequest: RequestInfo{Method: "GET", Path: "/test/path"},
			expectError: true},
	}

	for _, tc := range tests {

		log.Info("TestBuildClaimToken +++++++++++++++++ Running test: ", tc.testName)
		tokenString, err := buildClaimToken(&tc.testConfig, &tc.testRequest)

		if err != nil && tc.expectError {
			log.Debugf("%s: Expected error.", tc.testName)
			continue
		}

		if err != nil && !tc.expectError {
			t.Errorf("%s: Building claim token failed unexpectedly. Err: %v", tc.testName, err)
		}

		if err == nil && tc.expectError {
			t.Errorf("%s: Building claim token should have failed.", tc.testName)
		}
		decodedTokenBytes, err := base64.URLEncoding.DecodeString(tokenString)

		if err != nil {
			t.Errorf("%s: Token decoding failed. Err: %v", tc.testName, err)
		}

		comparisonResult, _ := JSONBytesEqual(decodedTokenBytes, []byte(tc.expectedToken))

		if !comparisonResult {
			t.Errorf("%s: Token was not as expected. Expected: %v, Actual: %v", tc.testName, tc.expectedToken, string(decodedTokenBytes))
		}
	}
}

// JSONBytesEqual compares the JSON in two byte slices.
func JSONBytesEqual(a, b []byte) (bool, error) {
	var j, j2 interface{}
	if err := json.Unmarshal(a, &j); err != nil {
		return false, err
	}
	if err := json.Unmarshal(b, &j2); err != nil {
		return false, err
	}
	return reflect.DeepEqual(j2, j), nil
}

func getResource(id string) *gocloak.ResourceRepresentation {
	return &gocloak.ResourceRepresentation{ID: &id}
}

func getPositiveDescision() gocloak.RequestingPartyPermissionDecision {
	b := true
	return gocloak.RequestingPartyPermissionDecision{Result: &b}
}

func getNegativeDescision() gocloak.RequestingPartyPermissionDecision {
	b := false
	return gocloak.RequestingPartyPermissionDecision{Result: &b}
}
