package connector

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strconv"
	"testing"
	"time"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testAppID   = "0oaTESTAPP"
	testUserID  = "00uTESTUSER"
	testGroupID = "00gTESTGROUP"
)

const testAWSApp = `{
	"id": "` + testAppID + `",
	"name": "amazon_aws",
	"signOnMode": "SAML_2_0",
	"settings": {
		"app": {
			"useGroupMapping": false,
			"groupFilter": "aws_(?{{accountid}}\\d+)_(?{{role}}[a-zA-Z0-9+=,.@\\-_]+)",
			"joinAllRoles": false,
			"identityProviderArn": "arn:aws:iam::123456789012:saml-provider/okta"
		}
	}
}`

const testAppUserSchema = `{"definitions": {"base": {"properties": {}}}}`

type fakeRoute func(req *http.Request) *http.Response

// fakeOkta answers SDK requests by "METHOD path", failing the test on any unexpected call.
type fakeOkta struct {
	t      *testing.T
	routes map[string]fakeRoute
}

func (f *fakeOkta) RoundTrip(req *http.Request) (*http.Response, error) {
	route, ok := f.routes[req.Method+" "+req.URL.Path]
	if !ok {
		f.t.Fatalf("unexpected Okta request: %s %s", req.Method, req.URL.Path)
	}
	resp := route(req)
	resp.Request = req
	return resp, nil
}

func oktaResponse(statusCode int, remaining int, body string) *http.Response {
	now := time.Now()
	header := http.Header{}
	header.Set("Content-Type", "application/json")
	header.Set("Date", now.UTC().Format(http.TimeFormat))
	header.Set("X-Rate-Limit-Limit", "20")
	header.Set("X-Rate-Limit-Remaining", strconv.Itoa(remaining))
	header.Set("X-Rate-Limit-Reset", strconv.FormatInt(now.Add(30*time.Second).Unix(), 10))
	return &http.Response{
		Status:     strconv.Itoa(statusCode) + " " + http.StatusText(statusCode),
		StatusCode: statusCode,
		Header:     header,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
	}
}

func ok(body string) fakeRoute {
	return func(*http.Request) *http.Response { return oktaResponse(http.StatusOK, 12, body) }
}

func tooManyRequests() fakeRoute {
	return func(*http.Request) *http.Response {
		return oktaResponse(http.StatusTooManyRequests, 0, `{"errorCode":"E0000047","errorSummary":"API call exceeded rate limit due to too many requests."}`)
	}
}

func newTestAccountBuilder(t *testing.T, routes map[string]fakeRoute) *accountResourceType {
	t.Helper()
	cfg, err := oktav5.NewConfiguration(
		oktav5.WithOrgUrl("https://example.okta.com"),
		oktav5.WithToken("test-token"),
		oktav5.WithHttpClientPtr(&http.Client{Transport: &fakeOkta{t: t, routes: routes}}),
		oktav5.WithCache(false),
		// Fail on the first 429 instead of sleeping until the reset.
		oktav5.WithRateLimitMaxRetries(0),
	)
	require.NoError(t, err)
	return accountBuilder(&Okta{
		clientV5:  oktav5.NewAPIClient(cfg),
		awsConfig: &awsConfig{OktaAppId: testAppID},
	})
}

// appRoutes are the lookups every Grant and Revoke makes before touching the principal.
func appRoutes(extra map[string]fakeRoute) map[string]fakeRoute {
	routes := map[string]fakeRoute{
		"GET /api/v1/apps/" + testAppID:                           ok(testAWSApp),
		"GET /api/v1/meta/schemas/apps/" + testAppID + "/default": ok(testAppUserSchema),
	}
	for k, v := range extra {
		routes[k] = v
	}
	return routes
}

func appUserJSON(roles string) string {
	return `{"id": "` + testUserID + `", "scope": "USER", "profile": {"samlRoles": [` + roles + `]}}`
}

func testEntitlement(role string) *v2.Entitlement {
	return v2.Entitlement_builder{
		Id: "account:123456789012:" + role,
		Resource: v2.Resource_builder{
			Id: v2.ResourceId_builder{ResourceType: resourceTypeAccount.Id, Resource: "123456789012"}.Build(),
		}.Build(),
	}.Build()
}

func testPrincipal(resourceType, id string) *v2.Resource {
	return v2.Resource_builder{
		Id: v2.ResourceId_builder{ResourceType: resourceType, Resource: id}.Build(),
	}.Build()
}

func testGrant(principal *v2.Resource, role string) *v2.Grant {
	return v2.Grant_builder{
		Entitlement: testEntitlement(role),
		Principal:   principal,
	}.Build()
}

// requireRateLimitError asserts err is retryable by baton-sdk and carries Okta's reset time.
func requireRateLimitError(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "expected a gRPC status in %v", err)
	require.Equal(t, codes.Unavailable, st.Code())

	var desc *v2.RateLimitDescription
	for _, d := range st.Details() {
		if rl, ok := d.(*v2.RateLimitDescription); ok {
			desc = rl
		}
	}
	require.NotNil(t, desc, "expected rate-limit details on %v", err)
	require.Equal(t, v2.RateLimitDescription_STATUS_OVERLIMIT, desc.GetStatus())
	require.True(t, desc.GetResetAt().AsTime().After(time.Now()))
}

func requireRateLimitAnnotation(t *testing.T, annos annotations.Annotations) {
	t.Helper()
	desc := &v2.RateLimitDescription{}
	found, err := annos.Pick(desc)
	require.NoError(t, err)
	require.True(t, found, "expected a rate-limit annotation")
	require.Equal(t, int64(20), desc.GetLimit())
	require.Equal(t, int64(12), desc.GetRemaining())
}

func TestGrantUserRateLimited(t *testing.T) {
	appUserPath := "/api/v1/apps/" + testAppID + "/users/" + testUserID
	tests := map[string]map[string]fakeRoute{
		"app lookup": {
			"GET /api/v1/apps/" + testAppID: tooManyRequests(),
		},
		"app user lookup": appRoutes(map[string]fakeRoute{
			"GET " + appUserPath: tooManyRequests(),
		}),
		"app user update": appRoutes(map[string]fakeRoute{
			"GET " + appUserPath:  ok(appUserJSON(`"existing"`)),
			"POST " + appUserPath: tooManyRequests(),
		}),
	}
	for name, routes := range tests {
		t.Run(name, func(t *testing.T) {
			o := newTestAccountBuilder(t, routes)
			_, err := o.Grant(context.Background(), testPrincipal(resourceTypeUser.Id, testUserID), testEntitlement("admin"))
			requireRateLimitError(t, err)
		})
	}
}

func TestGrantUserReportsRateLimit(t *testing.T) {
	appUserPath := "/api/v1/apps/" + testAppID + "/users/" + testUserID
	o := newTestAccountBuilder(t, appRoutes(map[string]fakeRoute{
		"GET " + appUserPath:  ok(appUserJSON(`"existing"`)),
		"POST " + appUserPath: ok(appUserJSON(`"existing", "admin"`)),
	}))

	annos, err := o.Grant(context.Background(), testPrincipal(resourceTypeUser.Id, testUserID), testEntitlement("admin"))
	require.NoError(t, err)
	requireRateLimitAnnotation(t, annos)
}

func TestGrantUserAlreadyExistsReportsRateLimit(t *testing.T) {
	o := newTestAccountBuilder(t, appRoutes(map[string]fakeRoute{
		"GET /api/v1/apps/" + testAppID + "/users/" + testUserID: ok(appUserJSON(`"admin"`)),
	}))

	annos, err := o.Grant(context.Background(), testPrincipal(resourceTypeUser.Id, testUserID), testEntitlement("admin"))
	require.NoError(t, err)
	require.True(t, annos.Contains(&v2.GrantAlreadyExists{}))
	requireRateLimitAnnotation(t, annos)
}

func TestRevokeUserRateLimited(t *testing.T) {
	appUserPath := "/api/v1/apps/" + testAppID + "/users/" + testUserID
	o := newTestAccountBuilder(t, appRoutes(map[string]fakeRoute{
		"GET " + appUserPath:  ok(appUserJSON(`"admin"`)),
		"POST " + appUserPath: tooManyRequests(),
	}))

	_, err := o.Revoke(context.Background(), testGrant(testPrincipal(resourceTypeUser.Id, testUserID), "admin"))
	requireRateLimitError(t, err)
}

func TestRevokeUserReportsRateLimit(t *testing.T) {
	appUserPath := "/api/v1/apps/" + testAppID + "/users/" + testUserID
	o := newTestAccountBuilder(t, appRoutes(map[string]fakeRoute{
		"GET " + appUserPath:  ok(appUserJSON(`"admin"`)),
		"POST " + appUserPath: ok(appUserJSON(``)),
	}))

	annos, err := o.Revoke(context.Background(), testGrant(testPrincipal(resourceTypeUser.Id, testUserID), "admin"))
	require.NoError(t, err)
	requireRateLimitAnnotation(t, annos)
}

func TestGrantGroupRateLimited(t *testing.T) {
	appGroupPath := "/api/v1/apps/" + testAppID + "/groups/" + testGroupID
	o := newTestAccountBuilder(t, appRoutes(map[string]fakeRoute{
		"GET " + appGroupPath:   ok(`{"id": "` + testGroupID + `", "profile": {"samlRoles": ["existing"]}}`),
		"PATCH " + appGroupPath: tooManyRequests(),
	}))

	_, err := o.Grant(context.Background(), testPrincipal(resourceTypeGroup.Id, testGroupID), testEntitlement("admin"))
	requireRateLimitError(t, err)
}

func TestGrantGroupReportsRateLimit(t *testing.T) {
	appGroupPath := "/api/v1/apps/" + testAppID + "/groups/" + testGroupID
	o := newTestAccountBuilder(t, appRoutes(map[string]fakeRoute{
		"GET " + appGroupPath:   ok(`{"id": "` + testGroupID + `", "profile": {"samlRoles": ["existing"]}}`),
		"PATCH " + appGroupPath: ok(`{"id": "` + testGroupID + `", "profile": {"samlRoles": ["existing", "admin"]}}`),
	}))

	annos, err := o.Grant(context.Background(), testPrincipal(resourceTypeGroup.Id, testGroupID), testEntitlement("admin"))
	require.NoError(t, err)
	requireRateLimitAnnotation(t, annos)
}

func TestNonRateLimitErrorsUnchanged(t *testing.T) {
	appUserPath := "/api/v1/apps/" + testAppID + "/users/" + testUserID
	o := newTestAccountBuilder(t, appRoutes(map[string]fakeRoute{
		"GET " + appUserPath: ok(appUserJSON(`"existing"`)),
		"POST " + appUserPath: func(*http.Request) *http.Response {
			return oktaResponse(http.StatusForbidden, 12, `{"errorCode":"E0000006","errorSummary":"You do not have permission to perform the requested action"}`)
		},
	}))

	_, err := o.Grant(context.Background(), testPrincipal(resourceTypeUser.Id, testUserID), testEntitlement("admin"))
	require.Error(t, err)
	require.NotEqual(t, codes.Unavailable, status.Code(err))
	require.Contains(t, err.Error(), "failed to update application user")
}
