package connector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	resource2 "github.com/conductorone/baton-sdk/pkg/types/resource"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const (
	testGroupID = "00g1testgroup"
	testUserID  = "00u1testuser"
)

// newTestGroupResourceType builds a groupResourceType whose Okta v5 client is
// pointed at the given test server.
func newTestGroupResourceType(t *testing.T, srv *httptest.Server) *groupResourceType {
	t.Helper()

	config, err := oktav5.NewConfiguration(
		oktav5.WithOrgUrl(srv.URL),
		oktav5.WithToken("test-token"),
		oktav5.WithTestingDisableHttpsCheck(true),
		oktav5.WithCache(false),
		// Without this, a 429/5xx from the test server would be retried with
		// real backoff and stall the test.
		oktav5.WithRateLimitMaxRetries(0),
	)
	if err != nil {
		t.Fatalf("failed to build okta v5 configuration: %v", err)
	}

	// NewConfiguration derives Host from url.Hostname(), which drops the port, so
	// a test server on an ephemeral port would be unreachable. client.go assigns
	// the request URL's Host from cfg.Host verbatim, so set it with the port.
	srvURL, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("failed to parse test server url: %v", err)
	}
	config.Host = srvURL.Host
	config.Scheme = srvURL.Scheme

	return groupBuilder(&Okta{clientV5: oktav5.NewAPIClient(config)})
}

// groupMembershipServer serves the group membership assign/unassign endpoint
// with a fixed status code, and records the method and path it saw.
func groupMembershipServer(t *testing.T, statusCode int, body string) (*httptest.Server, *[]string) {
	t.Helper()

	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Method+" "+r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(statusCode)
		if body != "" {
			_, _ = w.Write([]byte(body))
		}
	}))
	t.Cleanup(srv.Close)

	return srv, &seen
}

func testGroupEntitlement() *v2.Entitlement {
	return &v2.Entitlement{
		Slug: "member",
		Resource: &v2.Resource{
			Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: testGroupID},
		},
	}
}

func testPrincipal(resourceType string, id string) *v2.Resource {
	return &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceType, Resource: id}}
}

// TestGroupGrantRevokePrincipalTypeGuard asserts that only user principals are
// accepted, and that a rejection is reported as InvalidArgument rather than an
// opaque Unknown error, so the platform can tell a permanent bad request from a
// transient failure.
func TestGroupGrantRevokePrincipalTypeGuard(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		principalType string
		wantErr       bool
	}{
		{name: "user principal is accepted", principalType: resourceTypeUser.Id, wantErr: false},
		{name: "group principal is rejected", principalType: resourceTypeGroup.Id, wantErr: true},
		{name: "account principal is rejected", principalType: resourceTypeAccount.Id, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// 204 No Content is what Okta returns for a successful assign/unassign,
			// so the accepted case reaches the API and succeeds.
			srv, seen := groupMembershipServer(t, http.StatusNoContent, "")
			g := newTestGroupResourceType(t, srv)
			ctx := context.Background()

			for _, op := range []string{"Grant", "Revoke"} {
				var err error
				switch op {
				case "Grant":
					_, err = g.Grant(ctx, testPrincipal(tt.principalType, testUserID), testGroupEntitlement())
				case "Revoke":
					_, err = g.Revoke(ctx, &v2.Grant{
						Entitlement: testGroupEntitlement(),
						Principal:   testPrincipal(tt.principalType, testUserID),
					})
				}

				if tt.wantErr {
					if err == nil {
						t.Fatalf("%s: expected an error for principal type %q, got nil", op, tt.principalType)
					}
					if got := status.Code(err); got != codes.InvalidArgument {
						t.Errorf("%s: expected codes.InvalidArgument, got %v (err: %v)", op, got, err)
					}
				} else if err != nil {
					t.Fatalf("%s: unexpected error for user principal: %v", op, err)
				}
			}

			// A rejected principal must be rejected before any Okta call is made.
			if tt.wantErr && len(*seen) != 0 {
				t.Errorf("expected no Okta requests for rejected principal, got %v", *seen)
			}
		})
	}
}

// TestGroupRevokeIdempotency asserts the revoke idempotency contract from
// CLAUDE.md: a 404 from Okta means the group or user is gone, so the membership
// is already revoked and that is a success carrying GrantAlreadyRevoked, not an
// error.
func TestGroupRevokeIdempotency(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		statusCode         int
		body               string
		wantErrCode        codes.Code
		wantAlreadyRevoked bool
	}{
		{
			name:               "204 is a successful revoke",
			statusCode:         http.StatusNoContent,
			wantErrCode:        codes.OK,
			wantAlreadyRevoked: false,
		},
		{
			name:               "404 is treated as already revoked",
			statusCode:         http.StatusNotFound,
			body:               `{"errorCode":"E0000007","errorSummary":"Not found"}`,
			wantErrCode:        codes.OK,
			wantAlreadyRevoked: true,
		},
		{
			name:        "403 remains a permission error",
			statusCode:  http.StatusForbidden,
			body:        `{"errorCode":"E0000006","errorSummary":"Forbidden"}`,
			wantErrCode: codes.PermissionDenied,
		},
		{
			name:        "500 remains a transient error",
			statusCode:  http.StatusInternalServerError,
			body:        `{"errorCode":"E0000009","errorSummary":"Internal error"}`,
			wantErrCode: codes.Unavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv, _ := groupMembershipServer(t, tt.statusCode, tt.body)
			g := newTestGroupResourceType(t, srv)

			annos, err := g.Revoke(context.Background(), &v2.Grant{
				Entitlement: testGroupEntitlement(),
				Principal:   testPrincipal(resourceTypeUser.Id, testUserID),
			})

			if tt.wantErrCode == codes.OK {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected an error with code %v, got nil", tt.wantErrCode)
				}
				if got := status.Code(err); got != tt.wantErrCode {
					t.Fatalf("expected code %v, got %v (err: %v)", tt.wantErrCode, got, err)
				}
				return
			}

			gotAlreadyRevoked := annos.Contains(&v2.GrantAlreadyRevoked{})
			if gotAlreadyRevoked != tt.wantAlreadyRevoked {
				t.Errorf("GrantAlreadyRevoked annotation: got %v, want %v", gotAlreadyRevoked, tt.wantAlreadyRevoked)
			}
		})
	}
}

// TestGroupGrantErrorMapping asserts Grant surfaces Okta failures with an
// explicit gRPC code. A 409 is deliberately NOT mapped to GrantAlreadyExists:
// AssignUserToGroup is a PUT that returns 204 for an existing member, so a
// conflict signals a genuine problem such as an immutable app-managed group.
func TestGroupGrantErrorMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		statusCode  int
		body        string
		wantErrCode codes.Code
	}{
		{name: "204 succeeds", statusCode: http.StatusNoContent, wantErrCode: codes.OK},
		{
			name:        "404 is a not found error",
			statusCode:  http.StatusNotFound,
			body:        `{"errorCode":"E0000007","errorSummary":"Not found"}`,
			wantErrCode: codes.NotFound,
		},
		{
			name:        "409 is surfaced rather than swallowed as already exists",
			statusCode:  http.StatusConflict,
			body:        `{"errorCode":"E0000079","errorSummary":"Conflict"}`,
			wantErrCode: codes.AlreadyExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv, _ := groupMembershipServer(t, tt.statusCode, tt.body)
			g := newTestGroupResourceType(t, srv)

			annos, err := g.Grant(
				context.Background(),
				testPrincipal(resourceTypeUser.Id, testUserID),
				testGroupEntitlement(),
			)

			if tt.wantErrCode == codes.OK {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				if annos.Contains(&v2.GrantAlreadyExists{}) {
					t.Error("did not expect a GrantAlreadyExists annotation on a 204")
				}
				return
			}

			if err == nil {
				t.Fatalf("expected an error with code %v, got nil", tt.wantErrCode)
			}
			if got := status.Code(err); got != tt.wantErrCode {
				t.Errorf("expected code %v, got %v (err: %v)", tt.wantErrCode, got, err)
			}
		})
	}
}

// TestGroupSyncStubs asserts the sync surface stays a no-op. This connector does
// not sync groups as first class resources; the group resource type is
// registered only so the SDK has a provisioner to dispatch grant/revoke to, and
// resourceTypeGroup carries SkipEntitlementsAndGrants to declare that.
func TestGroupSyncStubs(t *testing.T) {
	t.Parallel()

	g := groupBuilder(&Okta{})
	ctx := context.Background()
	groupResource := testPrincipal(resourceTypeGroup.Id, testGroupID)

	resources, resourcesResults, err := g.List(ctx, nil, resource2.SyncOpAttrs{})
	if err != nil || resources != nil || resourcesResults != nil {
		t.Errorf("List: expected (nil, nil, nil), got (%v, %v, %v)", resources, resourcesResults, err)
	}

	ents, entsResults, err := g.Entitlements(ctx, groupResource, resource2.SyncOpAttrs{})
	if err != nil || ents != nil || entsResults != nil {
		t.Errorf("Entitlements: expected (nil, nil, nil), got (%v, %v, %v)", ents, entsResults, err)
	}

	grants, grantsResults, err := g.Grants(ctx, groupResource, resource2.SyncOpAttrs{})
	if err != nil || grants != nil || grantsResults != nil {
		t.Errorf("Grants: expected (nil, nil, nil), got (%v, %v, %v)", grants, grantsResults, err)
	}

	if got := g.ResourceType(ctx); got != resourceTypeGroup {
		t.Errorf("ResourceType: expected resourceTypeGroup, got %v", got)
	}

	groupRTAnnos := annotations.Annotations(resourceTypeGroup.Annotations)
	if !groupRTAnnos.Contains(&v2.SkipEntitlementsAndGrants{}) {
		t.Error("resourceTypeGroup should carry SkipEntitlementsAndGrants: its sync methods are stubs")
	}
}
