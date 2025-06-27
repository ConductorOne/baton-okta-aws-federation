package connector

import (
	"context"
	"net/http"
	"net/url"

	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

// listGroupAssignedRoles. List all group role assignments
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentBGroup/#tag/RoleAssignmentBGroup/operation/listGroupAssignedRoles
func listGroupAssignedRoles(ctx context.Context, client *okta.Client, groupId string, qp *query.Params) ([]*Roles, *okta.Response, error) {
	apiPath, err := url.JoinPath(groupsUrl, groupId, "roles")
	if err != nil {
		return nil, nil, err
	}

	reqUrl, err := url.Parse(apiPath)
	if err != nil {
		return nil, nil, err
	}

	var role []*Roles
	resp, err := doRequest(ctx, reqUrl.String(), http.MethodGet, &role, client)
	if err != nil {
		return nil, resp, err
	}

	return role, resp, nil
}

// listAssignedRolesForUser. List all user role assignments.
// https://developer.okta.com/docs/api/openapi/okta-management/management/tag/RoleAssignmentAUser/#tag/RoleAssignmentAUser/operation/listAssignedRolesForUser
func listAssignedRolesForUser(ctx context.Context, client *okta.Client, userId string) ([]*Roles, *okta.Response, error) {
	apiPath, err := url.JoinPath(usersUrl, userId, "roles")
	if err != nil {
		return nil, nil, err
	}

	reqUrl, err := url.Parse(apiPath)
	if err != nil {
		return nil, nil, err
	}

	var role []*Roles
	resp, err := doRequest(ctx, reqUrl.String(), http.MethodGet, &role, client)
	if err != nil {
		return nil, nil, err
	}

	return role, resp, nil
}
