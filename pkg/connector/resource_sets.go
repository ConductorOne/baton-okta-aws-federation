package connector

import (
	"context"

	"github.com/okta/okta-sdk-golang/v2/okta"
)

const (
	apiPathListIamResourceSets = "/api/v1/iam/resource-sets"
	roleTypeCustom             = "CUSTOM"
	roleStatusInactive         = "INACTIVE"
	usersUrl                   = "/api/v1/users"
	groupsUrl                  = "/api/v1/groups"
	defaultProtocol            = "https:"
	bindingEntitlement         = "bindings"
)

func doRequest(ctx context.Context, url, httpMethod string, res interface{}, client *okta.Client) (*okta.Response, error) {
	rq := client.CloneRequestExecutor()
	req, err := rq.WithAccept(ContentType).
		WithContentType(ContentType).
		NewRequest(httpMethod, url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := rq.Do(ctx, req, &res)
	if err != nil {
		return resp, err
	}

	return resp, nil
}
