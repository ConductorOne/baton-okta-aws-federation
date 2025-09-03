package connector

import (
	"context"
	"fmt"

	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"

	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

func listApplicationGroupAssignments(ctx context.Context, client *okta.Client, appID string, token *pagination.Token, qp *query.Params) ([]*okta.ApplicationGroupAssignment, *responseContext, error) {
	applicationGroupAssignments, resp, err := client.Application.ListApplicationGroupAssignments(ctx, appID, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch app group assignments from okta: %w", handleOktaResponseError(resp, err))
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return applicationGroupAssignments, reqCtx, nil
}

func listApplicationGroupAssignmentsV5(ctx context.Context, client *oktav5.APIClient, appID string, token *pagination.Token, after string) ([]oktav5.ApplicationGroupAssignment, *responseContextV5, error) {
	applicationGroupAssignments, resp, err := client.ApplicationGroupsAPI.ListApplicationGroupAssignments(ctx, appID).
		After(after).
		Limit(defaultLimit).
		Execute()
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch app group assignments from okta: %w", handleOktaResponseErrorV5(resp, err))
	}

	reqCtx, err := responseToContextV5(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return applicationGroupAssignments, reqCtx, nil
}

func listApplicationUsers(ctx context.Context, client *okta.Client, appID string, token *pagination.Token, qp *query.Params) ([]*okta.AppUser, *responseContext, error) {
	applicationUsers, resp, err := client.Application.ListApplicationUsers(ctx, appID, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch app users from okta: %w", handleOktaResponseError(resp, err))
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return applicationUsers, reqCtx, nil
}

func listApplicationUsersV5(ctx context.Context, client *oktav5.APIClient, appID string, token *pagination.Token, after string) ([]oktav5.AppUser, *responseContextV5, error) {
	applicationUsers, resp, err := client.ApplicationUsersAPI.ListApplicationUsers(ctx, appID).
		After(after).
		Limit(defaultLimit).
		Execute()
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch app users from okta: %w", handleOktaResponseErrorV5(resp, err))
	}

	reqCtx, err := responseToContextV5(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return applicationUsers, reqCtx, nil
}
