package connector

import (
	"context"
	"fmt"

	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"

	"github.com/conductorone/baton-sdk/pkg/pagination"
)

func listApplicationGroupAssignmentsV5(
	ctx context.Context,
	client *oktav5.APIClient,
	appID string,
	token *pagination.Token,
	after string,
) ([]oktav5.ApplicationGroupAssignment, *responseContextV5, error) {
	applicationGroupAssignments, resp, err := client.ApplicationGroupsAPI.ListApplicationGroupAssignments(ctx, appID).
		After(after).
		Limit(defaultLimit).
		Execute()

	// Always convert response to context to preserve rate limit information.
	var reqCtx *responseContextV5
	if resp != nil {
		defer resp.Body.Close()
		reqCtx, _ = responseToContextV5(token, resp)
	}

	if err != nil {
		return nil, reqCtx, fmt.Errorf("okta-connectorv2: failed to fetch app group assignments from okta: %w", handleOktaResponseErrorV5(resp, err))
	}

	return applicationGroupAssignments, reqCtx, nil
}

func listApplicationUsersV5(ctx context.Context, client *oktav5.APIClient, appID string, token *pagination.Token, after string) ([]oktav5.AppUser, *responseContextV5, error) {
	applicationUsers, resp, err := client.ApplicationUsersAPI.ListApplicationUsers(ctx, appID).
		After(after).
		Limit(defaultLimit).
		Execute()

	var reqCtx *responseContextV5
	if resp != nil {
		defer resp.Body.Close()
		reqCtx, _ = responseToContextV5(token, resp)
	}

	if err != nil {
		return nil, reqCtx, fmt.Errorf("okta-connectorv2: failed to fetch app users from okta: %w", handleOktaResponseErrorV5(resp, err))
	}

	return applicationUsers, reqCtx, nil
}
