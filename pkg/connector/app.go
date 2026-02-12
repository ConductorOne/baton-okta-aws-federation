package connector

import (
	"context"
	"fmt"

	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"

	"github.com/conductorone/baton-sdk/pkg/pagination"

	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
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
	if err != nil {
		l := ctxzap.Extract(ctx)
		l.Debug("Got error from listApplicationGroupAssignmentsV5", zap.Error(err))

		fullError := handleOktaResponseErrorWithRateLimitingV5(resp, err)

		l.Debug("returning rate limit error", zap.Error(fullError))
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to fetch app group assignments from okta: %w", fullError)
	}

	reqCtx, err := responseToContextV5(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return applicationGroupAssignments, reqCtx, nil
}

func listApplicationUsersV5(ctx context.Context, client *oktav5.APIClient, appID string, token *pagination.Token, after string) ([]oktav5.AppUser, *responseContextV5, error) {
	applicationUsers, resp, err := client.ApplicationUsersAPI.ListApplicationUsers(ctx, appID).
		After(after).
		Limit(defaultLimit).
		Execute()
	if err != nil {
		l := ctxzap.Extract(ctx)
		l.Debug("Got error from listApplicationUsersV5", zap.Error(err))

		fullError := handleOktaResponseErrorWithRateLimitingV5(resp, err)

		l.Debug("returning rate limit error", zap.Error(fullError))
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to fetch app users from okta: %w", fullError)
	}

	reqCtx, err := responseToContextV5(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return applicationUsers, reqCtx, nil
}
