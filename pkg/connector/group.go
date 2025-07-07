package connector

import (
	"context"
	"fmt"
	"regexp"

	"go.uber.org/zap"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

type groupResourceType struct {
	resourceType *v2.ResourceType
	connector    *Okta
}

func (o *groupResourceType) ResourceType(ctx context.Context) *v2.ResourceType {
	return o.resourceType
}

func (o *groupResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	token *pagination.Token,
) ([]*v2.Resource, string, annotations.Annotations, error) {
	var rv []*v2.Resource
	return rv, "", nil, nil
}

func (o *groupResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var rv []*v2.Entitlement
	return rv, "", nil, nil
}

func (o *groupResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	token *pagination.Token,
) ([]*v2.Grant, string, annotations.Annotations, error) {
	var rv []*v2.Grant
	return rv, "", nil, nil
}

func listGroupsHelper(ctx context.Context, client *okta.Client, token *pagination.Token, qp *query.Params) ([]*okta.Group, *responseContext, error) {
	groups, resp, err := client.Group.ListGroups(ctx, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch groups from okta: %w", handleOktaResponseError(resp, err))
	}
	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}
	return groups, reqCtx, nil
}

/*
This filter field uses a regular expression to filter AWS-related groups and extract the accountid and role.

If you use the default AWS role group syntax (aws#[account alias]#[role name]#[account #]), then you can use this Regex string:
^aws\#\S+\#(?{{role}}[\w\-]+)\#(?{{accountid}}\d+)$

This Regex expression logically equates to:
find groups that start with AWS, then #, then a string of text, then #, then the AWS role, then #, then the AWS account ID.

You can also use this Regex expression:
aws_(?{{accountid}}\d+)_(?{{role}}[a-zA-Z0-9+=,.@\-_]+)
If you don't use a default Regex expression, create on that properly filters your AWS role groups.
The expression should capture the AWS role name and account ID within two distinct Regex groups named {{role}} and {{accountid}}.
*/
func parseAccountIDAndRoleFromGroupName(ctx context.Context, roleRegex string, groupName string) (string, string, bool, error) {
	// TODO(lauren) move to get app config
	re, err := regexp.Compile(roleRegex)
	if err != nil {
		return "", "", false, fmt.Errorf("error compiling regex '%s': %w", roleRegex, err)
	}
	match := re.FindStringSubmatch(groupName)
	if len(match) != ExpectedGroupNameCaptureGroupsWithGroupFilterForMultipleAWSInstances {
		return "", "", false, nil
	}
	// First element is full string
	accountId := match[1]
	role := match[2]

	return accountId, role, true, nil
}

func listUsersGroupsClient(ctx context.Context, client *okta.Client, userId string) ([]*okta.Group, *responseContext, error) {
	users, resp, err := client.User.ListUserGroups(ctx, userId)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch group users from okta: %w", handleOktaResponseError(resp, err))
	}

	reqCtx, err := responseToContext(&pagination.Token{}, resp)
	if err != nil {
		return nil, nil, err
	}

	return users, reqCtx, nil
}

func (g *groupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"okta-connector: only users can be granted group membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector: only users can be granted group membership")
	}

	groupId := entitlement.Resource.Id.Resource
	userId := principal.Id.Resource

	response, err := g.connector.client.Group.AddUserToGroup(ctx, groupId, userId)
	if err != nil {
		return nil, handleOktaResponseError(response, err)
	}

	l.Debug("Membership has been created",
		zap.String("Status", response.Status),
	)

	return nil, nil
}

func (g *groupResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	entitlement := grant.Entitlement
	principal := grant.Principal
	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"okta-connector: only users can have group membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-connector:only users can have group membership revoked")
	}

	groupId := entitlement.Resource.Id.Resource
	userId := principal.Id.Resource

	response, err := g.connector.client.Group.RemoveUserFromGroup(ctx, groupId, userId)
	if err != nil {
		return nil, handleOktaResponseError(response, err)
	}

	l.Warn("Membership has been revoked",
		zap.String("Status", response.Status),
	)

	return nil, nil
}

func (o *groupResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	var annos annotations.Annotations
	return nil, annos, nil
}

func groupBuilder(connector *Okta) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		connector:    connector,
	}
}
