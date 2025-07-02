package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"github.com/okta/okta-sdk-golang/v2/okta/query"
)

const membershipUpdatedField = "lastMembershipUpdated"
const usersCountProfileKey = "users_count"

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

func (o *groupResourceType) etagMd(group *okta.Group) (*v2.ETagMetadata, error) {
	if group.LastMembershipUpdated != nil {
		data, err := structpb.NewStruct(map[string]interface{}{
			membershipUpdatedField: group.LastMembershipUpdated.Format(time.RFC3339Nano),
		})
		if err != nil {
			return nil, err
		}
		return &v2.ETagMetadata{
			Metadata: data,
		}, nil
	}

	return nil, nil
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

func (o *groupResourceType) listAWSGroups(ctx context.Context, token *pagination.Token, page string) ([]*okta.Group, *responseContext, error) {
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, nil, err
	}
	groups := make([]*okta.Group, 0)
	if awsConfig.UseGroupMapping {
		qp := queryParams(token.Size, page)
		groups, respCtx, err := listGroupsHelper(ctx, o.connector.client, token, qp)
		if err != nil {
			return nil, nil, err
		}
		for _, group := range groups {
			_, _, matchesRolePattern, err := parseAccountIDAndRoleFromGroupName(ctx, awsConfig.RoleRegex, group.Profile.Name)
			if err != nil {
				return nil, nil, fmt.Errorf("okta-aws-connector: failed to parse account id and role from group name: %w", err)
			}
			if matchesRolePattern {
				groups = append(groups, group)
			}
		}
		return groups, respCtx, nil
	}

	qp := queryParamsExpand(token.Size, page, "group")
	appGroups, respCtx, err := listApplicationGroupAssignments(ctx, o.connector.client, o.connector.awsConfig.OktaAppId, token, qp)
	if err != nil {
		return nil, nil, err
	}

	for _, appGroup := range appGroups {
		appGroupSAMLRoles, err := appGroupSAMLRolesWrapper(ctx, appGroup)
		if err != nil {
			return nil, nil, err
		}
		oktaGroup, err := embeddedOktaGroupFromAppGroup(appGroup)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-aws-connector: failed to fetch groups from okta: %w", err)
		}
		groups = append(groups, oktaGroup)
		awsConfig.appGroupCache.Store(appGroup.Id, appGroupSAMLRoles)
	}
	return groups, respCtx, nil
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

func (o *groupResourceType) listGroupUsers(ctx context.Context, groupID string, token *pagination.Token, qp *query.Params) ([]*okta.User, *responseContext, error) {
	users, resp, err := o.connector.client.Group.ListGroupUsers(ctx, groupID, qp)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-connectorv2: failed to fetch group users from okta: %w", handleOktaResponseError(resp, err))
	}

	reqCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return users, reqCtx, nil
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

func (o *groupResourceType) groupResource(ctx context.Context, group *okta.Group) (*v2.Resource, error) {
	trait, err := o.groupTrait(ctx, group)
	if err != nil {
		return nil, err
	}

	var annos annotations.Annotations
	annos.Update(trait)
	annos.Update(&v2.V1Identifier{
		Id: fmtResourceIdV1(group.Id),
	})
	annos.Update(&v2.RawId{Id: group.Id})

	etagMd, err := o.etagMd(group)
	if err != nil {
		return nil, err
	}
	annos.Update(etagMd)

	return &v2.Resource{
		Id:          fmtResourceId(resourceTypeGroup.Id, group.Id),
		DisplayName: group.Profile.Name,
		Annotations: annos,
	}, nil
}

func (o *groupResourceType) groupTrait(ctx context.Context, group *okta.Group) (*v2.GroupTrait, error) {
	profileMap := map[string]interface{}{
		"description": group.Profile.Description,
		"name":        group.Profile.Name,
	}

	if userCount, exists := getGroupUserCount(group); exists {
		profileMap[usersCountProfileKey] = int64(userCount)
	}

	profile, err := structpb.NewStruct(profileMap)
	if err != nil {
		return nil, fmt.Errorf("okta-connectorv2: failed to construct group profile for group trait: %w", err)
	}

	ret := &v2.GroupTrait{
		Profile: profile,
	}

	return ret, nil
}

func getGroupUserCount(group *okta.Group) (float64, bool) {
	embedded := group.Embedded
	if embedded == nil {
		return 0, false
	}
	embeddedMap, ok := embedded.(map[string]interface{})
	if !ok {
		return 0, false
	}
	embeddedStats, ok := embeddedMap["stats"]
	if !ok {
		return 0, false
	}
	embeddedStatsMap, ok := embeddedStats.(map[string]interface{})
	if !ok {
		return 0, false
	}
	embeddedStatsUsersCount, ok := embeddedStatsMap["usersCount"]
	if !ok {
		return 0, false
	}
	userCount := embeddedStatsUsersCount.(float64)
	return userCount, true
}

func (o *groupResourceType) groupEntitlement(ctx context.Context, resource *v2.Resource) *v2.Entitlement {
	return sdkEntitlement.NewAssignmentEntitlement(resource, "member",
		sdkEntitlement.WithAnnotation(&v2.V1Identifier{
			Id: V1MembershipEntitlementID(resource.Id.GetResource()),
		}),
		sdkEntitlement.WithGrantableTo(resourceTypeUser),
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Group Member", resource.DisplayName)),
		sdkEntitlement.WithDescription(fmt.Sprintf("Member of %s group in Okta", resource.DisplayName)),
	)
}

func groupGrant(resource *v2.Resource, user *okta.User) *v2.Grant {
	ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: user.Id}}

	return sdkGrant.NewGrant(resource, "member", ur, sdkGrant.WithAnnotation(&v2.V1Identifier{
		Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), user.Id),
	}))
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

func embeddedOktaGroupFromAppGroup(appGroup *okta.ApplicationGroupAssignment) (*okta.Group, error) {
	embedded := appGroup.Embedded
	if embedded == nil {
		return nil, fmt.Errorf("app group '%s' embedded data was nil", appGroup.Id)
	}
	embeddedMap, ok := embedded.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("app group embedded data was not a map for group with id '%s'", appGroup.Id)
	}
	embeddedGroup, ok := embeddedMap["group"]
	if !ok {
		return nil, fmt.Errorf("embedded group data was nil for app group '%s'", appGroup.Id)
	}
	groupJSON, err := json.Marshal(embeddedGroup)
	if err != nil {
		return nil, fmt.Errorf("error marshalling embedded group data for app group '%s': %w", appGroup.Id, err)
	}
	oktaGroup := &okta.Group{}
	err = json.Unmarshal(groupJSON, &oktaGroup)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling embedded group data for app group '%s': %w", appGroup.Id, err)
	}
	return oktaGroup, nil
}

func (o *groupResourceType) Get(ctx context.Context, resourceId *v2.ResourceId, parentResourceId *v2.ResourceId) (*v2.Resource, annotations.Annotations, error) {
	var annos annotations.Annotations
	return nil, annos, nil
}

func (o *groupResourceType) getAWSGroup(ctx context.Context, groupId string) (*okta.Group, *okta.Response, error) {
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx)
	if err != nil {
		return nil, nil, err
	}
	if awsConfig.UseGroupMapping {
		group, resp, err := o.connector.client.Group.GetGroup(ctx, groupId)
		if err != nil {
			return nil, nil, handleOktaResponseError(resp, err)
		}

		_, _, matchesRolePattern, err := parseAccountIDAndRoleFromGroupName(ctx, awsConfig.RoleRegex, group.Profile.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-aws-connector: failed to parse account id and role from group name: %w", err)
		}

		if matchesRolePattern {
			return group, resp, nil
		}

		return nil, nil, nil
	}

	qp := query.NewQueryParams(query.WithExpand("group"))
	appGroup, resp, err := o.connector.client.Application.GetApplicationGroupAssignment(ctx, o.connector.awsConfig.OktaAppId, groupId, qp)
	if err != nil {
		return nil, nil, handleOktaResponseError(resp, err)
	}
	appGroupSAMLRoles, err := appGroupSAMLRolesWrapper(ctx, appGroup)
	if err != nil {
		return nil, nil, err
	}
	oktaGroup, err := embeddedOktaGroupFromAppGroup(appGroup)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to fetch groups from okta: %w", err)
	}
	awsConfig.appGroupCache.Store(appGroup.Id, appGroupSAMLRoles)
	return oktaGroup, resp, nil
}

func groupBuilder(connector *Okta) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		connector:    connector,
	}
}
