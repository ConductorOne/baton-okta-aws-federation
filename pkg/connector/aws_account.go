package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/bid"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkEntitlement "github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	resource2 "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type OktaAppGroupWrapper struct {
	samlRoles []string
}

type AWSRoles struct {
	AWSEnvironmentEnum []string `json:"AWSEnvironmentEnum,omitempty"`
	SamlIamRole        []string `json:"SamlIamRole,omitempty"`
	IamRole            []string `json:"IamRole,omitempty"`
}

type accountResourceType struct {
	resourceType *v2.ResourceType
	connector    *Okta
}

const (
	appUserScope  = "USER"
	appGroupScope = "GROUP"

	apiPathApplicationGroup = "/api/v1/apps/%s/groups/%s"
	apiPathSamlRoles = "/api/v1/internal/apps/%s/types"
)

func (o *accountResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return o.resourceType
}

func accountBuilder(connector *Okta) *accountResourceType {
	return &accountResourceType{
		resourceType: resourceTypeAccount,
		connector:    connector,
	}
}

func (o *accountResourceType) List(
	ctx context.Context,
	resourceID *v2.ResourceId,
	attrs resource2.SyncOpAttrs,
) ([]*v2.Resource, *resource2.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)
	token := &attrs.PageToken
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx, attrs.Session)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting aws app settings config")
	}
	if !awsConfig.UseGroupMapping {
		accountId := awsConfig.IdentityProviderArnAccountID
		// TODO(lauren) what should name be?
		resource, err := resource2.NewResource(accountId, o.resourceType, accountId)
		if err != nil {
			return nil, nil, err
		}
		return []*v2.Resource{resource}, nil, nil
	}

	bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeAccount.Id})
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to parse page token: %w", err)
	}

	accountSet := mapset.NewSet[string]()

	appGroups, respCtx, err := listGroupsHelperV5(ctx, o.connector.clientV5, token, page)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to list application groups: %w", err)
	}

	var rv []*v2.Resource

	nextPage, annos, err := parseRespV5(respCtx.OktaResponse)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to parse response: %w", err)
	}
	err = bag.Next(nextPage)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to fetch bag.Next: %w", err)
	}

	for _, group := range appGroups {
		if group.Profile.Name == nil {
			l.Warn("okta-aws-connector: group profile name was nil", zap.Any("groupId", group.Id))
			continue
		}

		accountId, _, matchesRolePattern, err := parseAccountIDAndRoleFromGroupName(ctx, awsConfig.RoleRegex, *group.Profile.Name)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-aws-connector: failed to parse account id and role from group name: %w", err)
		}
		if !matchesRolePattern {
			continue
		}
		accountSet.Add(accountId)
	}

	for accountId := range accountSet.Iterator().C {
		resource, err := resource2.NewResource(accountId, o.resourceType, accountId)
		if err != nil {
			return nil, nil, err
		}

		rv = append(rv, resource)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, nil, err
	}

	return rv, &resource2.SyncOpResults{
			NextPageToken: pageToken,
			Annotations:   annos,
	}, nil
}

func (o *accountResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	attrs resource2.SyncOpAttrs,
) ([]*v2.Entitlement, *resource2.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)
	token := &attrs.PageToken
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx, attrs.Session)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting aws app settings config")
	}
	var rv []*v2.Entitlement
	if !awsConfig.UseGroupMapping {
		awsRoles, respCtx, err := o.listAWSSamlRoles(ctx)
		if err != nil {
			return nil, nil, err
		}
		for _, role := range awsRoles.SamlIamRole {
			rv = append(rv, samlRoleEntitlement(resource, role))
		}
		annos, err := parseGetRespV5(respCtx.OktaResponse)
		if err != nil {
			return nil, nil, err
		}
		return rv, &resource2.SyncOpResults{
			Annotations: annos,
		}, nil
	} else {
		bag, page, err := parsePageToken(token.Token, &v2.ResourceId{ResourceType: resourceTypeAccount.Id})
		if err != nil {
			return nil, nil, fmt.Errorf("okta-aws-connector: failed to parse page token: %w", err)
		}

		groups, respCtx, err := listGroupsHelperV5(ctx, o.connector.clientV5, token, page)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-aws-connector: failed to list application groups: %w", err)
		}

		nextPage, annos, err := parseRespV5(respCtx.OktaResponse)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-aws-connector: failed to parse response: %w", err)
		}
		err = bag.Next(nextPage)
		if err != nil {
			return nil, nil, fmt.Errorf("okta-aws-connector: failed to fetch bag.Next: %w", err)
		}

		for _, group := range groups {
			if group.Profile.Name == nil {
				l.Warn("okta-aws-connector: group profile name was nil", zap.Any("groupId", group.Id))
				continue
			}

			accountId, roleName, matchesRolePattern, err := parseAccountIDAndRoleFromGroupName(ctx, awsConfig.RoleRegex, *group.Profile.Name)
			if err != nil {
				return nil, nil, fmt.Errorf("okta-aws-connector: failed to parse account id and role from group name: %w", err)
			}
			if !matchesRolePattern || accountId != resource.GetId().Resource {
				continue
			}
			rv = append(rv, samlRoleEntitlement(resource, roleName))
		}

		pageToken, err := bag.Marshal()
		if err != nil {
			return nil, nil, err
		}

		return rv, &resource2.SyncOpResults{
			NextPageToken: pageToken,
			Annotations:   annos,
		}, nil
	}
}

func samlRoleEntitlement(resource *v2.Resource, role string) *v2.Entitlement {
	return sdkEntitlement.NewAssignmentEntitlement(resource, role,
		sdkEntitlement.WithDisplayName(fmt.Sprintf("%s Role Member", role)),
		sdkEntitlement.WithDescription(fmt.Sprintf("Has the %s role in AWS Okta app", role)),
		sdkEntitlement.WithGrantableTo(resourceTypeUser, resourceTypeGroup),
	)
}

func parseSAMLRoleFromEntitlementID(entitlementID string) (string, error) {
	parts := strings.Split(entitlementID, ":")
	if len(parts) != 3 {
		return "", fmt.Errorf("okta-aws-connector: invalid entitlement ID format: %s, expected format: resource-type:resource-id:samlRole", entitlementID)
	}
	resourceType := parts[0]
	resourceID := parts[1]
	samlRole := parts[2]
	if resourceType == "" || resourceID == "" || samlRole == "" {
		return "", fmt.Errorf("okta-aws-connector: entitlement ID contains empty components: %s", entitlementID)
	}
	return samlRole, nil
}

// Add group principal grant if assigned with a saml role
// Use expand grant if join all roles/use group mapping enabled to get user grants
// Otherwise:
// list application users, if direct assignment, give those role, if group scope, look at all the users groups
// if join all roles also do the above JUST for direct assignments.
func (o *accountResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	attrs resource2.SyncOpAttrs,
) ([]*v2.Grant, *resource2.SyncOpResults, error) {
	token := &attrs.PageToken
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx, attrs.Session)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting aws app settings config")
	}
	bag := &pagination.Bag{}
	err = bag.Unmarshal(token.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to parse page token: %w", err)
	}
	if bag.Current() == nil {
		if !awsConfig.UseGroupMapping {
			bag.Push(pagination.PageState{
				ResourceTypeID: resourceTypeUser.Id,
			})
		}
		bag.Push(pagination.PageState{
			ResourceTypeID: resourceTypeGroup.Id,
		})
	}
	page := bag.PageToken()

	var rv []*v2.Grant
	var nextPage string
	var annos annotations.Annotations

	switch bag.ResourceTypeID() {
	case resourceTypeUser.Id:
		rv, nextPage, annos, err = o.userGrants(ctx, resource, attrs, page)
	case resourceTypeGroup.Id:
		rv, nextPage, annos, err = o.groupGrants(ctx, resource, attrs, page)
	default:
		rv, nextPage, annos, err = o.groupGrants(ctx, resource, attrs, page)
	}
	if err != nil {
		return nil, nil, err
	}

	err = bag.Next(nextPage)
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to fetch bag.Next: %w", err)
	}

	pageToken, err := bag.Marshal()
	if err != nil {
		return nil, nil, err
	}
	return rv, &resource2.SyncOpResults{
		NextPageToken: pageToken,
		Annotations:   annos,
	}, nil
}

func (o *accountResourceType) userGrants(ctx context.Context, resource *v2.Resource, attrs resource2.SyncOpAttrs, page string) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	token := &attrs.PageToken

	awsConfig, err := o.connector.getAWSApplicationConfig(ctx, attrs.Session)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: error getting aws app settings config")
	}

	// Parse the provided page token to evaluate the page to start obtaining users from
	// and the specific user (if any) to start collecting roles for.
	oktaAfter, startUserIndex, err := parseUserGrantsPageToken(page)
	if err != nil {
		return nil, "", nil, err
	}
	var rv []*v2.Grant

	appUsers, respContext, err := listApplicationUsersV5(ctx, o.connector.clientV5, o.connector.awsConfig.OktaAppId, token, oktaAfter)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: error listing application users %w", err)
	}

	// For our caller, extract the first part of our next page token and any annotations.
	nextOktaPage, annos, err := parseRespV5(respContext.OktaResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse response: %w", err)
	}

	// Process users starting from the second part of our page token.
	for i := startUserIndex; i < len(appUsers); i++ {
		appUser := appUsers[i]
		if appUser.Id == nil {
			l.Warn("okta-aws-connector: app user id was nil")
			continue
		} else if appUser.Scope == nil {
			l.Warn("okta-aws-connector: app user scope was nil", zap.Any("userId", appUser.Id))
			continue
		}

		appUserSAMLRolesMap := mapset.NewSet[string]()

		// For users with direct assignments or with Union enabled, we extract samlRoles from their profile
		if *appUser.Scope == appUserScope || (*appUser.Scope == appGroupScope && awsConfig.SamlRolesUnionEnabled) {
			appUserSAMLRoles, err := getSAMLRolesFromAppUserProfileV5(ctx, appUser)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to get saml roles for user '%v': %w", appUser.Id, err)
			}
			appUserSAMLRolesMap.Append(appUserSAMLRoles...)
		}

		// For group-scoped users (no direct assignment) and when Union/JoinAllRoles is disabled,
		// samlRoles are gathered by inspecting the user's group memberships
		if *appUser.Scope == appGroupScope && !awsConfig.JoinAllRoles && !awsConfig.SamlRolesUnionEnabled {
			appUserSAMLRolesMap, err = o.collectRolesFromUserGroups(ctx, attrs.Session, *appUser.Id)
			if err != nil {
				// Check if this is a rate limit error.
				if st, ok := status.FromError(err); ok && st.Code() == codes.Unavailable && i > startUserIndex {
					// We have made some progress already. Return what we have so far, with a page token, with no error:
					// forward progress on Grants() may require us to return here instead of
					// asking to be completely restarted here.
					nextPageToken := encodeUserGrantsPageToken(oktaAfter, i)
					return rv, nextPageToken, annos, nil
				}

				// This is either not a rate-limit error OR we have not yet processed a whole user.
				return nil, "", nil, err
			}
		}

		for samlRole := range appUserSAMLRolesMap.Iterator().C {
			rv = append(rv, o.accountGrant(resource, samlRole, *appUser.Id))
		}
	}

	nextPageToken := ""
	if nextOktaPage != "" {
		nextPageToken = encodeUserGrantsPageToken(nextOktaPage, 0)
	}

	return rv, nextPageToken, annos, nil
}

func parseUserGrantsPageToken(page string) (string, int, error) {
	// The token is "okta page token | index of user in returned value" (or "").
	if page == "" {
		return "", 0, nil
	}

	parts := strings.Split(page, "|")
	if len(parts) == 1 {
		// Just the Okta page token, no user index (implicitly 0).
		return parts[0], 0, nil
	} else if len(parts) == 2 {
		// The Okta page token and a user index; parse that.
		userIndex := 0
		if idx, err := strconv.Atoi(parts[1]); err == nil {
			userIndex = idx
		}
		return parts[0], userIndex, nil
	}

	// Invalid format, give up and start from the beginning.
	return "", 0, fmt.Errorf("okta-aws-connector: invalid user grants page token: %s", page)
}

func encodeUserGrantsPageToken(oktaAfter string, userIndex int) string {
	// The token is "okta page token | index of user in returned value".
	// (Do not call this function when iteration is completely done).
	return fmt.Sprintf("%s|%d", oktaAfter, userIndex)
}

func (o *accountResourceType) collectRolesFromUserGroups(
	ctx context.Context,
	ss sessions.SessionStore,
	userID string,
) (mapset.Set[string], error) {
	l := ctxzap.Extract(ctx)

	userGroups, _, err := listUsersGroupsClientV5(ctx, o.connector.clientV5, userID)
	if err != nil {
		return nil, fmt.Errorf("okta-aws-connector: failed to get groups for user '%s': %w", userID, err)
	}

	roles := mapset.NewSet[string]()

	for _, group := range userGroups {
		if group.Id == nil {
			l.Warn("okta-aws-connector: user group id was nil", zap.Any("userId", userID), zap.Any("group", group))
			continue
		}

		appGroup, err := o.getOktaAppGroupFromCacheOrFetch(ctx, ss, *group.Id)
		if err != nil {
			return nil, err
		}
		if appGroup != nil {
			roles.Append(appGroup.samlRoles...)
		}
	}

	return roles, nil
}

func (o *accountResourceType) groupGrants(ctx context.Context, resource *v2.Resource, attrs resource2.SyncOpAttrs, page string) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	token := &attrs.PageToken

	awsConfig, err := o.connector.getAWSApplicationConfig(ctx, attrs.Session)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: error getting aws app settings config")
	}
	var rv []*v2.Grant

	if awsConfig.UseGroupMapping {
		groups, respCtx, err := listGroupsHelperV5(ctx, o.connector.clientV5, token, page)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to list groups: %w", err)
		}

		nextPage, annos, err := parseRespV5(respCtx.OktaResponse)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse response: %w", err)
		}

		for _, group := range groups {
			if group.Profile.Name == nil {
				l.Warn("okta-aws-connector: group profile name was nil", zap.Any("groupId", group.Id))
				continue
			}

			if group.Id == nil {
				l.Warn("okta-aws-connector: group id was nil", zap.Any("groupName", group.Profile.Name))
				continue
			}

			accountId, roleName, matchesRolePattern, err := parseAccountIDAndRoleFromGroupName(ctx, awsConfig.RoleRegex, *group.Profile.Name)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse account id and role from group name: %w", err)
			}
			if !matchesRolePattern || accountId != resource.GetId().GetResource() {
				continue
			}
			grant, err := o.accountGrantGroupExpandable(resource, roleName, *group.Id)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to create expandable group grant: %w", err)
			}
			rv = append(rv, grant)
		}
		return rv, nextPage, annos, nil
	}

	appGroups, respCtx, err := listApplicationGroupAssignmentsV5(ctx, o.connector.clientV5, o.connector.awsConfig.OktaAppId, token, page)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to list application groups: %w", err)
	}

	nextPage, annos, err := parseRespV5(respCtx.OktaResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse response: %w", err)
	}

	for _, appGroup := range appGroups {
		if appGroup.Id == nil {
			l.Warn("okta-aws-connector: app group id was nil")
			continue
		}

		appGroupSAMLRoles, err := appGroupSAMLRolesWrapperV5(ctx, appGroup)
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to get saml roles for app group: %w", err)
		}

		// TODO(lauren) we only need this when !awsConfig.JoinAllRoles
		_ = awsConfig.setAppGroupInCache(ctx, attrs.Session, *appGroup.Id, appGroupSAMLRoles)

		for _, role := range appGroupSAMLRoles.samlRoles {
			if !awsConfig.JoinAllRoles {
				rv = append(rv, o.accountGrantGroup(resource, role, *appGroup.Id))
			} else {
				grant, err := o.accountGrantGroupExpandable(resource, role, *appGroup.Id)
				if err != nil {
					return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to create expandable group grant: %w", err)
				}
				rv = append(rv, grant)
			}
		}
	}
	return rv, nextPage, annos, nil
}

func (o *accountResourceType) accountGrant(resource *v2.Resource, samlRole string, oktaUserId string) *v2.Grant {
	grantOpts := make([]sdkGrant.GrantOption, 0)
	grantOpts = append(grantOpts, sdkGrant.WithAnnotation(&v2.ExternalResourceMatchID{Id: oktaUserId}))
	ur := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeUser.Id, Resource: oktaUserId}}
	return sdkGrant.NewGrant(resource, samlRole, ur, grantOpts...)
}

func (o *accountResourceType) accountGrantGroup(resource *v2.Resource, samlRole string, groupId string) *v2.Grant {
	grantOpts := make([]sdkGrant.GrantOption, 0)
	grantOpts = append(grantOpts, sdkGrant.WithAnnotation(&v2.ExternalResourceMatchID{Id: groupId}))
	gr := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: groupId}}
	return sdkGrant.NewGrant(resource, samlRole, gr, grantOpts...)
}

func (o *accountResourceType) accountGrantGroupExpandable(resource *v2.Resource, samlRole string, groupId string) (*v2.Grant, error) {
	rID := &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: groupId}
	gr := &v2.Resource{Id: rID}

	grantOpts := make([]sdkGrant.GrantOption, 0)

	ent := sdkEntitlement.NewAssignmentEntitlement(gr, "member")
	bidEnt, err := bid.MakeBid(ent)
	if err != nil {
		return nil, err
	}
	expandEntitlementId := bidEnt
	grantOpts = append(grantOpts, sdkGrant.WithAnnotation(&v2.ExternalResourceMatchID{Id: groupId}))

	grantOpts = append(grantOpts, sdkGrant.WithAnnotation(&v2.GrantExpandable{
		EntitlementIds: []string{expandEntitlementId},
		Shallow:        true,
	}))

	return sdkGrant.NewGrant(resource, samlRole, gr, grantOpts...), nil
}

/*
Join all roles: This option enables merging all available roles assigned to a user as follows:

For example, if a user is directly assigned Role1 and Role2 (user to app assignment),
and the user belongs to group GroupAWS with RoleA and RoleB assigned (group to app assignment), then:

Join all roles OFF: Role1 and Role2 are available upon login to AWS
Join all roles ON: Role1, Role2, RoleA, and RoleB are available upon login to AWS
*/

func (o *accountResourceType) listAWSSamlRoles(ctx context.Context) (*AWSRoles, *responseContextV5, error) {
	apiPath := fmt.Sprintf(apiPathSamlRoles, o.connector.awsConfig.OktaAppId)

	req, err := o.connector.clientV5.PrepareRequest(
		ctx,
		apiPath,
		http.MethodGet,
		nil,
		map[string]string{
			"Accept":       ContentType,
			"Content-Type": ContentType,
		},
		nil,
		nil,
	)
	if err != nil {
		return nil, nil, err
	}

	httpResp, err := o.connector.clientV5.Do(ctx, req)
	if err != nil {
		return nil, nil, err
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode >= 400 {
		return nil, nil, fmt.Errorf("okta-aws-connector: failed AWS saml roles list request, status code %d", httpResp.StatusCode)
	}

	var awsRoles AWSRoles
	if err := json.NewDecoder(httpResp.Body).Decode(&awsRoles); err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to decode response: %w", err)
	}

	// Wrap the http.Response in an APIResponse, and return as a V5 context.
	apiResp := oktav5.NewAPIResponse(httpResp, o.connector.clientV5, &awsRoles)
	respCtx, err := responseToContextV5(&pagination.Token{}, apiResp)
	if err != nil {
		return nil, nil, err
	}

	return &awsRoles, respCtx, nil
}

func getSAMLRolesFromAppUserProfileV5(ctx context.Context, appUser oktav5.AppUser) ([]string, error) {
	l := ctxzap.Extract(ctx)
	if appUser.Profile == nil {
		l.Error("app user profile was nil", zap.Any("userId", appUser.Id))
		return nil, nil
	}
	return getSAMLRoles(appUser.Profile)
}

func getOrCreateAppUserProfileV5(ctx context.Context, appUser *oktav5.AppUser) map[string]any {
	l := ctxzap.Extract(ctx)
	if appUser.Profile == nil {
		l.Error("app user profile was nil", zap.Any("userId", appUser.Id))
		return make(map[string]any)
	}
	return appUser.Profile
}

func getSAMLRolesFromAppGroupProfileV5(ctx context.Context, appGroup oktav5.ApplicationGroupAssignment) ([]string, error) {
	l := ctxzap.Extract(ctx)
	if appGroup.Profile == nil {
		l.Error("app group profile was nil", zap.Any("groupId", appGroup.Id))
		return nil, nil
	}
	return getSAMLRoles(appGroup.Profile)
}

func getSAMLRoles(profile map[string]interface{}) ([]string, error) {
	samlRolesField := profile["samlRoles"]
	if samlRolesField == nil {
		return nil, nil
	}

	samlRoles, ok := samlRolesField.([]interface{})
	if !ok {
		return nil, errors.New("unexpected type in profile[\"samlRoles\"")
	}

	ret := make([]string, len(samlRoles))
	for i, r := range samlRoles {
		role, ok := r.(string)
		if !ok {
			return nil, errors.New("role was not string")
		}
		ret[i] = role
	}
	return ret, nil
}

func (o *accountResourceType) getOktaAppGroupFromCacheOrFetch(ctx context.Context, ss sessions.SessionStore, groupId string) (*OktaAppGroupWrapper, error) {
	l := ctxzap.Extract(ctx)
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx, ss)
	if err != nil {
		return nil, err
	}
	appGroupSAMLRoles, err := awsConfig.getAppGroupFromCache(ctx, ss, groupId)
	if err != nil {
		return nil, err
	}
	if appGroupSAMLRoles != nil {
		l.Debug("okta-aws-connector: found group in cache", zap.String("groupId", groupId))
		return appGroupSAMLRoles, nil
	}
	notAnAppGroup, err := awsConfig.checkIfNotAppGroupFromCache(ctx, ss, groupId)
	if err != nil {
		return nil, err
	}
	if notAnAppGroup {
		return nil, nil
	}

	oktaAppGroup, resp, err := o.connector.clientV5.ApplicationGroupsAPI.GetApplicationGroupAssignment(ctx, o.connector.awsConfig.OktaAppId, groupId).
		Execute()

	if err != nil {
		if resp == nil {
			return nil, fmt.Errorf("okta-aws-connector: failed to fetch application group assignment: %w", err)
		}

		defer resp.Body.Close()
		errOkta, getErr := getErrorV5(resp)
		if getErr != nil {
			l.Error("Failed to parse error from GetApplicationGroupAssignment", zap.Error(getErr))
			return nil, handleOktaResponseErrorV5(ctx, resp, err)
		}

		if errOkta.ErrorCode == nil {
			l.Error("GetApplicationGroupAssignment returned error with nil ErrorCode")
			return nil, handleOktaResponseErrorV5(ctx, resp, err)
		}

		errorSummary := ""
		if errOkta.ErrorSummary != nil {
			errorSummary = *errOkta.ErrorSummary
		}

		if *errOkta.ErrorCode != ResourceNotFoundExceptionErrorCode {
			l.Warn("okta-aws-connector: ", zap.String("ErrorCode", *errOkta.ErrorCode), zap.String("ErrorSummary", errorSummary))
			return nil, handleOktaResponseErrorV5(ctx, resp, err)
		}

		// ResourceNotFound means the group is not assigned to the app - this is not an error,
		// there is just no grant to emit here.
		_ = awsConfig.setNotAppGroupInCache(ctx, ss, groupId, true)

		return nil, nil
	}

	appGroupSAMLRoles, err = appGroupSAMLRolesWrapperV5(ctx, *oktaAppGroup)
	if err != nil {
		return nil, err
	}

	_ = awsConfig.setAppGroupInCache(ctx, ss, groupId, appGroupSAMLRoles)

	return appGroupSAMLRoles, nil
}

type JSONPatchOperation struct {
	// The operation (PATCH action)
	Op string `json:"op,omitempty"`
	// The resource path of the attribute to update
	Path string `json:"path,omitempty"`
	// The update operation value
	Value interface{} `json:"value,omitempty"`
}

func (o *accountResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	if principal.Id.ResourceType != resourceTypeUser.Id && principal.Id.ResourceType != resourceTypeGroup.Id {
		return nil, fmt.Errorf("okta-aws-connector: only users or groups can be granted app membership")
	}
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("error getting aws app settings config")
	}

	if awsConfig.UseGroupMapping {
		return nil, fmt.Errorf("okta-aws-connector: group assignments are based on group names matching regex")
	}

	appID := o.connector.awsConfig.OktaAppId
	newSamlRole, err := parseSAMLRoleFromEntitlementID(entitlement.GetId())
	if err != nil {
		return nil, err
	}

	if newSamlRole == "" {
		return nil, fmt.Errorf("okta-aws-connector: entitlement %s had an empty slug", entitlement.Id)
	}

	switch principal.Id.ResourceType {
	case resourceTypeUser.Id:
		userID := principal.Id.Resource
		appUser, response, err := o.connector.clientV5.ApplicationUsersAPI.GetApplicationUser(ctx, appID, userID).
			Execute()
		if err != nil {
			if response == nil {
				return nil, fmt.Errorf("okta-aws-connector: failed to fetch application user: %w", err)
			}
			defer response.Body.Close()
			errOkta, err := getErrorV5(response)
			if err != nil {
				return nil, err
			}

			if errOkta.ErrorCode == nil {
				return nil, errors.New("okta-aws-connector: failed to fetch application user with unknown error")
			}

			if *errOkta.ErrorCode != ResourceNotFoundExceptionErrorCode {
				return nil, fmt.Errorf("okta-aws-connector: error fetching application user: %v", errOkta)
			}
		}

		if appUser != nil {
			if appUser.Id == nil {
				return nil, fmt.Errorf("okta-aws-connector: application user %s has no id", appID)
			}

			if appUser.Scope == nil {
				return nil, fmt.Errorf("okta-aws-connector: app user scope was nil for user '%v'", appUser.Id)
			}

			// This converts group assignment to direct assignment
			canDirectAssign := awsConfig.JoinAllRoles || awsConfig.SamlRolesUnionEnabled
			if *appUser.Scope == appGroupScope && (!o.connector.awsConfig.AllowGroupToDirectAssignmentConversionForProvisioning || !canDirectAssign) {
				return nil, fmt.Errorf("okta-aws-connector: connect add individual assignment for user with group assignment '%v'", appUser.Id)
			}

			appUserProfile := getOrCreateAppUserProfileV5(ctx, appUser)
			samlRoles, err := getSAMLRoles(appUserProfile)
			if err != nil {
				return nil, fmt.Errorf("okta-aws-connector: failed to get saml roles for user '%v': %w", appUser.Id, err)
			}

			if slices.Contains(samlRoles, newSamlRole) {
				return annotations.New(&v2.GrantAlreadyExists{}), nil
			}

			if samlRoles == nil {
				samlRoles = make([]string, 0)
			}

			samlRoles = append(samlRoles, newSamlRole)
			appUserProfile["samlRoles"] = samlRoles

			_, _, err = o.connector.clientV5.ApplicationUsersAPI.UpdateApplicationUser(ctx, appID, *appUser.Id).
				AppUser(oktav5.AppUserUpdateRequest{
					AppUserProfileRequestPayload: &oktav5.AppUserProfileRequestPayload{
						Profile: appUserProfile,
						AdditionalProperties: map[string]interface{}{
							"scope": appUserScope,
						},
					},
				}).
				Execute()
			if err != nil {
				return nil, fmt.Errorf("okta-aws-connector: failed to update application user: %w", err)
			}

			return nil, nil
		}

		profile := map[string]any{
			"samlRoles": []string{newSamlRole},
		}

		_, _, err = o.connector.clientV5.ApplicationUsersAPI.AssignUserToApplication(ctx, appID).
			AppUser(oktav5.AppUserAssignRequest{
				Id:      userID,
				Scope:   oktav5.PtrString(appUserScope),
				Profile: profile,
			}).
			Execute()
		if err != nil {
			return nil, fmt.Errorf("okta-aws-connector: error assigning app to user %w", err)
		}
	case resourceTypeGroup.Id:
		groupID := principal.Id.Resource
		appGroup, response, err := o.connector.clientV5.ApplicationGroupsAPI.GetApplicationGroupAssignment(ctx, appID, groupID).
			Execute()
		if err != nil {
			if response == nil {
				return nil, fmt.Errorf("okta-aws-connector: failed to fetch application group assignment: %w", err)
			}
			defer response.Body.Close()
			errOkta, err := getErrorV5(response)
			if err != nil {
				return nil, err
			}

			if errOkta.ErrorCode == nil {
				return nil, errors.New("okta-aws-connector: failed to fetch application group assignment with unknown error")
			}

			if *errOkta.ErrorCode != ResourceNotFoundExceptionErrorCode {
				return nil, fmt.Errorf("okta-aws-connector: error fetching application group assignment %v", errOkta)
			}
		}

		if appGroup != nil {
			return addSamlRoleToAppGroup(ctx, o.connector.clientV5, appID, groupID, newSamlRole, appGroup)
		}

		// AssignGroupToApplication() does not allow atomic setting of the new saml role,
		// so this just does the basic assignment.
		_, _, err = o.connector.clientV5.ApplicationGroupsAPI.AssignGroupToApplication(ctx, appID, groupID).
			Execute()
		if err != nil {
			return nil, fmt.Errorf("okta-aws-connector: error creating application group assignment %w", err)
		}

		// Now, we need to repeat the call from above to get any existing saml roles set via the assignment.
		appGroup, _, err = o.connector.clientV5.ApplicationGroupsAPI.GetApplicationGroupAssignment(ctx, appID, groupID).
			Execute()
		if err != nil {
			return nil, fmt.Errorf("okta-aws-connector: error getting application group assignment after assignment: %w", err)
		}

		return addSamlRoleToAppGroup(ctx, o.connector.clientV5, appID, groupID, newSamlRole, appGroup)
	default:
		return nil, fmt.Errorf("okta-aws-connector: invalid grant resource type: %s", principal.Id.ResourceType)
	}

	return nil, nil
}

func (o *accountResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	if grant.Principal.Id.ResourceType != resourceTypeUser.Id && grant.Principal.Id.ResourceType != resourceTypeGroup.Id {
		return nil, fmt.Errorf("okta-aws-connector: only users or groups can be have aws account role revoked")
	}
	awsConfig, err := o.connector.getAWSApplicationConfig(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("okta-aws-connector: error getting aws app settings config")
	}

	if awsConfig.UseGroupMapping {
		return nil, fmt.Errorf("okta-aws-connector: grants are based on group name matching configured regular expression")
	}

	appID := o.connector.awsConfig.OktaAppId
	samlRoleToRemove, err := parseSAMLRoleFromEntitlementID(grant.GetEntitlement().GetId())
	if err != nil {
		return nil, err
	}

	if samlRoleToRemove == "" {
		return nil, fmt.Errorf("okta-aws-connector: entitlement %s had an empty slug", grant.Entitlement.Id)
	}

	switch grant.Principal.Id.ResourceType {
	case resourceTypeUser.Id:
		userID := grant.Principal.Id.Resource
		appUser, response, err := o.connector.clientV5.ApplicationUsersAPI.GetApplicationUser(ctx, appID, userID).
			Execute()
		if err != nil {
			if response == nil {
				return nil, fmt.Errorf("okta-aws-connector: failed to fetch application user: %w", err)
			}
			defer response.Body.Close()
			errOkta, err := getErrorV5(response)
			if err != nil {
				return nil, err
			}

			if errOkta.ErrorCode == nil {
				return nil, errors.New("okta-aws-connector: failed to fetch application user with unknown error")
			}

			if *errOkta.ErrorCode != ResourceNotFoundExceptionErrorCode {
				// TODO(lauren) should we error if app user not found?
				return nil, fmt.Errorf("okta-aws-connector: error fetching application user: %v", errOkta)
			}
			return nil, nil
		}

		if appUser.Id == nil {
			return nil, fmt.Errorf("okta-aws-connector: application user %s has no id", appID)
		}

		if appUser.Scope == nil {
			return nil, fmt.Errorf("okta-aws-connector: app user scope was nil for user '%v'", appUser.Id)
		}

		canDirectAssign := awsConfig.JoinAllRoles || awsConfig.SamlRolesUnionEnabled
		if *appUser.Scope == appGroupScope && (!o.connector.awsConfig.AllowGroupToDirectAssignmentConversionForProvisioning || !canDirectAssign) {
			return nil, fmt.Errorf("okta-aws-connector: connect remove role granted via group assignment '%v'", appUser.Id)
		}

		samlRoles, err := getSAMLRolesFromAppUserProfileV5(ctx, *appUser)
		if err != nil {
			return nil, fmt.Errorf("okta-aws-connector: failed to get saml roles for user '%v': %w", appUser.Id, err)
		}
		if !slices.Contains(samlRoles, samlRoleToRemove) {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}

		appUserProfile := appUser.Profile
		if appUserProfile == nil {
			return nil, fmt.Errorf("okta-aws-connector: app user profile '%s' is nil", *appUser.Id)
		}

		newSamlRoles := removeSamlRole(samlRoles, samlRoleToRemove)

		appUserProfile["samlRoles"] = newSamlRoles

		_, _, err = o.connector.clientV5.ApplicationUsersAPI.UpdateApplicationUser(ctx, appID, *appUser.Id).
			AppUser(oktav5.AppUserUpdateRequest{
				AppUserProfileRequestPayload: &oktav5.AppUserProfileRequestPayload{
					Profile: appUserProfile,
					AdditionalProperties: map[string]interface{}{
						"samlRoles": newSamlRoles,
						"scope":     appUserScope,
					},
				},
			}).
			Execute()
		if err != nil {
			return nil, fmt.Errorf("okta-aws-connector: error updating application user: %w", err)
		}
	case resourceTypeGroup.Id:
		groupID := grant.Principal.Id.Resource
		appGroup, response, err := o.connector.clientV5.ApplicationGroupsAPI.GetApplicationGroupAssignment(ctx, appID, groupID).
			Execute()
		if err != nil {
			if response == nil {
				return nil, fmt.Errorf("okta-aws-connector: failed to fetch application group assignment: %w", err)
			}
			defer response.Body.Close()
			errOkta, err := getErrorV5(response)
			if err != nil {
				return nil, err
			}

			if errOkta.ErrorCode == nil {
				return nil, errors.New("okta-aws-connector: failed to fetch application group assignment with unknown error")
			}

			// TODO(lauren) should we error if app group not found?
			if *errOkta.ErrorCode != ResourceNotFoundExceptionErrorCode {
				return nil, fmt.Errorf("okta-aws-connector: error fetching application group assignment %v", errOkta)
			}
			return nil, nil
		}

		samlRoles, err := getSAMLRolesFromAppGroupProfileV5(ctx, *appGroup)
		if err != nil {
			return nil, fmt.Errorf("okta-aws-connector: failed to get saml roles for app group '%s': %w", groupID, err)
		}
		if !slices.Contains(samlRoles, samlRoleToRemove) {
			return annotations.New(&v2.GrantAlreadyRevoked{}), nil
		}
		newSamlRoles := removeSamlRole(samlRoles, samlRoleToRemove)
		_, err = updateApplicationGroup(ctx, o.connector.clientV5, appID, groupID, newSamlRoles)
		if err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("okta-aws-connector: invalid revoke resource type: %s", grant.Principal.Id.ResourceType)
	}
	return nil, nil
}

func addSamlRoleToAppGroup(
	ctx context.Context,
	clientV5 *oktav5.APIClient,
	appID string,
	groupID string,
	newSamlRole string,
	appGroup *oktav5.ApplicationGroupAssignment,
) (annotations.Annotations, error) {
	samlRoles, err := getSAMLRolesFromAppGroupProfileV5(ctx, *appGroup)
	if err != nil {
		return nil, fmt.Errorf("okta-aws-connector: failed to get saml roles for app group profile '%s': %w", groupID, err)
	}
	if slices.Contains(samlRoles, newSamlRole) {
		return annotations.New(&v2.GrantAlreadyExists{}), nil
	}
	if samlRoles == nil {
		samlRoles = make([]string, 0)
	}
	samlRoles = append(samlRoles, newSamlRole)
	_, err = updateApplicationGroup(ctx, clientV5, appID, groupID, samlRoles)
	if err != nil {
		return nil, fmt.Errorf("okta-aws-connector: error updating application group '%s': %w", groupID, err)
	}
	return nil, nil
}

// This function *replaces* saml roles on an application group with those provided.
func updateApplicationGroup(
	ctx context.Context,
	clientV5 *oktav5.APIClient,
	appID string,
	groupID string,
	samlRoles []string,
) (*oktav5.ApplicationGroupAssignment, error) {
	apiPath := fmt.Sprintf(apiPathApplicationGroup, appID, groupID)

	payload := []JSONPatchOperation{
		{
			Op:   "replace",
			Path: "/profile/samlRoles",
			Value: samlRoles,
		},
	}

	// Prepare the HTTP request using v5 client
	req, err := clientV5.PrepareRequest(
		ctx,
		apiPath,
		http.MethodPatch,
		payload,
		map[string]string{
			"Accept":       ContentType,
			"Content-Type": ContentType,
		},
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	httpResp, err := clientV5.Do(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("okta-aws-connector: error updating application group: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode >= 400 {
		return nil, fmt.Errorf("okta-aws-connector: failed saml roles replace request, status code %d", httpResp.StatusCode)
	}

	var appGroup oktav5.ApplicationGroupAssignment
	if err := json.NewDecoder(httpResp.Body).Decode(&appGroup); err != nil {
		return nil, fmt.Errorf("okta-aws-connector: failed to decode response: %w", err)
	}

	return &appGroup, nil
}

func removeSamlRole(samlRoles []string, samlRoleToRemove string) []string {
	newSamlRoles := make([]string, 0)
	for _, samlRole := range samlRoles {
		if samlRole == samlRoleToRemove {
			continue
		}
		newSamlRoles = append(newSamlRoles, samlRole)
	}
	return newSamlRoles
}

func listGroupsHelperV5(ctx context.Context, client *oktav5.APIClient, token *pagination.Token, after string) ([]oktav5.Group, *responseContextV5, error) {
	groups, resp, err := client.GroupAPI.ListGroups(ctx).
		Limit(defaultLimit).
		After(after).
		Execute()
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to fetch groups from okta: %w", handleOktaResponseErrorV5(ctx, resp, err))
	}

	reqCtx, err := responseToContextV5(token, resp)
	if err != nil {
		return nil, nil, err
	}
	return groups, reqCtx, nil
}

func listUsersGroupsClientV5(ctx context.Context, client *oktav5.APIClient, userId string) ([]oktav5.Group, *responseContextV5, error) {
	// This API does not support pagination.
	userGroups, resp, err := client.UserAPI.ListUserGroups(ctx, userId).
		Execute()
	if err != nil {
		return nil, nil, fmt.Errorf("okta-aws-connector: failed to fetch group users from okta: %w", handleOktaResponseErrorV5(ctx, resp, err))
	}

	reqCtx, err := responseToContextV5(&pagination.Token{}, resp)
	if err != nil {
		return nil, nil, err
	}

	return userGroups, reqCtx, nil
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
