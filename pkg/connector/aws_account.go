package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
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

	LargeAppGroupCollectionSize = 5
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

	awsConfig, err := o.connector.getAWSApplicationConfig(ctx, attrs.Session)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: error getting aws app settings config")
	}

	//
	// Determine what to do here:
	//  - If we have no ResourceID set in our token (`page`), we call the Okta API to list application users,
	//    and process any that we only need direct SAML roles for inline. If we saw any users that we need
	//    to collect roles from user groups for, then we push those into `page`.
	//  - If we have a ResourceID set in `page` with an empty Token, we process the user's groups from index 0.
	//  - If we have a ResourceID set in `page` with a numeric Token, we resume processing the user's groups
	//    from that index into the sorted group ID list.
	//
	// The idea is that collecting roles from user groups requires potentially many API calls,
	// and we're concerned about rate-limiting. If we process a single user at a time,
	// we allow the SDK to retry us at a pretty granular level, minimizing the amount of work
	// we have to do at each retry - and if that user has a particularly large amount of
	// app group assignments to process, we must paginate at that level as well or else
	// we may flat out time out when running in a lambda function.
	//
	bag := &pagination.Bag{}
	err = bag.Unmarshal(page)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse user grants page token: %w", err)
	}

	if bag.Current() == nil {
		bag.Push(pagination.PageState{
			Token:      "", // Token holds the next okta page, we want to start from the first one.
			ResourceID: "", // ResourceID holds a user ID whose roles need to be collected from user groups. Empty means "process Okta page".
		})
	}
	current := bag.Current()

	var rv []*v2.Grant
	var annos annotations.Annotations

	// Check if we're resuming to process a specific app user.
	if current.ResourceID != "" {
		userID := current.ResourceID

		// Parse the start index from Token (0 if empty/first attempt).
		startIdx := 0
		if current.Token != "" {
			startIdx, err = strconv.Atoi(current.Token)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse group index from token: %w", err)
			}
		}

		roles, nextIdx, err := o.collectRolesFromUserGroups(ctx, attrs.Session, userID, startIdx)
		if err != nil {
			// This may be a rate-limit error: in this (common) case, we'll retry this user later on.
			return nil, "", nil, err
		}

		for samlRole := range roles.Iterator().C {
			rv = append(rv, o.accountGrant(resource, samlRole, userID))
		}

		// Pop this user from the bag - if we're not currently done with it,
		// we'll push it back onto the bag immediately with a start index.
		bag.Pop()

		// If we didn't finish, push a continuation with the index we stopped at.
		if nextIdx >= 0 {
			bag.Push(pagination.PageState{
				ResourceID: userID,
				Token:      strconv.Itoa(nextIdx),
			})
		}

		nextPageToken, err := bag.Marshal()
		if err != nil {
			return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to serialize bag: %w", err)
		}

		return rv, nextPageToken, annos, nil
	}

	// Otherwise, we have a new batch of application users to list.
	oktaAfter := bag.PageToken()
	appUsers, respContext, err := listApplicationUsersV5(ctx, o.connector.clientV5, o.connector.awsConfig.OktaAppId, &attrs.PageToken, oktaAfter)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: error listing application users: %w", err)
	}

	nextOktaPage, annos, err := parseRespV5(respContext.OktaResponse)
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to parse response: %w", err)
	}

	// Pop the current Okta page state (we've consumed it by fetching this page),
	// and push the next Okta page state if there is one. This must happen before
	// pushing any per-user states, so the next page sits below them in the stack.
	bag.Pop()
	if nextOktaPage != "" {
		bag.Push(pagination.PageState{
			Token:      nextOktaPage,
			ResourceID: "", // Empty means "process Okta page".
		})
	}

	// Process any regular app users inline, and collect any users that need group-based role collection.
	for _, appUser := range appUsers {
		if appUser.Id == nil {
			l.Warn("okta-aws-connector: app user id was nil")
			continue
		} else if appUser.Scope == nil {
			l.Warn("okta-aws-connector: app user scope was nil", zap.Any("userId", appUser.Id))
			continue
		}

		// For users with direct assignments or with Union enabled, we extract samlRoles from their profile
		if *appUser.Scope == appUserScope || (*appUser.Scope == appGroupScope && awsConfig.SamlRolesUnionEnabled) {
			appUserSAMLRoles, err := getSAMLRolesFromAppUserProfileV5(ctx, appUser)
			if err != nil {
				return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to get saml roles for user '%v': %w", appUser.Id, err)
			}

			for _, samlRole := range appUserSAMLRoles {
				rv = append(rv, o.accountGrant(resource, samlRole, *appUser.Id))
			}
		} else if *appUser.Scope == appGroupScope && !awsConfig.JoinAllRoles && !awsConfig.SamlRolesUnionEnabled {
			// For group-scoped users (no direct assignment) and when Union/JoinAllRoles is disabled,
			// samlRoles are gathered by inspecting the user's group memberships (which we'll do in when called back).

			// Push this user into the bag.
			bag.Push(pagination.PageState{
				Token:      "", // Empty means start from group index 0.
				ResourceID: *appUser.Id,
			})
		}
	}

	nextPageToken, err := bag.Marshal()
	if err != nil {
		return nil, "", nil, fmt.Errorf("okta-aws-connector: failed to serialize bag: %w", err)
	}

	return rv, nextPageToken, annos, nil
}

// collectRolesFromUserGroups lists roles from a user's groups, sorted by ID,
// and processes them starting from startIdx.
//
// On success, it returns all collected roles and the index -1.
//
// If a fetch error occurs after making some progress (i > startIdx), it returns the
// roles collected so far and the index it stopped at.
// If the error occurs on the very first group (no progress),
// it returns that error (typically a rate-limiting related error).
//
func (o *accountResourceType) collectRolesFromUserGroups(
	ctx context.Context,
	ss sessions.SessionStore,
	userID string,
	startIdx int,
) (mapset.Set[string], int, error) {
	l := ctxzap.Extract(ctx)

	userGroups, _, err := listUsersGroupsClientV5(ctx, o.connector.clientV5, userID)
	if err != nil {
		return nil, -1, fmt.Errorf("okta-aws-connector: failed to get groups for user '%s': %w", userID, err)
	}

	var groupIDs []string
	for _, group := range userGroups {
		if group.Id == nil {
			l.Warn("okta-aws-connector: user group id was nil", zap.String("userId", userID))
			continue
		}
		groupIDs = append(groupIDs, *group.Id)
	}
	sort.Strings(groupIDs)

	if startIdx > len(groupIDs) {
		l.Warn("okta-aws-connector: start index for user groups was > number of groups",
			zap.Int("startIdx", startIdx), zap.Int("numGroups", len(groupIDs)))
		return nil, -1, nil
	} else if startIdx < 0 {
		return nil, -1, fmt.Errorf("okta-aws-connector: invalid start index %d for user groups found", startIdx)
	}

	roles := mapset.NewSet[string]()
	for i := startIdx; i < len(groupIDs); i++ {
		appGroup, fetchErr := o.getOktaAppGroupFromCacheOrFetch(ctx, ss, groupIDs[i])
		if fetchErr != nil {
			// No progress made — return the (already processed, likely rate-limiting related) error.
			if i == startIdx {
				return nil, -1, fetchErr
			}

			return roles, i, nil
		}

		if appGroup != nil {
			roles.Append(appGroup.samlRoles...)
		}
	}

	return roles, -1, nil
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

	var appGroupIDs []string
	for _, appGroup := range appGroups {
		if appGroup.Id == nil {
			l.Warn("okta-aws-connector: app group id was nil")
			continue
		}

		appGroupIDs = append(appGroupIDs, *appGroup.Id)

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

	// Accumulate app group IDs into the session store set.
	// This is built up across pages so that getOktaAppGroupFromCacheOrFetch
	// can skip API calls for groups that are definitely not app groups.
	// We skip this for small deployments where the overhead isn't worth it.
	isSinglePage := page == "" && nextPage == ""
	if len(appGroupIDs) > 0 && (!isSinglePage || len(appGroupIDs) >= LargeAppGroupCollectionSize) {
		if err := awsConfig.appendToAppGroupIDSet(ctx, attrs.Session, appGroupIDs); err != nil {
			l.Warn("okta-aws-connector: failed to store app group ID set", zap.Error(err))
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

	// If we have the complete set of app group IDs (built during group grants),
	// check whether this group is in it. If the set exists and this group isn't
	// in it, we know it's not an app group without an API call. If the set
	// itself is missing (not yet built or evicted), keep going.
	appGroupIDSet, err := awsConfig.getAppGroupIDSet(ctx, ss)
	if err == nil && appGroupIDSet != nil && !appGroupIDSet[groupId] {
		_ = awsConfig.setNotAppGroupInCache(ctx, ss, groupId, true)
		return nil, nil
	}

	oktaAppGroup, resp, err := o.connector.clientV5.ApplicationGroupsAPI.GetApplicationGroupAssignment(ctx, o.connector.awsConfig.OktaAppId, groupId).
		Execute()

	if err != nil {
		if resp == nil {
			return nil, fmt.Errorf("okta-aws-connector: failed to fetch application group assignment: %w", err)
		} else if resp.Response == nil || resp.Body == nil {
			// Treat as a possible 429 - Okta SDK can rarely construct a partial response.
			return nil, handleOktaResponseErrorV5(ctx, resp, err)
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
