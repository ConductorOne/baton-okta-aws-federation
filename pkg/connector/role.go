package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	sdkResource "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

// Roles that can only be assigned at the org-wide scope.
// For full list of roles see: https://developer.okta.com/docs/reference/api/roles/#role-types
var standardRoleTypes = []*okta.Role{
	{Type: "API_ACCESS_MANAGEMENT_ADMIN", Label: "API Access Management Administrator"},
	{Type: "MOBILE_ADMIN", Label: "Mobile Administrator"},
	{Type: "ORG_ADMIN", Label: "Organizational Administrator"},
	{Type: "READ_ONLY_ADMIN", Label: "Read-Only Administrator"},
	{Type: "REPORT_ADMIN", Label: "Report Administrator"},
	{Type: "SUPER_ADMIN", Label: "Super Administrator"},
	// The type name is strange, but it is what Okta uses for the Group Administrator standard role
	{Type: "USER_ADMIN", Label: "Group Administrator"},
	{Type: "HELP_DESK_ADMIN", Label: "Help Desk Administrator"},
	{Type: "APP_ADMIN", Label: "Application Administrator"},
	{Type: "GROUP_MEMBERSHIP_ADMIN", Label: "Group Membership Administrator"},
}

type CustomRoles struct {
	Roles []*okta.Role `json:"roles,omitempty"`
	Links interface{}  `json:"_links,omitempty"`
}

type RoleAssignment struct {
	Id    string      `json:"id,omitempty"`
	Orn   string      `json:"orn,omitempty"`
	Links interface{} `json:"_links,omitempty"`
}

type RoleAssignments struct {
	RoleAssignments []*RoleAssignment `json:"value,omitempty"`
	Links           interface{}       `json:"_links,omitempty"`
}

const (
	apiPathListAdministrators              = "/api/internal/administrators"
	apiPathListIamCustomRoles              = "/api/v1/iam/roles"
	apiPathListAllUsersWithRoleAssignments = "/api/v1/iam/assignees/users"
	ContentType                            = "application/json"
	NF                                     = -1
)

func getOrgSettings(ctx context.Context, client *okta.Client, token *pagination.Token) (*okta.OrgSetting, *responseContext, error) {
	orgSettings, resp, err := client.OrgSetting.GetOrgSettings(ctx)
	if err != nil {
		return nil, nil, handleOktaResponseError(resp, err)
	}

	respCtx, err := responseToContext(token, resp)
	if err != nil {
		return nil, nil, err
	}

	return orgSettings, respCtx, nil
}

func StandardRoleTypeFromLabel(label string) *okta.Role {
	for _, role := range standardRoleTypes {
		if role.Label == label {
			return role
		}
	}
	return nil
}

func roleResource(ctx context.Context, role *okta.Role, ctype *v2.ResourceType) (*v2.Resource, error) {
	var objectID = role.Type
	if role.Type == "" && role.Id != "" {
		objectID = role.Id
	}

	profile := map[string]interface{}{
		"id":    role.Id,
		"label": role.Label,
		"type":  role.Type,
	}

	return sdkResource.NewRoleResource(
		role.Label,
		ctype,
		objectID,
		[]sdkResource.RoleTraitOption{sdkResource.WithRoleProfile(profile)},
		sdkResource.WithAnnotation(&v2.V1Identifier{
			Id: fmtResourceIdV1(objectID),
		}),
	)
}

func roleGroupGrant(groupID string, resource *v2.Resource, shouldExpand bool) *v2.Grant {
	gr := &v2.Resource{Id: &v2.ResourceId{ResourceType: resourceTypeGroup.Id, Resource: groupID}}

	grantOpts := []sdkGrant.GrantOption{
		sdkGrant.WithAnnotation(&v2.V1Identifier{
			Id: fmtGrantIdV1(V1MembershipEntitlementID(resource.Id.Resource), groupID),
		}),
	}

	if shouldExpand {
		grantOpts = append(grantOpts, sdkGrant.WithAnnotation(&v2.GrantExpandable{
			EntitlementIds: []string{fmt.Sprintf("group:%s:member", groupID)},
			Shallow:        true,
		}))
	}

	return sdkGrant.NewGrant(resource, "assigned", gr, grantOpts...)
}
