package connector

import (
	"context"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	resource2 "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// groupResourceType exists solely to provision Okta group membership.
//
// This connector does not sync groups as first class resources: the AWS account
// syncer discovers the AWS role groups it cares about and emits grant expandable
// annotations that point at "group:<id>:member" entitlements. Those entitlements
// are therefore created by grant expansion rather than by a group sync, but they
// still need a provisioner registered for the "group" resource type so the SDK
// can dispatch grant/revoke calls against them. List/Entitlements/Grants are
// intentionally empty stubs.
var (
	_ connectorbuilder.ResourceSyncerV2           = (*groupResourceType)(nil)
	_ connectorbuilder.ResourceProvisionerLimited = (*groupResourceType)(nil)
)

type groupResourceType struct {
	resourceType *v2.ResourceType
	connector    *Okta
}

func groupBuilder(connector *Okta) *groupResourceType {
	return &groupResourceType{
		resourceType: resourceTypeGroup,
		connector:    connector,
	}
}

func (g *groupResourceType) ResourceType(_ context.Context) *v2.ResourceType {
	return g.resourceType
}

// List is intentionally a stub: groups are not synced as resources by this connector.
func (g *groupResourceType) List(
	ctx context.Context,
	parentResourceID *v2.ResourceId,
	attrs resource2.SyncOpAttrs,
) ([]*v2.Resource, *resource2.SyncOpResults, error) {
	return nil, nil, nil
}

// Entitlements is intentionally a stub: group member entitlements are created via
// grant expansion from the account syncer, not by syncing groups.
func (g *groupResourceType) Entitlements(
	ctx context.Context,
	resource *v2.Resource,
	attrs resource2.SyncOpAttrs,
) ([]*v2.Entitlement, *resource2.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants is intentionally a stub: see Entitlements.
func (g *groupResourceType) Grants(
	ctx context.Context,
	resource *v2.Resource,
	attrs resource2.SyncOpAttrs,
) ([]*v2.Grant, *resource2.SyncOpResults, error) {
	return nil, nil, nil
}

func (g *groupResourceType) Grant(ctx context.Context, principal *v2.Resource, entitlement *v2.Entitlement) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"okta-aws-connector: only users can be granted group membership",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-aws-connector: only users can be granted group membership")
	}

	groupId := entitlement.Resource.Id.Resource
	userId := principal.Id.Resource

	response, err := g.connector.clientV5.GroupAPI.AssignUserToGroup(ctx, groupId, userId).Execute()
	if err != nil {
		return nil, handleOktaResponseErrorV5(ctx, response, err)
	}

	if response != nil && response.Response != nil {
		l.Debug("Membership has been created", zap.String("Status", response.Status))
	} else {
		l.Debug("Membership has been created")
	}

	return nil, nil
}

func (g *groupResourceType) Revoke(ctx context.Context, grant *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	entitlement := grant.Entitlement
	principal := grant.Principal
	if principal.Id.ResourceType != resourceTypeUser.Id {
		l.Warn(
			"okta-aws-connector: only users can have group membership revoked",
			zap.String("principal_type", principal.Id.ResourceType),
			zap.String("principal_id", principal.Id.Resource),
		)
		return nil, fmt.Errorf("okta-aws-connector: only users can have group membership revoked")
	}

	groupId := entitlement.Resource.Id.Resource
	userId := principal.Id.Resource

	response, err := g.connector.clientV5.GroupAPI.UnassignUserFromGroup(ctx, groupId, userId).Execute()
	if err != nil {
		return nil, handleOktaResponseErrorV5(ctx, response, err)
	}

	if response != nil && response.Response != nil {
		l.Warn("Membership has been revoked", zap.String("Status", response.Status))
	} else {
		l.Warn("Membership has been revoked")
	}

	return nil, nil
}
