package connector

import (
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	mapset "github.com/deckarep/golang-set/v2"
	oktaSDK "github.com/okta/okta-sdk-golang/v2/okta"
)

var (
	GroupChangeFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("group.user_membership.add", "group.lifecycle.create"),
		TargetTypes: mapset.NewSet[string]("UserGroup"),
		EventHandler: func(event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["UserGroup"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 UserGroup target, got %d", len(targetMap["UserGroup"]))
			}
			userGroup := targetMap["UserGroup"][0]
			rv.Event = &v2.Event_ResourceChangeEvent{
				ResourceChangeEvent: &v2.ResourceChangeEvent{
					ResourceId: &v2.ResourceId{
						ResourceType: resourceTypeGroup.Id,
						Resource:     userGroup.Id,
					},
				},
			}
			return nil
		},
	}
	UserLifecycleFilter = EventFilter{
		EventTypes:  mapset.NewSet[string]("user.lifecycle.create", "user.lifecycle.activate", "user.account.update_profile"),
		TargetTypes: mapset.NewSet[string]("User"),
		EventHandler: func(event *oktaSDK.LogEvent, targetMap map[string][]*oktaSDK.LogTarget, rv *v2.Event) error {
			if len(targetMap["User"]) != 1 {
				return fmt.Errorf("okta-connectorv2: expected 1 User target, got %d", len(targetMap["User"]))
			}
			user := targetMap["User"][0]
			rv.Event = &v2.Event_ResourceChangeEvent{
				ResourceChangeEvent: &v2.ResourceChangeEvent{
					ResourceId: &v2.ResourceId{
						ResourceType: resourceTypeUser.Id,
						Resource:     user.Id,
					},
				},
			}
			return nil
		},
	}
)
