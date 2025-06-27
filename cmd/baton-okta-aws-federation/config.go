package main

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	domain              = field.StringField("domain", field.WithRequired(true), field.WithDescription("The URL for the Okta organization"))
	apiToken            = field.StringField("api-token", field.WithRequired(true), field.WithDescription("The API token for the service account"))
	syncInactivateApps  = field.BoolField("sync-inactive-apps", field.WithDescription("Whether to sync inactive apps or not"), field.WithDefaultValue(true))
	oktaProvisioning    = field.BoolField("okta-provisioning")
	cache               = field.BoolField("cache", field.WithDescription("Enable response cache"), field.WithDefaultValue(true))
	cacheTTI            = field.IntField("cache-tti", field.WithDescription("Response cache cleanup interval in seconds"), field.WithDefaultValue(60))
	cacheTTL            = field.IntField("cache-ttl", field.WithDescription("Response cache time to live in seconds"), field.WithDefaultValue(300))
	syncCustomRoles     = field.BoolField("sync-custom-roles", field.WithDescription("Enable syncing custom roles"), field.WithDefaultValue(false))
	skipSecondaryEmails = field.BoolField("skip-secondary-emails", field.WithDescription("Skip syncing secondary emails"), field.WithDefaultValue(false))

	awsAllowGroupToDirectAssignmentConversionForProvisioning = field.BoolField("aws-allow-group-to-direct-assignment-conversion-for-provisioning",
		field.WithDescription("Whether to allow group to direct assignment conversion when provisioning"))
	awsSourceIdentityMode = field.BoolField("aws-source-identity-mode",
		field.WithDescription("Enable AWS source identity mode. When set, user and group identities are loaded from the source connector .c1z file"))
	awsOktaAppId = field.StringField("aws-okta-app-id", field.WithRequired(true), field.WithDescription("The Okta app id for the AWS application"))
	SyncSecrets  = field.BoolField("sync-secrets", field.WithDescription("Whether to sync secrets or not"), field.WithDefaultValue(false))
)

var configuration = field.NewConfiguration([]field.SchemaField{
	domain,
	apiToken,
	syncInactivateApps,
	oktaProvisioning,
	cache,
	cacheTTI,
	cacheTTL,
	syncCustomRoles,
	skipSecondaryEmails,
	awsOktaAppId,
	SyncSecrets,
	awsSourceIdentityMode,
	awsAllowGroupToDirectAssignmentConversionForProvisioning,
})
