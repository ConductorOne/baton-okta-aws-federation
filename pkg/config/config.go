package config

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	domain = field.StringField("domain",
		field.WithDisplayName("Okta domain"),
		field.WithDescription("The URL for the Okta organization"),
		field.WithPlaceholder("e.g. acmeco.okta.com"),
		field.WithRequired(true),
	)

	apiToken = field.StringField("api-token",
		field.WithDisplayName("API token"),
		field.WithDescription("The API token for the service account"),
		field.WithPlaceholder("Your Okta API token"),
		field.WithRequired(true),
		field.WithIsSecret(true),
	)

	awsAllowGroupToDirectAssignmentConversionForProvisioning = field.BoolField("aws-allow-group-to-direct-assignment-conversion-for-provisioning",
		field.WithDisplayName("Allow group to direct assignment conversion for provisioning"),
		field.WithDescription("Whether to allow group to direct assignment conversion when provisioning"),
		field.WithDefaultValue(false),
	)

	awsOktaAppId = field.StringField("aws-okta-app-id",
		field.WithDisplayName("AWS Okta App ID"),
		field.WithDescription("The Okta app id for the AWS application"),
		field.WithRequired(true),
	)

	cache               = field.BoolField("cache", field.WithDescription("Enable response cache"), field.WithDefaultValue(true))
	cacheTTI            = field.IntField("cache-tti", field.WithDescription("Response cache cleanup interval in seconds"), field.WithDefaultValue(60))
	cacheTTL            = field.IntField("cache-ttl", field.WithDescription("Response cache time to live in seconds"), field.WithDefaultValue(300))
	skipSecondaryEmails = field.BoolField("skip-secondary-emails", field.WithDescription("Skip syncing secondary emails"), field.WithDefaultValue(false))
)

//go:generate go run ./gen
var Config = field.NewConfiguration([]field.SchemaField{
	domain,
	apiToken,
	cache,
	cacheTTI,
	cacheTTL,
	skipSecondaryEmails,
	awsOktaAppId,
	awsAllowGroupToDirectAssignmentConversionForProvisioning,
},
	field.WithConnectorDisplayName("Okta AWS Federation"),
	field.WithIconUrl("/static/app-icons/okta.svg"),
	field.WithIsDirectory(true),
	field.WithSupportsExternalResources(true),
	field.WithRequiresExternalConnector(true),
)
