package main

import (
	"github.com/conductorone/baton-sdk/pkg/field"
)

var (
	domain   = field.StringField("domain", field.WithRequired(true), field.WithDescription("The URL for the Okta organization"))
	apiToken = field.StringField("api-token", field.WithRequired(true), field.WithDescription("The API token for the service account"))

	awsAllowGroupToDirectAssignmentConversionForProvisioning = field.BoolField("aws-allow-group-to-direct-assignment-conversion-for-provisioning",
		field.WithDescription("Whether to allow group to direct assignment conversion when provisioning"))
	awsOktaAppId = field.StringField("aws-okta-app-id", field.WithRequired(true), field.WithDescription("The Okta app id for the AWS application"))

	cache    = field.BoolField("cache", field.WithDescription("Enable response cache"), field.WithDefaultValue(true))
	cacheTTI = field.IntField("cache-tti", field.WithDescription("Response cache cleanup interval in seconds"), field.WithDefaultValue(60))
	cacheTTL = field.IntField("cache-ttl", field.WithDescription("Response cache time to live in seconds"), field.WithDefaultValue(300))
)

var configuration = field.NewConfiguration([]field.SchemaField{
	domain,
	apiToken,
	cache,
	cacheTTI,
	cacheTTL,
	awsOktaAppId,
	awsAllowGroupToDirectAssignmentConversionForProvisioning,
})
