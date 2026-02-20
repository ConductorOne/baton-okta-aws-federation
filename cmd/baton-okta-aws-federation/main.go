package main

import (
	"context"

	cfg "github.com/conductorone/baton-okta-aws-federation/pkg/config"
	"github.com/conductorone/baton-okta-aws-federation/pkg/connector"
	"github.com/conductorone/baton-sdk/pkg/config"
	"github.com/conductorone/baton-sdk/pkg/connectorrunner"
)

var version = "dev"

func main() {
	ctx := context.Background()
	config.RunConnector(ctx,
		"baton-okta-aws-federation",
		version,
		cfg.Config,
		connector.New,
		connectorrunner.WithSessionStoreEnabled(),
		connectorrunner.WithDefaultCapabilitiesConnectorBuilderV2(&connector.Okta{}),
	)
}
