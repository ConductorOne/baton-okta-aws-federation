package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/conductorone/baton-okta-aws-federation/pkg/connector"
	configschema "github.com/conductorone/baton-sdk/pkg/config"
)

var version = "dev"

func main() {
	ctx := context.Background()
	_, cmd, err := configschema.DefineConfiguration(ctx, "baton-okta-aws-federation", getConnector, configuration)
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	cmd.Version = version
	err = cmd.Execute()
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}

func getConnector(ctx context.Context, v *viper.Viper) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)
	ccfg := &connector.Config{
		Domain:                v.GetString("domain"),
		ApiToken:              v.GetString("api-token"),
		OktaProvisioning:      v.GetBool("okta-provisioning"),
		Cache:                 v.GetBool("cache"),
		CacheTTI:              v.GetInt32("cache-tti"),
		CacheTTL:              v.GetInt32("cache-ttl"),
		SyncCustomRoles:       v.GetBool("sync-custom-roles"),
		SkipSecondaryEmails:   v.GetBool("skip-secondary-emails"),
		AWSOktaAppId:          v.GetString("aws-okta-app-id"),
		AWSSourceIdentityMode: v.GetBool("aws-source-identity-mode"),
		AllowGroupToDirectAssignmentConversionForProvisioning: v.GetBool("aws-allow-group-to-direct-assignment-conversion-for-provisioning"),
	}

	cb, err := connector.New(ctx, ccfg)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	connector, err := connectorbuilder.NewConnector(ctx, cb)
	if err != nil {
		l.Error("error creating connector", zap.Error(err))
		return nil, err
	}

	return connector, nil
}
