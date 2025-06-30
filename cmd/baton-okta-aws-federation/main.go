package main

import (
	"context"
	"fmt"
	"os"

	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/types"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	"github.com/conductorone/baton-okta-aws-federation/pkg/config"
	"github.com/conductorone/baton-okta-aws-federation/pkg/connector"
	configschema "github.com/conductorone/baton-sdk/pkg/config"
)

var version = "dev"

func main() {
	ctx := context.Background()
	_, cmd, err := configschema.DefineConfiguration(ctx, "baton-okta-aws-federation", getConnector, config.Config)
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

// safeCacheInt32 converts int to int32 with bounds checking.
func safeCacheInt32(val int) (int32, error) {
	if val > 2147483647 || val < 0 {
		return 0, fmt.Errorf("value %d is out of range for int32", val)
	}
	return int32(val), nil
}

func getConnector(ctx context.Context, oaf *config.OktaAwsFederation) (types.ConnectorServer, error) {
	l := ctxzap.Extract(ctx)

	cacheTTI, err := safeCacheInt32(oaf.CacheTti)
	if err != nil {
		return nil, err
	}

	cacheTTL, err := safeCacheInt32(oaf.CacheTtl)
	if err != nil {
		return nil, err
	}

	ccfg := &connector.Config{
		Domain:                oaf.Domain,
		ApiToken:              oaf.ApiToken,
		Cache:                 oaf.Cache,
		CacheTTI:              cacheTTI,
		CacheTTL:              cacheTTL,
		SkipSecondaryEmails:   oaf.SkipSecondaryEmails,
		AWSOktaAppId:          oaf.AwsOktaAppId,
		AWSSourceIdentityMode: oaf.AwsSourceIdentityMode,
		AllowGroupToDirectAssignmentConversionForProvisioning: oaf.AwsAllowGroupToDirectAssignmentConversionForProvisioning,
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
