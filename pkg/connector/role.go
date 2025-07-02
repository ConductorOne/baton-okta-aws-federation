package connector

import (
	"context"

	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

const (
	apiPathListAdministrators = "/api/internal/administrators"
	ContentType               = "application/json"
	NF                        = -1
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
