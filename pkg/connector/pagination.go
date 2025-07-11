package connector

import (
	"net/url"

	"github.com/conductorone/baton-sdk/pkg/ratelimit"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/okta/okta-sdk-golang/v2/okta"
)

const defaultLimit = 1000

func parseGetResp(resp *okta.Response) (annotations.Annotations, error) {
	var annos annotations.Annotations
	if resp != nil {
		if desc, err := ratelimit.ExtractRateLimitData(resp.Response.StatusCode, &resp.Response.Header); err == nil {
			annos.WithRateLimiting(desc)
		}
	}
	return annos, nil
}

func parseResp(resp *okta.Response) (string, annotations.Annotations, error) {
	var annos annotations.Annotations
	var nextPage string

	if resp != nil {
		u, err := url.Parse(resp.NextPage)
		if err != nil {
			return "", nil, err
		}
		after := u.Query().Get("after")

		if desc, err := ratelimit.ExtractRateLimitData(resp.Response.StatusCode, &resp.Response.Header); err == nil {
			annos.WithRateLimiting(desc)
		}
		nextPage = after
	}

	return nextPage, annos, nil
}

func parsePageToken(token string, resourceID *v2.ResourceId) (*pagination.Bag, string, error) {
	b := &pagination.Bag{}
	err := b.Unmarshal(token)
	if err != nil {
		return nil, "", err
	}

	if b.Current() == nil {
		b.Push(pagination.PageState{
			ResourceTypeID: resourceID.ResourceType,
			ResourceID:     resourceID.Resource,
		})
	}

	page := b.PageToken()

	return b, page, nil
}

func newPaginationToken(limit int, nextPageToken string) *pagination.Token {
	if limit == 0 || limit > defaultLimit {
		limit = defaultLimit
	}

	return &pagination.Token{
		Size:  limit,
		Token: nextPageToken,
	}
}
