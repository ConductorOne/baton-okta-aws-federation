package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"

	"github.com/conductorone/baton-sdk/pkg/pagination"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
	"github.com/okta/okta-sdk-golang/v2/okta"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const ContentType = "application/json"

type responseContext struct {
	OktaResponse *okta.Response
}

type responseContextV5 struct {
	OktaResponse *oktav5.APIResponse
}

func responseToContext(token *pagination.Token, resp *okta.Response) (*responseContext, error) {
	u, err := url.Parse(resp.NextPage)
	if err != nil {
		return nil, err
	}

	after := u.Query().Get("after")
	token.Token = after

	return &responseContext{
		OktaResponse: resp,
	}, nil
}

func responseToContextV5(token *pagination.Token, resp *oktav5.APIResponse) (*responseContextV5, error) {
	u, err := url.Parse(resp.NextPage())
	if err != nil {
		return nil, err
	}

	after := u.Query().Get("after")
	token.Token = after

	return &responseContextV5{
		OktaResponse: resp,
	}, nil
}

func getError(response *okta.Response) (okta.Error, error) {
	var errOkta okta.Error
	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return okta.Error{}, err
	}

	err = json.Unmarshal(bytes, &errOkta)
	if err != nil {
		return okta.Error{}, err
	}

	return errOkta, nil
}

func getErrorV5(response *oktav5.APIResponse) (oktav5.Error, error) {
	var errOkta oktav5.Error
	bytes, err := io.ReadAll(response.Body)
	if err != nil {
		return oktav5.Error{}, err
	}

	err = json.Unmarshal(bytes, &errOkta)
	if err != nil {
		return oktav5.Error{}, err
	}

	return errOkta, nil
}

func handleOktaResponseErrorV5(resp *oktav5.APIResponse, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return status.Error(codes.DeadlineExceeded, fmt.Sprintf("request timeout: %v", urlErr.URL))
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "request timeout")
	}
	if resp != nil && resp.StatusCode >= 500 {
		return status.Error(codes.Unavailable, "server error")
	}
	return err
}
