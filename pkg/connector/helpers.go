package connector

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	oktav5 "github.com/conductorone/okta-sdk-golang/v5/okta"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

const ContentType = "application/json"

type responseContextV5 struct {
	OktaResponse *oktav5.APIResponse
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

func handleOktaResponseErrorV5(ctx context.Context, resp *oktav5.APIResponse, err error) error {
	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		if urlErr.Timeout() {
			return status.Error(codes.DeadlineExceeded, fmt.Sprintf("request timeout: %v", urlErr.URL))
		}
	} else if errors.Is(err, context.DeadlineExceeded) {
		return status.Error(codes.DeadlineExceeded, "request timeout")
	}

	if resp != nil && resp.Response != nil {
		// Do some more error translation here.
		code := codes.Unknown
		switch resp.StatusCode {
		case http.StatusNotFound:
			code = codes.NotFound
		case http.StatusUnauthorized:
			code = codes.Unauthenticated
		case http.StatusForbidden:
			code = codes.PermissionDenied
		case http.StatusConflict:
			code = codes.AlreadyExists
		case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
			code = codes.Unavailable
		case http.StatusRequestTimeout:
			code = codes.DeadlineExceeded
		default:
			if resp.StatusCode >= http.StatusInternalServerError {
				code = codes.Unavailable // Transient - retry
			}
		}

		return uhttp.WrapErrorsWithRateLimitInfo(code, resp.Response)
	}

	return err
}
