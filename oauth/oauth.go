package oauth

import (
	"encoding/json"
	"fmt"
	"github.com/mercadolibre/golang-restclient/rest"
	"github.com/sunil206b/store_utils_go/errors"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"
	paramAccessToken = "access_token"
)

var (
	oauthRestClient = rest.RequestBuilder{
		BaseURL: "http://localhost:8081",
		Timeout: 200 * time.Millisecond,
	}
)
type accessToken struct {
	AccessToken string `json:"access_token"`
	UserId int64 `json:"user_id"`
	ClientId int64 `json:"client_id"`
	Expires int64 `json:"expires"`
}

func GetCallerId(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(req.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(req.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(req *http.Request) *errors.RestErr {
	if req == nil {
		return nil
	}
	cleanRequest(req)
	accessTokenId := strings.TrimSpace(req.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(accessTokenId)
	if err != nil {
		if err.StatusCode == http.StatusNotFound {
			return nil
		}
		return err
	}
	req.Header.Add(headerXCallerId, strconv.FormatInt(at.UserId, 10))
	req.Header.Add(headerXClientId, strconv.FormatInt(at.ClientId, 10))
	return nil
}

func cleanRequest(req *http.Request) {
	if req == nil {
		return
	}
	req.Header.Del(headerXClientId)
	req.Header.Del(headerXCallerId)
}

func getAccessToken(accessTokenId string) (*accessToken, *errors.RestErr) {
	res := oauthRestClient.Get(fmt.Sprintf("/login/access_token/%s", accessTokenId))
	if res.StatusCode > 299 {
		var errMsg errors.RestErr
		if err := json.Unmarshal(res.Bytes(), &errMsg); err != nil {
			return nil, errors.NewAuthenticationError("invalid error interface when trying to get access token")
		}
		return nil, &errMsg
	}

	var at accessToken
	if err := json.Unmarshal(res.Bytes(), &at); err != nil {
		return nil, errors.NewAuthenticationError("error when trying to unmarshal access token")
	}
	return &at, nil
}
