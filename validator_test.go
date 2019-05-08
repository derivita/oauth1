package oauth1

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func makeValues(m map[string]string) url.Values {
	values := make(url.Values)
	for k, v := range m {
		values.Set(k, v)
	}
	return values
}

func makeRequest(method, url, authHeader string, values url.Values) *http.Request {
	req := httptest.NewRequest(method, url, strings.NewReader(values.Encode()))
	if authHeader != "" {
		req.Header.Set(authorizationHeaderParam, authHeader)
	}
	req.Header.Set(contentType, formContentType)
	return req
}

func TestNewProviderRequest_ParamSources(t *testing.T) {
	expectedParams := map[string]string{
		"oauth_consumer_key":     "some_client",
		"oauth_signature":        "sig",
		"oauth_nonce":            "a_nonce",
		"oauth_timestamp":        "1",
		"oauth_signature_method": "HMAC-SHA1",
	}
	expectedValues := makeValues(expectedParams)
	url := "https://example.com/oauth1"
	queryReq := makeRequest("GET", url+"?"+expectedValues.Encode(), "", nil)
	bodyReq := makeRequest("POST", url, "", expectedValues)
	headerReq := makeRequest("GET", url, authHeaderValue(expectedParams), nil)

	delete(expectedParams, "oauth_signature")

	for i, req := range []*http.Request{queryReq, bodyReq, headerReq} {
		preq, err := newProviderRequest(req)
		assert.NoError(t, err, i)
		assert.Equal(t, expectedParams, preq.oauthParams, i)
		assert.Same(t, req, preq.req, i)
		assert.Equal(t, preq.signatureToVerify, "sig", i)
		assert.Equal(t, preq.signatureMethod, "HMAC-SHA1", i)
		assert.Equal(t, preq.nonce, "a_nonce", i)
		assert.Equal(t, preq.timestamp, int64(1), i)
		assert.Equal(t, preq.clientKey, "some_client", i)

	}
}

func TestNewProviderRequest_CombinedParams(t *testing.T) {
	req := makeRequest("POST", "https://example.com/oauth?query=1", "OAUTH header=\"1\"", makeValues(map[string]string{
		"body":                   "1",
		"oauth_consumer_key":     "some_client",
		"oauth_signature":        "sig",
		"oauth_nonce":            "a_nonce",
		"oauth_timestamp":        "1",
		"oauth_signature_method": "HMAC-SHA1",
	}))
	preq, err := newProviderRequest(req)
	assert.Nil(t, err)
	assert.Equal(t, map[string]string{
		"header":                 "1",
		"query":                  "1",
		"body":                   "1",
		"oauth_consumer_key":     "some_client",
		"oauth_nonce":            "a_nonce",
		"oauth_timestamp":        "1",
		"oauth_signature_method": "HMAC-SHA1",
	}, preq.oauthParams)
}

func TestNewProviderRequest_InvalidAuthHeader(t *testing.T) {
	req := makeRequest("POST", "https://example.com/oauth", "OAUTH thisisn'tvalid", makeValues(map[string]string{
		"oauth_consumer_key":     "some_client",
		"oauth_signature":        "sig",
		"oauth_nonce":            "a_nonce",
		"oauth_timestamp":        "1",
		"oauth_signature_method": "HMAC-SHA1",
	}))
	_, err := newProviderRequest(req)
	assert.NotNil(t, err)
}

func TestNewProviderRequest_OtherAuthHeader(t *testing.T) {
	req := makeRequest("POST", "https://example.com/oauth", "bearer foobar", makeValues(map[string]string{
		"oauth_consumer_key":     "some_client",
		"oauth_signature":        "sig",
		"oauth_nonce":            "a_nonce",
		"oauth_timestamp":        "1",
		"oauth_signature_method": "HMAC-SHA1",
	}))
	_, err := newProviderRequest(req)
	assert.Nil(t, err)
}

func TestNewProviderRequest_MissingParams(t *testing.T) {
	for _, param := range []string{"oauth_consumer_key", "oauth_signature", "oauth_nonce", "oauth_timestamp", "oauth_signature_method"} {
		params := map[string]string{
			"oauth_consumer_key":     "some_client",
			"oauth_signature":        "sig",
			"oauth_nonce":            "a_nonce",
			"oauth_timestamp":        "1",
			"oauth_signature_method": "HMAC-SHA1",
		}
		delete(params, param)
		_, err := newProviderRequest(makeRequest("POST", "https://example.com", "", makeValues(params)))
		assert.NotNil(t, err, param)
		assert.Contains(t, err.Error(), param)
	}

}

func TestCheckSignature_ValidSignature(t *testing.T) {
	config := &Config{ConsumerKey: "consumer_key", ConsumerSecret: "consumer_secret"}
	a := newAuther(config)

	req := makeRequest("POST", "https://example.com/foo?q=bar", "", makeValues(map[string]string{"data": "something"}))
	err := a.setRequestAuthHeader(req, nil)
	assert.NoError(t, err)
	preq, err := newProviderRequest(req)
	assert.NoError(t, err)
	assert.NoError(t, preq.checkSignature(a.signer()))
}

func TestCheckSignature_InvalidSignature(t *testing.T) {
	tests := []struct{ orig, modified *http.Request }{
		{
			// Change method
			makeRequest("POST", "https://example.com/foo?q=bar", "", makeValues(map[string]string{"data": "something"})),
			makeRequest("PUT", "https://example.com/foo?q=bar", "", makeValues(map[string]string{"data": "something"})),
		},
		{
			// Change body params
			makeRequest("POST", "https://example.com/foo?q=bar", "", makeValues(map[string]string{"data": "something"})),
			makeRequest("POST", "https://example.com/foo?q=bar", "", makeValues(map[string]string{"data": "nothing"})),
		},
		{
			// Change query params
			makeRequest("GET", "https://example.com/foo?q=bar", "", nil),
			makeRequest("GET", "https://example.com/foo?q=flowers", "", nil),
		},
	}
	a := &auther{
		&Config{ConsumerKey: "consumer_key", ConsumerSecret: "secret"},
		&fixedClock{time.Unix(50037133, 0)},
		&fixedNoncer{"some_nonce"},
	}
	for i, test := range tests {
		assert.NoError(t, a.setRequestAuthHeader(test.orig, nil))
		test.modified.Header[authorizationHeaderParam] = test.orig.Header[authorizationHeaderParam]
		preq, err := newProviderRequest(test.modified)
		assert.NoError(t, err, i)
		err = preq.checkSignature(a.signer())
		if assert.Error(t, err, i) {
			assert.Equal(t, errSignatureMismatch, err, i)
		}
	}
}

func TestCheckSignature_ReversedSignature(t *testing.T) {
	config := &Config{ConsumerKey: "consumer_key", ConsumerSecret: "consumer_secret"}
	a := newAuther(config)

	req := makeRequest("GET", "https://example.com/foo?q=bar", "", nil)
	err := a.setRequestAuthHeader(req, nil)
	assert.NoError(t, err)
	preq, err := newProviderRequest(req)
	assert.NoError(t, err)

	origSig := preq.signatureToVerify
	reversedSig := ""
	for _, v := range origSig {
		reversedSig = string(v) + reversedSig
	}
	preq.signatureToVerify = reversedSig

	err = preq.checkSignature(a.signer())
	if assert.Error(t, err) {
		assert.Equal(t, errSignatureMismatch, err)
	}
}

func TestNewProviderRequest_TimestampParsing(t *testing.T) {
	params := map[string]string{
		"oauth_consumer_key":     "some_client",
		"oauth_signature":        "sig",
		"oauth_nonce":            "a_nonce",
		"oauth_timestamp":        "-1",
		"oauth_signature_method": "HMAC-SHA1",
	}
	_, err := newProviderRequest(makeRequest("POST", "https://example.com", "", makeValues(params)))
	assert.NotNil(t, err)
	params["oauth_timestamp"] = "0"
	_, err = newProviderRequest(makeRequest("POST", "https://example.com", "", makeValues(params)))
	assert.NotNil(t, err)
	params["oauth_timestamp"] = "17"
	req, err := newProviderRequest(makeRequest("POST", "https://example.com", "", makeValues(params)))
	assert.Nil(t, err)
	assert.Equal(t, req.timestamp, int64(17))
}

type mockStorage struct {
	// outputs
	Signer    Signer
	SignerErr error
	NonceErr  error

	// Saved inputs
	SignerContext   context.Context
	SignerKey       string
	SignatureMethod string
	SignerRequest   *http.Request

	NonceContext context.Context
	NonceKey     string
	Nonce        string
	Timestamp    int64
	NonceRequest *http.Request
}

func (m *mockStorage) GetSigner(ctx context.Context, key, method string, req *http.Request) (Signer, error) {
	m.SignerContext = ctx
	m.SignerKey = key
	m.SignatureMethod = method
	m.SignerRequest = req
	return m.Signer, m.SignerErr
}

func (m *mockStorage) ValidateNonce(ctx context.Context, key, nonce string, timestamp int64, req *http.Request) error {
	m.NonceContext = ctx
	m.NonceKey = key
	m.Nonce = nonce
	m.Timestamp = timestamp
	m.NonceRequest = req
	return m.NonceErr
}

func TestValidateSignature_ClientStorageArgs(t *testing.T) {
	req := makeRequest("GET", "https://example.com/foo?q=bar", "", nil)
	a := &auther{
		&Config{ConsumerKey: "consumer_key", ConsumerSecret: "secret", Signer: &identitySigner{}},
		&fixedClock{time.Unix(50037133, 0)},
		&fixedNoncer{"some_nonce"},
	}
	err := a.setRequestAuthHeader(req, nil)
	assert.NoError(t, err)

	storage := &mockStorage{Signer: &identitySigner{}}
	assert.NoError(t, ValidateSignature(NoContext, req, storage))
	assert.Equal(t, "consumer_key", storage.SignerKey)
	assert.Equal(t, "identity", storage.SignatureMethod)
	assert.Same(t, req, storage.SignerRequest)

	assert.Same(t, NoContext, storage.NonceContext)
	assert.Equal(t, "consumer_key", storage.NonceKey)
	assert.Equal(t, "some_nonce", storage.Nonce)
	assert.EqualValues(t, 50037133, storage.Timestamp)
	assert.Same(t, req, storage.NonceRequest)
}
func TestValidateSignature_BadNonceOrTimestamp(t *testing.T) {
	req := makeRequest("GET", "https://example.com/foo?q=bar", "", nil)
	a := &auther{
		&Config{ConsumerKey: "consumer_key", ConsumerSecret: "secret", Signer: &identitySigner{}},
		&fixedClock{time.Unix(50037133, 0)},
		&fixedNoncer{"some_nonce"},
	}
	err := a.setRequestAuthHeader(req, nil)
	assert.NoError(t, err)

	storage := &mockStorage{NonceErr: fmt.Errorf("i don't like your nonce")}
	err = ValidateSignature(NoContext, req, storage)
	if assert.Error(t, err) {
		assert.Equal(t, storage.NonceErr, err)
	}
}
func TestValidateSignature_BadClientKey(t *testing.T) {
	req := makeRequest("GET", "https://example.com/foo?q=bar", "", nil)
	a := &auther{
		&Config{ConsumerKey: "consumer_key", ConsumerSecret: "secret", Signer: &identitySigner{}},
		&fixedClock{time.Unix(50037133, 0)},
		&fixedNoncer{"some_nonce"},
	}
	err := a.setRequestAuthHeader(req, nil)
	assert.NoError(t, err)

	storage := &mockStorage{SignerErr: fmt.Errorf("i don't like your key")}
	err = ValidateSignature(NoContext, req, storage)
	if assert.Error(t, err) {
		assert.Equal(t, storage.SignerErr, err)
	}
}

type countingSigner struct {
	count int
}

func (c *countingSigner) Name() string { return "count" }
func (c *countingSigner) Sign(tokenSecret, message string) (string, error) {
	c.count++
	return strconv.Itoa(c.count), nil
}

func TestValidateSignature_SignerCalledOnBadKey(t *testing.T) {
	req := makeRequest("GET", "https://example.com/foo?q=bar", "", nil)
	a := &auther{
		&Config{ConsumerKey: "consumer_key", ConsumerSecret: "secret", Signer: &identitySigner{}},
		&fixedClock{time.Unix(50037133, 0)},
		&fixedNoncer{"some_nonce"},
	}
	err := a.setRequestAuthHeader(req, nil)
	assert.NoError(t, err)

	signer := &countingSigner{}
	storage := &mockStorage{Signer: signer, SignerErr: fmt.Errorf("i don't like your key")}
	err = ValidateSignature(NoContext, req, storage)
	if assert.Error(t, err) {
		assert.Equal(t, storage.SignerErr, err)
	}
	assert.Equal(t, 1, signer.count)
}

func TestValidSignature_ValidSignature(t *testing.T) {
	config := &Config{ConsumerKey: "consumer_key", ConsumerSecret: "consumer_secret"}
	a := newAuther(config)

	req := makeRequest("POST", "https://example.com/foo?q=bar", "", makeValues(map[string]string{"data": "something"}))
	err := a.setRequestAuthHeader(req, nil)
	assert.NoError(t, err)

	storage := &mockStorage{Signer: a.signer()}
	assert.NoError(t, ValidateSignature(NoContext, req, storage))
}

func TestValidSignature_InvalidSecret(t *testing.T) {
	config := &Config{ConsumerKey: "consumer_key", ConsumerSecret: "consumer_secret"}
	a := newAuther(config)

	req := makeRequest("POST", "https://example.com/foo?q=bar", "", makeValues(map[string]string{"data": "something"}))
	err := a.setRequestAuthHeader(req, nil)
	assert.NoError(t, err)

	storage := &mockStorage{Signer: &HMACSigner{ConsumerSecret: "another_secret"}}
	err = ValidateSignature(NoContext, req, storage)
	if assert.Error(t, err) {
		assert.Equal(t, errSignatureMismatch, err)
	}
}
