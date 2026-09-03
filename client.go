package anubis

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Connect procedure routes. Connect derives these from the proto package and
// service name, so they change only if the proto does.
const (
	procLogin             = "/anubis.v1.AuthService/Login"
	procVerifyMfa         = "/anubis.v1.AuthService/VerifyMfa"
	procRefresh           = "/anubis.v1.AuthService/Refresh"
	procLogout            = "/anubis.v1.AuthService/Logout"
	procLogoutAll         = "/anubis.v1.AuthService/LogoutAll"
	procLogoutSession     = "/anubis.v1.AuthService/LogoutSession"
	procClientCredentials = "/anubis.v1.AuthService/ClientCredentials"
	procAuthorize         = "/anubis.v1.AuthzService/Authorize"
	procExplain           = "/anubis.v1.AuthzService/Explain"
	procSwitchScope       = "/anubis.v1.AuthzService/SwitchScope"
	procIntrospect        = "/anubis.v1.TokenService/Introspect"
	procRevoke            = "/anubis.v1.TokenService/Revoke"
	procGetMe             = "/anubis.v1.SessionService/GetMe"
	procListSessions      = "/anubis.v1.SessionService/ListSessions"
	procRevokeSession     = "/anubis.v1.SessionService/RevokeSession"
)

// Browser-facing HTTP paths. These are not Connect procedures: they are the
// OIDC-shaped flows a browser walks through, and they speak form encoding and
// snake_case JSON rather than Connect's camelCase.
const (
	pathAuthorize = "/v1/authorize"
	pathToken     = "/v1/token"
	pathLogout    = "/v1/logout"
)

// maxResponseBytes bounds what a single response may cost in memory. Anubis's
// largest ordinary answer is an explanation tree; anything approaching this is
// a proxy error page, not Anubis.
const maxResponseBytes = 4 << 20

// Client talks to an Anubis installation. Safe for concurrent use.
//
// It is the cold half of the SDK: sign-in, refresh, decisions, introspection.
// Verifying a token on the request path needs a Verifier instead, and needs no
// Client at all — see NewVerifier.
type Client struct {
	baseURL string
	opts    options
}

// New builds a client for the Anubis installation at baseURL.
//
// baseURL is the installation's origin — "https://anubis.internal" — not a
// path to a procedure. It must be https anywhere a browser is involved:
// __Host- cookies require it, so plain http breaks sign-in rather than merely
// weakening it.
func New(baseURL string, opts ...Option) (*Client, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("anubis: base url %q must be an absolute origin like https://anubis.internal", baseURL)
	}
	if u.Scheme != "https" && u.Hostname() != "localhost" && u.Hostname() != "127.0.0.1" {
		return nil, fmt.Errorf("anubis: base url %q must be https (browser sign-in needs it, and a credential does too)", baseURL)
	}
	o, err := newOptions(opts)
	if err != nil {
		return nil, err
	}
	return &Client{baseURL: strings.TrimRight(baseURL, "/"), opts: o}, nil
}

// Call invokes a Connect procedure this SDK does not wrap.
//
// The escape hatch. `in` is marshalled as the request body and `out` is
// unmarshalled from the response, with the same credential, headers, timeout
// and error classification every other call gets — so a procedure reached this
// way still refuses in the SDK's vocabulary rather than as a bare HTTP status.
//
// Procedure is the Connect route, leading slash included:
// "/anubis.v1.AuthzAdminService/ListGrants". Remember that responses come back
// in protojson's lowerCamelCase and that int64 fields arrive as JSON strings.
func (c *Client) Call(ctx context.Context, procedure string, in, out any) error {
	if !strings.HasPrefix(procedure, "/") {
		return fmt.Errorf("anubis: procedure %q must start with a slash", procedure)
	}
	return c.rpc(ctx, procedure, in, out)
}

// rpc calls a Connect procedure with a JSON body.
//
// Request fields are sent with their proto names (snake_case). protojson
// accepts those as well as lowerCamelCase, and they are what the API
// documentation shows, so a body copied from the docs and a body built here
// are the same body.
func (c *Client) rpc(ctx context.Context, procedure string, in, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return fmt.Errorf("anubis: encoding %s request: %w", procedure, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+procedure, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if err := c.attachCredential(ctx, req); err != nil {
		return err
	}
	return c.do(req, out)
}

// form posts to one of the browser-facing HTTP endpoints, which are
// form-encoded and answer in snake_case JSON.
func (c *Client) form(ctx context.Context, path string, values url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return c.do(req, out)
}

func (c *Client) do(req *http.Request, out any) error {
	for name, value := range c.opts.headers {
		req.Header.Set(name, value)
	}
	if c.opts.tenant != "" {
		req.Header.Set("X-Anubis-Tenant", c.opts.tenant)
	}
	resp, err := c.opts.httpClient.Do(req)
	if err != nil {
		// A transport failure is indistinguishable from an installation that
		// is down, and both are retryable, so both get the same type.
		return &UnavailableError{err: err}
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return &UnavailableError{err: fmt.Errorf("anubis: reading response: %w", err)}
	}
	if resp.StatusCode != http.StatusOK {
		return classify(parseWireError(raw, resp.StatusCode), resp.Header)
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("anubis: decoding response: %w", err)
	}
	return nil
}

// attachCredential attaches the caller's credential.
//
// Order matters and is deliberate. A configured API key is the application's
// own stable identity and is what a trusted back end should present. Falling
// back to the verified principal's own token lets a service forward the
// caller's authority without holding a key of its own — but it is a fallback,
// because a service that silently switches identity depending on whether a
// user happens to be present writes an audit trail nobody can read.
func (c *Client) attachCredential(ctx context.Context, req *http.Request) error {
	if c.opts.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.opts.apiKey)
		return nil
	}
	if p, ok := FromContext(ctx); ok && p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.Token)
		return nil
	}
	return ErrNoCredential
}

// ---- error decoding -------------------------------------------------------

// wireError covers both shapes Anubis answers with: the Connect error object
// ({"code","message","details":[…]}) and the plain-HTTP envelope
// ({"error","message","request_id","details":{…}}). One vocabulary, two
// transports — but not, unfortunately, one field name for the code.
type wireError struct {
	Code      string          `json:"code"`
	Error     string          `json:"error"`
	Message   string          `json:"message"`
	RequestID string          `json:"request_id"`
	Details   json.RawMessage `json:"details"`
}

type connectDetail struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func parseWireError(raw []byte, status int) *APIError {
	out := &APIError{Status: status}
	var w wireError
	if err := json.Unmarshal(raw, &w); err != nil {
		// Not JSON at all: a proxy error page. Say so rather than pretending
		// to have a code, so classify falls back to the HTTP status.
		out.Message = strings.TrimSpace(string(raw))
		if len(out.Message) > 512 {
			out.Message = out.Message[:512]
		}
		return out
	}
	out.Message, out.RequestID = w.Message, w.RequestID
	out.Code = firstNonEmpty(w.Error, w.Code)

	if len(w.Details) > 0 {
		// HTTP envelope: details is an object of strings.
		var m map[string]string
		if json.Unmarshal(w.Details, &m) == nil {
			out.Details = m
		} else {
			// Connect: details is an array of Any-shaped objects. The stable
			// code lives in an anubis.v1.ErrorInfo, base64 protobuf, because
			// Connect has nowhere else to put a domain code — its own `code`
			// field only carries the coarse transport class.
			var ds []connectDetail
			if json.Unmarshal(w.Details, &ds) == nil {
				for _, d := range ds {
					if !strings.HasSuffix(d.Type, "ErrorInfo") {
						continue
					}
					if info, err := decodeErrorInfo(d.Value); err == nil {
						out.Code = firstNonEmpty(info.code, out.Code)
						out.RequestID = firstNonEmpty(info.requestID, out.RequestID)
						out.Details = info.details
					}
				}
			}
		}
	}
	return out
}

type errorInfo struct {
	code      string
	requestID string
	details   map[string]string
}

// decodeErrorInfo reads anubis.v1.ErrorInfo straight off the protobuf wire.
//
// Depending on a protobuf runtime to read three fields would cost every
// consumer of this package the entire google.golang.org/protobuf tree, and the
// whole point of the offline half is that it costs them nothing. The message
// is three fields and will not grow a fourth without a proto change that this
// function's tests would catch.
//
//	string code = 1; string request_id = 2; map<string,string> details = 3;
func decodeErrorInfo(b64 string) (errorInfo, error) {
	var info errorInfo
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		// Connect writes standard base64; tolerate the url alphabet anyway,
		// since a proxy that re-encodes is likelier than a spec change.
		raw, err = base64.RawURLEncoding.DecodeString(b64)
		if err != nil {
			return info, err
		}
	}
	for len(raw) > 0 {
		field, payload, rest, err := nextProtoField(raw)
		if err != nil {
			return info, err
		}
		raw = rest
		switch field {
		case 1:
			info.code = string(payload)
		case 2:
			info.requestID = string(payload)
		case 3:
			k, v := decodeMapEntry(payload)
			if k != "" {
				if info.details == nil {
					info.details = map[string]string{}
				}
				info.details[k] = v
			}
		}
	}
	return info, nil
}

// nextProtoField reads one length-delimited field. Every field of ErrorInfo is
// length-delimited; anything else is a message this function does not know and
// must skip without guessing at its length, so it stops.
func nextProtoField(b []byte) (field int, payload, rest []byte, err error) {
	tag, n := binary.Uvarint(b)
	if n <= 0 {
		return 0, nil, nil, errors.New("anubis: truncated ErrorInfo tag")
	}
	if wire := tag & 7; wire != 2 {
		return 0, nil, nil, fmt.Errorf("anubis: unexpected ErrorInfo wire type %d", wire)
	}
	b = b[n:]
	size, n := binary.Uvarint(b)
	if n <= 0 || size > uint64(len(b[n:])) {
		return 0, nil, nil, errors.New("anubis: truncated ErrorInfo field")
	}
	b = b[n:]
	return int(tag >> 3), b[:size], b[size:], nil
}

// decodeMapEntry reads a protobuf map entry: key is field 1, value is field 2.
func decodeMapEntry(b []byte) (key, value string) {
	for len(b) > 0 {
		field, payload, rest, err := nextProtoField(b)
		if err != nil {
			return key, value
		}
		b = rest
		switch field {
		case 1:
			key = string(payload)
		case 2:
			value = string(payload)
		}
	}
	return key, value
}

// ---- small shared types ---------------------------------------------------

// pbInt64 decodes a proto int64, which protojson renders as a JSON *string*
// because a JSON number cannot hold the range. Accepting both spellings means
// the same struct reads a Connect response and a hand-written HTTP one.
type pbInt64 int64

func (v *pbInt64) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == `""` || s == "" {
		*v = 0
		return nil
	}
	s = strings.Trim(s, `"`)
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("anubis: %q is not an int64: %w", s, err)
	}
	*v = pbInt64(n)
	return nil
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// jsonBody encodes a value for a request body, deferring the error to the
// transport so callers get one error path rather than two.
func jsonBody(v any) io.Reader {
	raw, err := json.Marshal(v)
	if err != nil {
		return errReader{err}
	}
	return bytes.NewReader(raw)
}

type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }
