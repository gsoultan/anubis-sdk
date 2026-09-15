// Package anubistest runs an in-process Anubis good enough to develop and test
// an integration against.
//
// It signs real v4.public tokens with a real Ed25519 key, serves a real key
// document, and answers the procedures this SDK calls with the real wire
// shapes — including protojson's camelCase and its habit of rendering int64 as
// a string, and Connect's base64-protobuf error details. A fake that answered
// in a friendlier dialect than the server would let exactly the bugs that
// matter through.
//
// It is a separate package so it never links into a production binary.
package anubistest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	anubis "github.com/gsoultan/anubis-sdk"
	"github.com/gsoultan/anubis-sdk/paseto"
)

// Kid is the key id every token this server signs carries in its footer.
const Kid = "test-key-1"

// Server is a fake Anubis listening on a local address.
type Server struct {
	URL    string
	Issuer string

	t      testing.TB
	http   *httptest.Server
	public ed25519.PublicKey
	secret ed25519.PrivateKey

	mu sync.Mutex
	// decisions maps "subject|permission" to the answer Authorize gives. The
	// key is a plain string because it is an index, not a domain value.
	decisions map[string]anubis.Decision
	// liveRefresh is the refresh token currently valid for a session; a
	// presentation of anything else that was ever issued is reuse.
	liveRefresh map[string]string
	issued      map[string]string // refresh token -> session id
	consumed    map[string]bool
	codes       map[string]authCode
	grants      map[anubis.SubjectID][]GrantRow
	scopeNodes  []ScopeNodeRow
	// scopeNodePage is the ListScopeNodes page size. An axis is paged because
	// a real one can hold hundreds of thousands of nodes, and a fake that
	// answers every listing in one page hides a client that never pages.
	scopeNodePage int
	platformKey   string
	// The configuration half of the admin plane.
	catalogSources map[string]*CatalogSourceRow
	catalogRuns    map[string][]map[string]any
	syncSources    map[string]*SyncSourceRow
	authPages      map[string]*AuthPageRow
	// manifests is the installed catalog per application slug.
	manifests map[string]*manifestApp
	// Provisioning.
	tenants         map[string]*TenantRow
	realms          map[string]*realmRow
	applications    map[string]*ApplicationRow
	apiKeys         map[string]*apiKeyRow
	applicationPage int
	// seq names things the fake creates: cat_1, run_2.
	seq int
	// Calls counts procedure hits, so a test can assert that concurrent
	// callers produced exactly one refresh.
	Calls map[string]int

	// lastAsk records what the most recent Authorize call carried, so a test
	// can assert the axes a caller supplied rather than only the answer it
	// got back. A client that silently drops an axis still gets a decision;
	// only the request shows the bug.
	lastAsk Ask

	// RefreshDelay slows the refresh procedure. A single-flight test needs
	// the window to be wide enough for contenders to arrive during it;
	// without a delay the first caller can finish before the second starts
	// and the test passes for the wrong reason.
	RefreshDelay time.Duration
}

// Ask is one Authorize request, as it arrived.
type Ask struct {
	Subject    string
	Permission string
	Scopes     map[string]string
	AMR        []string
	AuthTime   int64
}

type authCode struct {
	challenge   string
	redirectURI string
	clientID    string
	subject     anubis.SubjectID
}

// NewServer starts a fake Anubis and stops it when the test ends.
func NewServer(t testing.TB) *Server {
	t.Helper()
	pub, sec, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("anubistest: generating a key: %v", err)
	}
	s := &Server{
		t:           t,
		public:      pub,
		secret:      sec,
		decisions:   map[string]anubis.Decision{},
		liveRefresh: map[string]string{},
		issued:      map[string]string{},
		consumed:    map[string]bool{},
		codes:       map[string]authCode{},
		grants:      map[anubis.SubjectID][]GrantRow{},
		Calls:       map[string]int{},
		// Big enough that tests which do not care about paging never meet it,
		// small enough that ScopeNodePageSize can drive it down to prove a
		// client walks pages.
		scopeNodePage: defaultScopeNodePage,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/anubis-keys.json", s.keys)
	mux.HandleFunc("/anubis.v1.AuthzService/Authorize", s.authorize)
	mux.HandleFunc("/anubis.v1.AuthzService/Explain", s.explain)
	mux.HandleFunc("/anubis.v1.AuthService/Refresh", s.refresh)
	mux.HandleFunc("/anubis.v1.AuthService/Login", s.login)
	mux.HandleFunc("/anubis.v1.AuthService/ClientCredentials", s.clientCredentials)
	mux.HandleFunc("/anubis.v1.TokenService/Introspect", s.introspect)
	mux.HandleFunc("/v1/authorize", s.browserAuthorize)
	mux.HandleFunc("/v1/token", s.tokenExchange)
	s.adminRoutes(mux)
	s.adminConfigRoutes(mux)
	s.manifestRoutes(mux)
	s.provisionRoutes(mux)

	s.http = httptest.NewServer(mux)
	s.URL = s.http.URL
	s.Issuer = s.http.URL
	t.Cleanup(s.http.Close)
	return s
}

// LastAsk returns the most recent Authorize request this server received.
func (s *Server) LastAsk() Ask {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastAsk
}

// Close stops the server. Registered with t.Cleanup already; calling it early
// is safe.
func (s *Server) Close() { s.http.Close() }

// Verifier returns a verifier configured for this server and the given
// audience — the application slug tokens are minted for.
func (s *Server) Verifier(audience string) *anubis.Verifier {
	s.t.Helper()
	v, err := anubis.NewVerifier(anubis.Config{
		Issuer:   s.Issuer,
		Audience: audience,
		KeysURL:  s.URL + "/.well-known/anubis-keys.json",
	})
	if err != nil {
		s.t.Fatalf("anubistest: building a verifier: %v", err)
	}
	return v
}

// MintToken signs an access token. Unset times are filled in with sensible
// live values so a test can name only the claims it cares about.
func (s *Server) MintToken(c anubis.Claims) string {
	s.t.Helper()
	now := time.Now()
	if c.Issuer == "" {
		c.Issuer = s.Issuer
	}
	if c.Expires == 0 {
		c.Expires = now.Add(10 * time.Minute).Unix()
	}
	if c.IssuedAt == 0 {
		c.IssuedAt = now.Unix()
	}
	if c.AuthTime == 0 {
		c.AuthTime = now.Unix()
	}
	body, err := json.Marshal(c)
	if err != nil {
		s.t.Fatalf("anubistest: encoding claims: %v", err)
	}
	footer, _ := json.Marshal(map[string]string{"kid": Kid})
	tok, err := paseto.Sign(s.secret, body, footer, nil)
	if err != nil {
		s.t.Fatalf("anubistest: signing: %v", err)
	}
	return tok
}

// MintLogoutToken signs a back-channel logout token for an audience.
func (s *Server) MintLogoutToken(audience string, subject anubis.SubjectID, sessionID anubis.SessionID) string {
	s.t.Helper()
	now := time.Now()
	body, _ := json.Marshal(map[string]any{
		"iss": s.Issuer,
		"aud": []string{audience},
		"iat": now.Unix(),
		"exp": now.Add(2 * time.Minute).Unix(),
		"jti": "jti_test",
		"sub": subject,
		"sid": sessionID,
		"events": map[string]any{
			"http://schemas.openid.net/event/backchannel-logout": map[string]any{},
		},
	})
	footer, _ := json.Marshal(map[string]string{"kid": Kid})
	tok, err := paseto.Sign(s.secret, body, footer, nil)
	if err != nil {
		s.t.Fatalf("anubistest: signing logout token: %v", err)
	}
	return tok
}

// Allow makes Authorize answer yes for this subject and permission.
func (s *Server) Allow(subject anubis.SubjectID, permission anubis.Permission) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decisions[string(subject)+"|"+string(permission)] = anubis.Decision{Allow: true}
}

// Deny makes Authorize answer no, naming the axis that failed.
func (s *Server) Deny(subject anubis.SubjectID, permission anubis.Permission, reason string, failingAxis anubis.Axis) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decisions[string(subject)+"|"+string(permission)] = anubis.Decision{
		Reason:      reason,
		FailingAxis: failingAxis,
		Message:     "no grant at or above " + string(failingAxis),
	}
}

// RequireStepUp makes Authorize answer with a step-up refusal.
func (s *Server) RequireStepUp(subject anubis.SubjectID, permission anubis.Permission, requiredAMR anubis.AuthMethods, maxAuthAge string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.decisions[string(subject)+"|"+string(permission)] = anubis.Decision{
		Reason:      "step_up_required",
		RequiredAMR: requiredAMR,
		MaxAuthAge:  maxAuthAge,
		CurrentAMR:  anubis.AuthMethods{anubis.MethodPassword},
		AuthAge:     "41m",
	}
}

// IssueSession registers a live session and returns its first token pair, as
// though a sign-in had just happened.
func (s *Server) IssueSession(subject anubis.SubjectID, audience string) anubis.Tokens {
	s.t.Helper()
	sid := anubis.SessionID("ses_" + randomID())
	access := s.MintToken(anubis.Claims{
		Subject: subject, Audience: []string{audience},
		Session: sid, Tenant: "tnt_test", AMR: anubis.AuthMethods{anubis.MethodPassword},
	})
	refresh := "anb_rt_" + randomID()
	s.mu.Lock()
	s.liveRefresh[string(sid)] = refresh
	s.issued[refresh] = string(sid)
	s.mu.Unlock()
	return anubis.Tokens{
		AccessToken: access, RefreshToken: refresh,
		TokenType: "Bearer", ExpiresIn: 600, SessionID: sid,
		IssuedAt: time.Now(),
	}
}

// ---- handlers -------------------------------------------------------------

func (s *Server) count(name string) {
	s.mu.Lock()
	s.Calls[name]++
	s.mu.Unlock()
}

func (s *Server) keys(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer": s.Issuer,
		"keys": []map[string]any{{
			"kid":        Kid,
			"alg":        "Ed25519",
			"public_key": base64.RawURLEncoding.EncodeToString(s.public),
		}},
	})
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request) {
	s.count("Authorize")
	var req struct {
		Subject    string            `json:"subject"`
		Permission string            `json:"permission"`
		Scopes     map[string]string `json:"scopes"`
		AMR        []string          `json:"amr"`
		AuthTime   int64             `json:"auth_time"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		connectError(w, http.StatusBadRequest, "invalid_argument", "bad body", "")
		return
	}
	if r.Header.Get("Authorization") == "" {
		connectError(w, http.StatusUnauthorized, "unauthenticated", "no credential", "req_test")
		return
	}
	s.mu.Lock()
	s.lastAsk = Ask{
		Subject:    req.Subject,
		Permission: req.Permission,
		Scopes:     req.Scopes,
		AMR:        req.AMR,
		AuthTime:   req.AuthTime,
	}
	d, ok := s.decisions[req.Subject+"|"+req.Permission]
	s.mu.Unlock()
	if !ok {
		d = anubis.Decision{Reason: "permission_not_held", Message: "no grant confers " + req.Permission}
	}
	// protojson spelling: the wire is camelCase, whatever the proto says.
	writeJSON(w, http.StatusOK, map[string]any{
		"allow":       d.Allow,
		"reason":      d.Reason,
		"failingAxis": string(d.FailingAxis),
		"message":     d.Message,
		"requiredAmr": d.RequiredAMR.Strings(),
		"maxAuthAge":  d.MaxAuthAge,
		"currentAmr":  d.CurrentAMR.Strings(),
		"authAge":     d.AuthAge,
	})
}

func (s *Server) explain(w http.ResponseWriter, _ *http.Request) {
	s.count("Explain")
	writeJSON(w, http.StatusOK, map[string]any{
		"allow": false, "reason": "scope_mismatch", "failingAxis": "customer",
		"detailJson": `{"gates":[]}`,
	})
}

func (s *Server) refresh(w http.ResponseWriter, r *http.Request) {
	s.count("Refresh")
	if s.RefreshDelay > 0 {
		time.Sleep(s.RefreshDelay)
	}
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)

	s.mu.Lock()
	sid, known := s.issued[req.RefreshToken]
	live := known && s.liveRefresh[sid] == req.RefreshToken
	alreadyUsed := s.consumed[req.RefreshToken]
	if live {
		s.consumed[req.RefreshToken] = true
	}
	s.mu.Unlock()

	if !known || alreadyUsed || !live {
		// The whole family dies. This is the response that must page a human.
		if known {
			s.mu.Lock()
			delete(s.liveRefresh, sid)
			s.mu.Unlock()
		}
		connectError(w, http.StatusUnauthorized, "unauthenticated",
			"Token family revoked. Re-authentication required.", "req_reuse")
		return
	}

	next := "anb_rt_" + randomID()
	s.mu.Lock()
	s.liveRefresh[sid] = next
	s.issued[next] = sid
	s.mu.Unlock()

	access := s.MintToken(anubis.Claims{
		Subject: "usr_test", Audience: []string{"billing-api"},
		Session: anubis.SessionID(sid), AMR: anubis.AuthMethods{anubis.MethodPassword},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"tokens": map[string]any{
			"accessToken": access, "refreshToken": next,
			"tokenType": "Bearer", "expiresIn": 600, "sessionId": sid,
		},
	})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	s.count("Login")
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	switch req.Username {
	case "mfa-user":
		writeJSON(w, http.StatusOK, map[string]any{
			"mfa": map[string]any{
				"mfaToken": "anb.local.v1.test", "methods": []string{"totp"}, "expiresIn": 60,
			},
		})
	case "enrol-user":
		writeJSON(w, http.StatusOK, map[string]any{
			"enrolmentRequired": map[string]any{
				"factors": []string{"totp"},
				// int64 on the wire is a STRING. A client that assumes a
				// number breaks here, which is the point of spelling it out.
				"deadline":   fmt.Sprint(time.Now().Add(-time.Hour).Unix()),
				"grantToken": "anb.local.v1.grant",
			},
		})
	case "bad-user":
		connectError(w, http.StatusUnauthorized, "unauthenticated",
			"Invalid username or password", "req_login")
	default:
		tokens := s.IssueSession("usr_test", "billing-api")
		writeJSON(w, http.StatusOK, map[string]any{
			"tokens": map[string]any{
				"accessToken": tokens.AccessToken, "refreshToken": tokens.RefreshToken,
				"tokenType": "Bearer", "expiresIn": 600, "sessionId": tokens.SessionID,
			},
		})
	}
}

func (s *Server) clientCredentials(w http.ResponseWriter, _ *http.Request) {
	s.count("ClientCredentials")
	access := s.MintToken(anubis.Claims{
		Subject: "app_billing-batch", Audience: []string{"reporting-api"},
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"accessToken": access, "tokenType": "Bearer", "expiresIn": 300,
	})
}

func (s *Server) introspect(w http.ResponseWriter, _ *http.Request) {
	s.count("Introspect")
	writeJSON(w, http.StatusOK, map[string]any{
		"active": true, "sub": "usr_test", "sid": "ses_test", "tid": "tnt_test",
		"roles": []string{"billing.clerk"}, "amr": []string{"pwd"},
		// int64 as string again, deliberately.
		"exp": fmt.Sprint(time.Now().Add(time.Minute).Unix()), "ial": 2,
	})
}

func (s *Server) browserAuthorize(w http.ResponseWriter, r *http.Request) {
	s.count("BrowserAuthorize")
	q := r.URL.Query()
	code := "code_" + randomID()
	s.mu.Lock()
	s.codes[code] = authCode{
		challenge:   q.Get("code_challenge"),
		redirectURI: q.Get("redirect_uri"),
		clientID:    q.Get("client_id"),
		subject:     "usr_test",
	}
	s.mu.Unlock()
	u, _ := url.Parse(q.Get("redirect_uri"))
	rq := u.Query()
	rq.Set("code", code)
	rq.Set("state", q.Get("state"))
	u.RawQuery = rq.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

// AuthorizeRedirect walks the browser leg without a browser: it calls
// /v1/authorize and returns the callback URL Anubis would have redirected to.
func (s *Server) AuthorizeRedirect(authorizeURL string) string {
	s.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, authorizeURL, nil)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Do(req)
	if err != nil {
		s.t.Fatalf("anubistest: walking /v1/authorize: %v", err)
	}
	defer resp.Body.Close()
	return resp.Header.Get("Location")
}

func (s *Server) tokenExchange(w http.ResponseWriter, r *http.Request) {
	s.count("TokenExchange")
	if err := r.ParseForm(); err != nil {
		httpError(w, http.StatusBadRequest, "invalid_argument", "bad form")
		return
	}
	code := r.PostFormValue("code")
	s.mu.Lock()
	ac, ok := s.codes[code]
	delete(s.codes, code) // single use
	s.mu.Unlock()
	if !ok {
		httpError(w, http.StatusBadRequest, "invalid_pkce", "unknown code")
		return
	}
	if !pkceMatches(r.PostFormValue("code_verifier"), ac.challenge) {
		httpError(w, http.StatusBadRequest, "invalid_pkce", "verifier does not match challenge")
		return
	}
	if r.PostFormValue("redirect_uri") != ac.redirectURI || r.PostFormValue("client_id") != ac.clientID {
		httpError(w, http.StatusBadRequest, "invalid_pkce", "redirect_uri or client_id changed")
		return
	}
	tokens := s.IssueSession(ac.subject, ac.clientID)
	// The browser endpoint answers in snake_case, unlike every Connect
	// procedure above. That asymmetry is real and a client has to handle it.
	writeJSON(w, http.StatusOK, map[string]any{
		"access_token": tokens.AccessToken, "refresh_token": tokens.RefreshToken,
		"token_type": "Bearer", "expires_in": 600, "session_id": tokens.SessionID,
	})
}

// ---- wire helpers ---------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// httpError writes the plain-HTTP envelope.
func httpError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]any{
		"error": code, "message": message, "request_id": "req_test",
	})
}

// connectError writes a Connect error, with the stable domain code where
// Connect actually puts it: a base64 protobuf anubis.v1.ErrorInfo detail.
func connectError(w http.ResponseWriter, status int, connectCode, message, requestID string) {
	detail := encodeErrorInfo(domainCodeFor(message), requestID)
	writeJSON(w, status, map[string]any{
		"code":    connectCode,
		"message": message,
		"details": []map[string]any{{
			"type":  "anubis.v1.ErrorInfo",
			"value": base64.StdEncoding.EncodeToString(detail),
		}},
	})
}

// domainCodeFor picks the stable code the real server would have sent.
func domainCodeFor(message string) string {
	switch {
	case strings.Contains(message, "family revoked"):
		return "refresh_token_reuse_detected"
	case strings.Contains(message, "username or password"):
		return "invalid_credentials"
	default:
		return "unauthenticated"
	}
}

// encodeErrorInfo writes anubis.v1.ErrorInfo on the protobuf wire:
// string code = 1, string request_id = 2.
func encodeErrorInfo(code, requestID string) []byte {
	var out []byte
	out = appendField(out, 1, code)
	out = appendField(out, 2, requestID)
	return out
}

func appendField(dst []byte, field int, value string) []byte {
	if value == "" {
		return dst
	}
	dst = append(dst, byte(field<<3|2))
	dst = appendVarint(dst, uint64(len(value)))
	return append(dst, value...)
}

func appendVarint(dst []byte, n uint64) []byte {
	for n >= 0x80 {
		dst = append(dst, byte(n)|0x80)
		n >>= 7
	}
	return append(dst, byte(n))
}

// pkceMatches applies the S256 check the real token endpoint applies:
// BASE64URL(SHA256(verifier)) must equal the stored challenge.
func pkceMatches(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:]) == challenge
}

func randomID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}
