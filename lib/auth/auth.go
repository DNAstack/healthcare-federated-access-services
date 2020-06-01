// Copyright 2019 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package auth contains authorization check wrapper for handlers.
// Example:
// h, err := auth.WithAuth(handler, checker, Requirement{ClientID: true, ClientSecret: true, Role: Admin}
// if err != nil { ... }
// r.HandleFunc("/path", h)
package auth

import (
	"context"
	"net/http"
	"strings"
	"sync"

	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auditlog" /* copybara-comment: auditlog */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/oathclients" /* copybara-comment: oathclients */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/permissions" /* copybara-comment: permissions */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/strutil" /* copybara-comment: strutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/verifier" /* copybara-comment: verifier */

	glog "github.com/golang/glog" /* copybara-comment */
)

const (
	// maxHTTPBody = 2M
	maxHTTPBody = 2 * 1000 * 1000
	// UserAuthorizationHeader is the standard user authorization request header as a bearer token.
	UserAuthorizationHeader = "Authorization"
	// LinkAuthorizationHeader is an additional auth token in the request header for linking accounts.
	LinkAuthorizationHeader = "X-Link-Authorization"
)

// Role requirement of access.
type Role string

const (
	// None -> no bearer token required
	None Role = ""
	// User -> requires any valid bearer token, need to match {user} in path
	User Role = "user"
	// Admin -> requires bearer token with admin permission
	Admin Role = "admin"
)

// Require defines the Authorization Requirement.
type Require struct {
	ClientID     bool
	ClientSecret bool
	// Roles current supports "user" and "admin". Check will check the role inside the bearer token.
	// not requirement bearer token if "Role" is empty.
	Role       Role
	EditScopes []string
}

var (
	// RequireNone -> requires nothing for authorization
	RequireNone = Require{ClientID: false, ClientSecret: false, Role: None}
	// RequireClientID -> only require client id
	RequireClientID = Require{ClientID: true, ClientSecret: false, Role: None}
	// RequireClientIDAndSecret -> require client id and matched secret
	RequireClientIDAndSecret = Require{ClientID: true, ClientSecret: true, Role: None}
	// RequireAdminToken -> require an admin token, also the client id and secret
	RequireAdminToken = Require{ClientID: true, ClientSecret: true, Role: Admin}
	// RequireUserToken -> require an user token, also the client id and secret
	RequireUserToken = Require{ClientID: true, ClientSecret: true, Role: User}
	// RequireAccountAdminUserToken -> require a user token, client id & secret, and non-admins require "account_admin" scope for edits methods
	RequireAccountAdminUserToken = Require{ClientID: true, ClientSecret: true, Role: User, EditScopes: []string{"account_admin"}}
)

// Checker stores information and functions for authorization check.
type Checker struct {
	// Audit log logger.
	logger *logging.Client
	// Accepted oidc issuer url.
	issuer string
	// permissions contains methor to check if user admin permission.
	permissions *permissions.Permissions
	// fetchClientSecrets fetchs client id and client secret.
	fetchClientSecrets func() (map[string]string, error)
	// transformIdentity transform as needed, will run just after token convert to identity.
	// eg. hydra stores custom claims in "ext" fields for access token. need to move to top
	// level field.
	transformIdentity func(*ga4gh.Identity) *ga4gh.Identity
	// init the verifier.AccessTokenVerifier
	init sync.Once
	// access token verifier
	verifier *verifier.AccessTokenVerifier
}

func (s *Checker) getVerifier(ctx context.Context) (*verifier.AccessTokenVerifier, error) {
	var err error
	s.init.Do(func() {
		s.verifier, err = verifier.NewAccessTokenVerifier(ctx, s.issuer)
	})

	if err != nil {
		return nil, err
	}

	return s.verifier, nil
}

// NewChecker creates checker for authorization check.
// ctx: used to creates oidc token verifier, may store httpclient for mock.
// logger: audit log logger.
// issuer: accepted oidc issuer url.
// permissions: contains method to check if user admin permission.
// fetchClientSecrets: fetches client id and client secret.
// transformIdentity: transform as needed, will run just after token convert to identity.
func NewChecker(logger *logging.Client, issuer string, permissions *permissions.Permissions, fetchClientSecrets func() (map[string]string, error), transformIdentity func(*ga4gh.Identity) *ga4gh.Identity) *Checker {
	return &Checker{
		logger:             logger,
		issuer:             issuer,
		permissions:        permissions,
		fetchClientSecrets: fetchClientSecrets,
		transformIdentity:  transformIdentity,
	}
}

// Context (i.e. auth.Context) is authorization information that is stored within the request context.
type Context struct {
	ID           *ga4gh.Identity
	LinkedID     *ga4gh.Identity
	ClientID     string
	ClientSecret string
	IsAdmin      bool
}
type authContextType struct{}

var authContextKey = &authContextType{}

// MustWithAuth wraps the handler func with authorization check includes client credentials, bearer token validation and role in token.
// function will cause fatal if passed in invalid requirement. This is cleaner when calling in main.
func MustWithAuth(handler func(http.ResponseWriter, *http.Request), checker *Checker, require Require) func(http.ResponseWriter, *http.Request) {
	h, err := WithAuth(handler, checker, require)
	if err != nil {
		glog.Fatalf("WithAuth(): %v", err)
	}
	return h
}

// WithAuth wraps the handler func with authorization check includes client credentials, bearer token validation and role in token.
// function will return error if passed in invalid requirement.
func WithAuth(handler func(http.ResponseWriter, *http.Request), checker *Checker, require Require) (func(http.ResponseWriter, *http.Request), error) {
	if !require.ClientID && (require.ClientSecret || len(require.Role) != 0) {
		return nil, status.Errorf(codes.Internal, "must require client_id when require client_secret or bearer token")
	}

	switch require.Role {
	case None, User, Admin:
	default:
		return nil, status.Errorf(codes.Internal, "undefined role: %s", require.Role)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		var linkedID *ga4gh.Identity
		log, id, isAdmin, err := checker.check(r, require)
		if err == nil && len(r.Header.Get(LinkAuthorizationHeader)) > 0 {
			linkedID, err = checker.verifiedBearerToken(r, LinkAuthorizationHeader, oathclients.ExtractClientID(r))
			if err == nil && !strutil.ContainsWord(linkedID.Scope, "link") {
				err = errutil.WithErrorReason(errScopeMissing, status.Errorf(codes.Unauthenticated, "linked auth bearer token missing required 'link' scope"))
			}
		}
		if err != nil {
			log.ErrorType = errutil.ErrorReason(err)
		}
		writeAccessLog(checker.logger, log, err, r)
		if err != nil {
			httputils.WriteError(w, err)
			return
		}
		a := &Context{
			ID:           id,
			LinkedID:     linkedID,
			ClientID:     oathclients.ExtractClientID(r),
			ClientSecret: oathclients.ExtractClientSecret(r),
			IsAdmin:      isAdmin,
		}
		r = r.WithContext(context.WithValue(r.Context(), authContextKey, a))

		handler(w, r)
	}, nil
}

// FromContext (i.e. auth.FromContext) returns auth information from the request context.
// Example within a request handler: a, err := auth.FromContext(r.Context())
func FromContext(ctx context.Context) (*Context, error) {
	v := ctx.Value(authContextKey)
	if v == nil {
		return nil, status.Errorf(codes.PermissionDenied, "unauthorized: identity not provided")
	}
	if a, ok := v.(*Context); ok {
		return a, nil
	}
	return nil, status.Errorf(codes.PermissionDenied, "unauthorized: invalid identity format")
}

// checkRequest need to validate the request before actually read data from it.
func checkRequest(r *http.Request) error {
	// TODO: maybe should also cover content-length = -1
	if r.ContentLength > maxHTTPBody {
		return errutil.WithErrorReason(errBodyTooLarge, status.Error(codes.FailedPrecondition, "body too large"))
	}

	return nil
}

// Check checks request meet all authorization requirements for this framework.
func (s *Checker) check(r *http.Request, require Require) (*auditlog.AccessLog, *ga4gh.Identity, bool, error) {
	log := &auditlog.AccessLog{}

	if err := checkRequest(r); err != nil {
		return log, nil, false, err
	}

	r.ParseForm()
	cID := oathclients.ExtractClientID(r)

	if require.ClientID {
		cSec := oathclients.ExtractClientSecret(r)

		if err := s.verifyClientCredentials(cID, cSec, require); err != nil {
			return log, nil, false, err
		}
	}

	id, isAdmin, err := s.verifyAccessToken(r, cID, require)
	log.TokenID = tokenID(id)
	log.TokenSubject = id.Subject
	log.TokenIssuer = id.Issuer

	if err != nil {
		return log, id, isAdmin, err
	}

	// EditScopes are required for some operations, unless the user is an administrator.
	if len(require.EditScopes) > 0 && isEditMethod(r.Method) && !isAdmin {
		for _, scope := range require.EditScopes {
			if !strutil.ContainsWord(id.Scope, scope) {
				return log, id, isAdmin, errutil.WithErrorReason(errScopeMissing, status.Errorf(codes.Unauthenticated, "scope %q required for this method (%q)", scope, id.Scope))
			}
		}
	}

	return log, id, isAdmin, err
}

// verifyClientCredentials based on the provided requirement, the function
// checks if the client is known and the provided secret matches the secret
// for that client.
func (s *Checker) verifyClientCredentials(client, secret string, require Require) error {
	secrets, err := s.fetchClientSecrets()
	if err != nil {
		return errutil.WithErrorReason(errClientUnavailable, err)
	}

	// Check that the client ID exists and it is a known.
	if len(client) == 0 {
		return errutil.WithErrorReason(errClientMissing, status.Error(codes.Unauthenticated, "requires a valid client ID"))
	}

	want, ok := secrets[client]
	if !ok {
		return errutil.WithErrorReason(errClientInvalid, status.Errorf(codes.Unauthenticated, "client ID %q is unrecognized", client))
	}

	if !require.ClientSecret {
		return nil
	}

	// Check that the client secret match the client ID.
	if want != secret {
		return errutil.WithErrorReason(errSecretMismatch, status.Error(codes.Unauthenticated, "requires a valid client secret"))
	}

	return nil
}

// verifyAccessToken verify the access token meet the given requirement.
// The returned identity will not be nil even in error cases.
func (s *Checker) verifyAccessToken(r *http.Request, clientID string, require Require) (*ga4gh.Identity, bool, error) {
	if require.Role == None {
		return &ga4gh.Identity{}, false, nil
	}

	id, err := s.verifiedBearerToken(r, UserAuthorizationHeader, clientID)
	if err != nil {
		return &ga4gh.Identity{}, false, err
	}

	isAdmin, err := s.permissions.CheckAdmin(id)
	if err != nil {
		return id, false, errutil.WithErrorReason(errCheckAdminFailed, status.Errorf(codes.Unavailable, "loadPermissions failed: %v", err))
	}

	switch require.Role {
	case Admin:
		if !isAdmin {
			// TODO: token maybe leaked at this point, consider auto revoke or contact user/admin.
			return id, isAdmin, errutil.WithErrorReason(errNotAdmin, status.Errorf(codes.Unauthenticated, "requires admin permission %v", err))
		}
		return id, isAdmin, nil

	case User:
		if isAdmin {
			// Token is for an administrator, who is able to act on behalf of any user, so short-circuit remaining checks.
			return id, isAdmin, nil
		}
		if user := mux.Vars(r)["user"]; len(user) != 0 && user != id.Subject {
			// TODO: token maybe leaked at this point, consider auto revoke or contact user/admin.
			return id, isAdmin, errutil.WithErrorReason(errUserMismatch, status.Errorf(codes.Unauthenticated, "user in path does not match token"))
		}
		return id, isAdmin, nil

	default:
		return id, isAdmin, errutil.WithErrorReason(errUnknownRole, status.Errorf(codes.Unauthenticated, "unknown role %q", require.Role))
	}
}

// verifiedBearerToken extracts the bearer token from the request and verifies it.
// Returns the identity for the token, token information, and error type, and error.
func (s *Checker) verifiedBearerToken(r *http.Request, authHeader, clientID string) (*ga4gh.Identity, error) {
	parts := strings.SplitN(r.Header.Get(authHeader), " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return nil, errutil.WithErrorReason(errIDVerifyFailed, status.Errorf(codes.Unauthenticated, "invalid brearer token"))
	}
	tok := parts[1]

	v, err := s.getVerifier(r.Context())
	if err != nil {
		return nil, err
	}

	if err := verifyToken(r.Context(), v, tok, s.issuer, clientID); err != nil {
		return nil, err
	}

	id, err := s.tokenToIdentityWithoutVerification(tok)
	if err != nil {
		return nil, err
	}

	return id, nil
}

// tokenToIdentityWithoutVerification parse the token to Identity struct.
// Also normalize the issuer string inside Identity and apply the transform needed in Checker.
func (s *Checker) tokenToIdentityWithoutVerification(tok string) (*ga4gh.Identity, error) {
	id, err := ga4gh.ConvertTokenToIdentityUnsafe(tok)
	if err != nil {
		return nil, errutil.WithErrorReason(errTokenInvalid, status.Errorf(codes.Unauthenticated, "invalid token format: %v", err))
	}
	id.Issuer = normalize(id.Issuer)
	return s.transformIdentity(id), nil
}

// verifyToken oidc spec verfiy token.
func verifyToken(ctx context.Context, v *verifier.AccessTokenVerifier, tok, iss, clientID string) error {
	err := v.Verify(ctx, tok, verifier.AccessTokenOption(clientID, iss))
	if err == nil {
		return nil
	}

	reason := errutil.ErrorReason(err)
	if len(reason) == 0 {
		reason = errIDVerifyFailed
	}
	return errutil.WithErrorReason(reason, status.Errorf(codes.Unauthenticated, "token verify failed: %v", err))
}

// normalize ensure the issuer string and tailling slash.
func normalize(issuer string) string {
	return strings.TrimSuffix(issuer, "/")
}

func isEditMethod(method string) bool {
	if method == http.MethodGet || method == http.MethodOptions {
		return false
	}
	return true
}

func writeAccessLog(client *logging.Client, entry *auditlog.AccessLog, err error, r *http.Request) {
	entry.RequestMethod = r.Method
	entry.RequestEndpoint = httputils.AbsolutePath(r)
	entry.RequestIP = httputils.RequesterIP(r)
	entry.TracingID = httputils.TracingID(r)
	entry.PassAuthCheck = true

	if err != nil {
		if st, ok := status.FromError(err); ok {
			entry.ResponseCode = httputils.HTTPStatus(st.Code())
		}
		entry.Payload = err.Error()
		entry.PassAuthCheck = false
	}
	entry.Request = r

	auditlog.WriteAccessLog(r.Context(), client, entry)
}

func tokenID(id *ga4gh.Identity) string {
	v, ok := id.Extra["tid"]
	if ok {
		if tid, ok := v.(string); ok {
			return tid
		}
	}

	if len(id.TokenID) > 0 {
		return id.TokenID
	}
	return id.ID
}
