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
	"fmt"
	"net/http"
	"strings"

	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/auditlog" /* copybara-comment: auditlog */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/oathclients" /* copybara-comment: oathclients */

	glog "github.com/golang/glog" /* copybara-comment */
)

type errType string

const (
	// maxHTTPBody = 2M
	maxHTTPBody = 2 * 1000 * 1000

	// None -> no bearer token required
	None Role = ""
	// User -> requires any valid bearer token, need to match {user} in path
	User Role = "user"
	// Admin -> requires bearer token with admin permission
	Admin Role = "admin"

	noErr                  errType = ""
	errBodyTooLarge        errType = "req:body_too_large"
	errClientUnavailable   errType = "client:unavailable"
	errClientMissing       errType = "client:missing"
	errClientInvalid       errType = "client:invalid"
	errSecretMismatch      errType = "client:secret_mismatch"
	errTokenInvalid        errType = "token:invalid"
	errIssMismatch         errType = "id:iss_mismatch"
	errSubMissing          errType = "id:sub_missing"
	errAudMismatch         errType = "id:aud_mismatch"
	errIDInvalid           errType = "id:invalid"
	errVerifierUnavailable errType = "oidc:verifier_unavailable"
	errIDVerifyFailed      errType = "id:verify_failed"
	errNotAdmin            errType = "role:user_not_admin"
	errUserMismatch        errType = "role:user_mismatch"
	errUnknownRole         errType = "role:unknown_role"
)

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
)

// Role requirement of access.
type Role string

// Checker stores information and functions for authorization check.
type Checker struct {
	// Audit log logger.
	Logger *logging.Client
	// Accepted oidc Issuer url.
	Issuer string
	// FetchClientSecrets fetchs client id and client secret.
	FetchClientSecrets func() (map[string]string, error)
	// TransformIdentity transform as needed, will run just after token convert to identity.
	// eg. hydra stores custom claims in "ext" fields for access token. need to move to top
	// level field.
	TransformIdentity func(*ga4gh.Identity) *ga4gh.Identity
	// IsAdmin checks if the given identity has admin permission.
	IsAdmin func(*ga4gh.Identity) error
}

// Require defines the Authorization Requirement.
type Require struct {
	ClientID     bool
	ClientSecret bool
	// Roles current supports "user" and "admin". Check will check the role inside the bearer token.
	// not requirement bearer token if "Role" is empty.
	Role Role
}

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
		return nil, fmt.Errorf("must require client_id when require client_secret or bearer token")
	}

	if require.Role != None && require.Role != User && require.Role != Admin {
		return nil, fmt.Errorf("undefined role: %s", require.Role)
	}

	return func(w http.ResponseWriter, r *http.Request) {
		log, err := checker.check(r, require)
		writeAccessLog(checker.Logger, log, err, r)
		if err != nil {
			httputil.WriteRPCResp(w, nil, err)
			return
		}

		handler(w, r)
	}, nil
}

// checkRequest need to validate the request before actually read data from it.
func checkRequest(r *http.Request) (errType, error) {
	// TODO: maybe should also cover content-length = -1
	if r.ContentLength > maxHTTPBody {
		return errBodyTooLarge, status.Error(codes.FailedPrecondition, "body too large")
	}

	return noErr, nil
}

// Check checks request meet all authorization requirements.
func (s *Checker) check(r *http.Request, require Require) (*auditlog.AccessLog, error) {
	log := &auditlog.AccessLog{}

	if et, err := checkRequest(r); err != nil {
		log.ErrorType = string(et)
		return log, err
	}

	if !require.ClientID {
		return log, nil
	}

	r.ParseForm()

	cID := oathclients.ExtractClientID(r)
	cSec := oathclients.ExtractClientSecret(r)

	if et, err := s.verifyClientCredentials(cID, cSec, require); err != nil {
		log.ErrorType = string(et)
		return log, err
	}

	// Not require bearer token.
	if require.Role == None {
		return log, nil
	}

	tok := extractBearerToken(r)

	if et, err := verifyToken(r.Context(), tok, s.Issuer, cID); err != nil {
		log.ErrorType = string(et)
		return log, err
	}

	id, et, err := s.tokenToIdentityWithoutVerification(tok)
	if err != nil {
		log.ErrorType = string(et)
		return log, err
	}

	log.TokenID = id.ID
	log.TokenSubject = id.Subject
	log.TokenIssuer = id.Issuer

	if et, err := verifyIdentity(id, s.Issuer, cID); err != nil {
		log.ErrorType = string(et)
		return log, err
	}

	err = s.IsAdmin(id)

	switch require.Role {
	case Admin:
		if err != nil {
			// TODO: token maybe leaked at this point, consider auto revoke or contact user/admin.
			log.ErrorType = string(errNotAdmin)
			return log, status.Errorf(codes.Unauthenticated, "requires admin permission %v", err)
		}
		return log, nil

	case User:
		// Token is for an administrator, who is able to act on behalf of any user, so short-circuit remaining checks.
		if err == nil {
			return log, nil
		}
		if user := mux.Vars(r)["user"]; len(user) != 0 && user != id.Subject {
			// TODO: token maybe leaked at this point, consider auto revoke or contact user/admin.
			log.ErrorType = string(errUserMismatch)
			return log, status.Errorf(codes.Unauthenticated, "user in path does not match token")
		}
		return log, nil

	default:
		log.ErrorType = string(errUnknownRole)
		return log, status.Errorf(codes.Unauthenticated, "unknown role %q", require.Role)
	}
}

// verifyClientCredentials based on the provided requirement, the function
// checks if the client is known and the provided secret matches the secret
// for that client.
func (s *Checker) verifyClientCredentials(client, secret string, require Require) (errType, error) {
	secrets, err := s.FetchClientSecrets()
	if err != nil {
		return errClientUnavailable, err
	}

	// Check that the client ID exists and it is a known.
	if len(client) == 0 {
		return errClientMissing, status.Error(codes.Unauthenticated, "requires a valid client ID")
	}

	want, ok := secrets[client]
	if !ok {
		return errClientInvalid, status.Errorf(codes.Unauthenticated, "client ID %q is unrecognized", client)
	}

	if !require.ClientSecret {
		return noErr, nil
	}

	// Check that the client secret match the client ID.
	if want != secret {
		return errSecretMismatch, status.Error(codes.Unauthenticated, "requires a valid client secret")
	}

	return noErr, nil
}

// extractBearerToken from Authorization Header.
func extractBearerToken(r *http.Request) string {
	parts := strings.SplitN(r.Header.Get("Authorization"), " ", 2)
	if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
		return parts[1]
	}
	return ""
}

// tokenToIdentityWithoutVerification parse the token to Identity struct.
// Also normalize the issuer string inside Identity and apply the transform needed in Checker.
func (s *Checker) tokenToIdentityWithoutVerification(tok string) (*ga4gh.Identity, errType, error) {
	id, err := ga4gh.ConvertTokenToIdentityUnsafe(tok)
	if err != nil {
		return nil, errTokenInvalid, status.Errorf(codes.Unauthenticated, "invalid token format: %v", err)
	}

	id.Issuer = normalize(id.Issuer)

	id = s.TransformIdentity(id)

	return id, noErr, nil
}

// verifyIdentity verifies:
// - token issuer
// - subject is not empty
// - aud and azp allow given clientID
// - id.Valid(): expire, notBefore, issueAt
func verifyIdentity(id *ga4gh.Identity, issuer, clientID string) (errType, error) {
	iss := normalize(issuer)
	if id.Issuer != iss {
		// TODO: token maybe leaked at this point, consider auto revoke or contact user/admin.
		return errIssMismatch, status.Errorf(codes.Unauthenticated, "token unauthorized: for issuer %s", id.Issuer)
	}

	if len(id.Subject) == 0 {
		return errSubMissing, status.Error(codes.Unauthenticated, "token unauthorized: no subject")
	}

	if !ga4gh.IsAudience(id, clientID, iss) {
		// TODO: token maybe leaked at this point, consider auto revoke or contact user/admin.
		return errAudMismatch, status.Errorf(codes.Unauthenticated, "token unauthorized: unauthorized party")
	}

	if err := id.Valid(); err != nil {
		return errIDInvalid, status.Errorf(codes.Unauthenticated, "token unauthorized: %v", err)
	}

	return noErr, nil
}

// verifyToken oidc spec verfiy token.
func verifyToken(ctx context.Context, tok, iss, clientID string) (errType, error) {
	v, err := ga4gh.GetOIDCTokenVerifier(ctx, clientID, iss)
	if err != nil {
		return errVerifierUnavailable, status.Errorf(codes.Unauthenticated, "GetOIDCTokenVerifier failed: %v", err)
	}

	if _, err = v.Verify(ctx, tok); err != nil {
		return errIDVerifyFailed, status.Errorf(codes.Unauthenticated, "token verify failed: %v", err)
	}

	return noErr, nil
}

// normalize ensure the issuer string and tailling slash.
func normalize(issuer string) string {
	return strings.TrimSuffix(issuer, "/")
}

func writeAccessLog(client *logging.Client, entry *auditlog.AccessLog, err error, r *http.Request) {
	entry.RequestMethod = r.Method
	entry.RequestEndpoint = httputil.AbsolutePath(r)
	entry.RequestIP = httputil.RequesterIP(r)
	entry.TracingID = httputil.TracingID(r)
	entry.PassAuthCheck = true

	if err != nil {
		if st, ok := status.FromError(err); ok {
			entry.ResponseCode = httputil.HTTPStatus(st.Code())
		}
		entry.Payload = err.Error()
		entry.PassAuthCheck = false
	}
	entry.Request = r

	auditlog.WriteAccessLog(r.Context(), client, entry)
}
