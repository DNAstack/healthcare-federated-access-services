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

package ic

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

// HydraLogin handles login request from hydra.
func (s *Service) HydraLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	// Use login_challenge fetch information from hydra.
	challenge, status := hydra.ExtractLoginChallenge(r)
	if status != nil {
		httputil.WriteStatus(w, status)
		return
	}

	login, err := hydra.GetLoginRequest(s.httpClient, s.hydraAdminURL, challenge)
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}

	if hydra.LoginSkip(w, r, s.httpClient, login, s.hydraAdminURL, challenge) {
		return
	}

	u, err := url.Parse(login.RequestURL)
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}

	realm := u.Query().Get("realm")
	if len(realm) == 0 {
		realm = storage.DefaultRealm
	}

	cfg, err := s.loadConfig(nil, realm)
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}

	scopes := login.RequestedScope
	if len(scopes) == 0 {
		scopes = defaultIdpScopes
	}

	// Return login page if no login hint.
	loginHint := u.Query().Get("login_hint")
	if !strings.Contains(loginHint, ":") {
		// Return Login page.
		query := fmt.Sprintf("?scope=%s&login_challenge=%s", url.QueryEscape(strings.Join(scopes, " ")), url.QueryEscape(challenge))
		page, err := s.renderLoginPage(cfg, map[string]string{"realm": realm}, query)
		if err != nil {
			httputil.WriteError(w, http.StatusServiceUnavailable, err)
			return
		}
		httputil.WriteHTMLResp(w, page)
		return
	}

	// Skip login page and select the given idp when if contains login hint.
	hint := strings.SplitN(loginHint, ":", 2)
	loginHintProvider := hint[0]
	loginHintAccount := hint[1]

	// Idp login
	in := loginIn{
		realm:     realm,
		scope:     scopes,
		loginHint: loginHintAccount,
		idpName:   loginHintProvider,
		challenge: challenge,
	}
	s.login(in, w, r, cfg)
}

func (s *Service) hydraLoginError(w http.ResponseWriter, r *http.Request, state, errName, errDesc string) {
	var loginState cpb.LoginState
	err := s.store.Read(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, state, storage.LatestRev, &loginState)
	if err != nil {
		httputil.WriteError(w, http.StatusInternalServerError, fmt.Errorf("read login state failed, %q", err))
		return
	}

	if len(loginState.Challenge) == 0 {
		httputil.WriteError(w, http.StatusUnauthorized, fmt.Errorf("invalid login state challenge parameter"))
		return
	}

	// Report the login err to hydra.
	hyErr := &hydraapi.RequestDeniedError{
		Name:        errName,
		Description: errDesc,
	}
	resp, err := hydra.RejectLogin(s.httpClient, s.hydraAdminURL, loginState.Challenge, hyErr)
	if err != nil {
		httputil.WriteError(w, http.StatusServiceUnavailable, err)
		return
	}

	httputil.WriteRedirect(w, r, resp.RedirectTo)
}

// HydraConsent handles consent request from hydra.
func (s *Service) HydraConsent(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	redirect, out, err := s.hydraConsent(r)
	if err != nil {
		httputil.WriteStatusError(w, err)
	}
	if redirect {
		httputil.WriteRedirect(w, r, out)
		return
	}
	httputil.WriteHTMLResp(w, out)
}

// hydraConsent returns:
//   if true, redirect address.
//   if false, the html page.
func (s *Service) hydraConsent(r *http.Request) (_ bool, _ string, ferr error) {

	// Use consent_challenge fetch information from hydra.
	challenge, sts := hydra.ExtractConsentChallenge(r)
	if sts != nil {
		return false, "", sts.Err()
	}

	consent, err := hydra.GetConsentRequest(s.httpClient, s.hydraAdminURL, challenge)
	if err != nil {
		return false, "", status.Errorf(httputil.RPCCode(http.StatusServiceUnavailable), "%v", err)
	}

	yes, redirect, err := hydra.ConsentSkip(r, s.httpClient, consent, s.hydraAdminURL, challenge)
	if err != nil {
		return false, "", status.Errorf(httputil.RPCCode(http.StatusServiceUnavailable), "%v", err)
	}
	if yes {
		return true, redirect, nil
	}

	clientName := consent.Client.Name
	if len(clientName) == 0 {
		clientName = consent.Client.ClientID
	}
	if len(clientName) == 0 {
		return false, "", status.Errorf(httputil.RPCCode(http.StatusServiceUnavailable), "consent.Client.Name empty")
	}

	sub := consent.Subject
	if len(sub) == 0 {
		return false, "", status.Errorf(httputil.RPCCode(http.StatusServiceUnavailable), "consent.Subject empty")
	}

	stateID, sts := hydra.ExtractStateIDInConsent(consent)
	if sts != nil {
		return false, "", sts.Err()
	}

	tx, err := s.store.Tx(true)
	if err != nil {
		return false, "", status.Errorf(httputil.RPCCode(http.StatusServiceUnavailable), "%v", err)
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

	state := &cpb.AuthTokenState{}
	err = s.store.ReadTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, tx)
	if err != nil {
		return false, "", status.Errorf(httputil.RPCCode(http.StatusInternalServerError), "%v", err)
	}

	state.ConsentChallenge = challenge
	state.Scope = strings.Join(consent.RequestedScope, " ")
	state.Audience = append(consent.RequestedAudience, consent.Client.ClientID)
	err = s.store.WriteTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, nil, tx)
	if err != nil {
		return false, "", status.Errorf(httputil.RPCCode(http.StatusInternalServerError), "%v", err)
	}

	acct, st, err := s.loadAccount(sub, state.Realm, tx)
	if err != nil {
		return false, "", status.Errorf(httputil.RPCCode(st), "%v", err)
	}

	cfg, err := s.loadConfig(tx, state.Realm)
	if err != nil {
		return false, "", status.Errorf(httputil.RPCCode(http.StatusServiceUnavailable), "%v", err)
	}

	secrets, err := s.loadSecrets(tx)
	if err != nil {
		return false, "", status.Errorf(httputil.RPCCode(http.StatusServiceUnavailable), "%v", err)
	}

	id, err := s.accountToIdentity(r.Context(), acct, cfg, secrets)
	if err != nil {
		return false, "", status.Errorf(httputil.RPCCode(http.StatusInternalServerError), "%v", err)
	}

	id.Scope = strings.Join(consent.RequestedScope, " ")

	page := s.informationReleasePage(id, stateID, clientName, id.Scope, state.Realm, cfg)
	return false, page, nil
}

// hydraRejectConsent returns the redirect address.
func (s *Service) hydraRejectConsent(r *http.Request, stateID string) (_ string, ferr error) {
	tx, err := s.store.Tx(true)
	if err != nil {
		return "", status.Errorf(httputil.RPCCode(http.StatusServiceUnavailable), "%v", err)
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil {
			ferr = err
		}
	}()

	state := &cpb.AuthTokenState{}
	err = s.store.ReadTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, tx)
	if err != nil {
		return "", status.Errorf(httputil.RPCCode(http.StatusInternalServerError), "%v", err)
	}

	// The temporary state for information releasing process can be only used once.
	err = s.store.DeleteTx(storage.AuthTokenStateDatatype, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, tx)
	if err != nil {
		return "", status.Errorf(httputil.RPCCode(http.StatusInternalServerError), "%v", err)
	}

	req := &hydraapi.RequestDeniedError{
		Code:        http.StatusUnauthorized,
		Name:        "Consent Denied",
		Description: "User deny consent",
	}

	resp, err := hydra.RejectConsent(s.httpClient, s.hydraAdminURL, state.ConsentChallenge, req)
	if err != nil {
		return "", status.Errorf(httputil.RPCCode(http.StatusServiceUnavailable), "%v", err)
	}

	return resp.RedirectTo, nil
}

func identityToHydraMap(id *ga4gh.Identity) (map[string]interface{}, error) {
	b, err := json.Marshal(id)
	if err != nil {
		return nil, err
	}

	m := map[string]interface{}{}
	err = json.Unmarshal(b, &m)
	if err != nil {
		return nil, err
	}

	// Remove all standard claims which already included in hydra.
	claims := []string{"sub", "iss", "iat", "nbf", "exp", "scope", "aud", "azp", "jti", "nonce"}
	for _, n := range claims {
		delete(m, n)
	}
	return m, err
}

func (s *Service) hydraAcceptConsent(r *http.Request, state *cpb.AuthTokenState, cfg *pb.IcConfig, tx storage.Tx) (string, error) {
	secrets, err := s.loadSecrets(tx)
	if err != nil {
		return "", status.Errorf(httputil.RPCCode(http.StatusServiceUnavailable), "%v", err)
	}

	acct, st, err := s.loadAccount(state.Subject, state.Realm, tx)
	if err != nil {
		return "", status.Errorf(httputil.RPCCode(st), "%v", err)
	}

	id, err := s.accountToIdentity(r.Context(), acct, cfg, secrets)
	if err != nil {
		return "", status.Errorf(httputil.RPCCode(http.StatusInternalServerError), "%v", err)
	}

	now := time.Now().Unix()

	// TODO: scope maybe different after optional information release.
	// scope down the identity.
	scoped := scopedIdentity(id, state.Scope, s.getIssuerString(), state.Subject, "", now, id.NotBefore, id.Expiry, []string{}, "")
	m, err := identityToHydraMap(scoped)
	if err != nil {
		return "", status.Errorf(httputil.RPCCode(http.StatusInternalServerError), "%v", err)
	}

	req := &hydraapi.HandledConsentRequest{
		GrantedAudience: state.Audience,
		GrantedScope:    strings.Split(state.Scope, " "),
		Session: &hydraapi.ConsentRequestSessionData{
			IDToken: m,
		},
	}

	if len(scoped.Identities) != 0 {
		var identities []string
		for k := range scoped.Identities {
			identities = append(identities, k)
		}

		req.Session.AccessToken = map[string]interface{}{
			"identities": identities,
		}
	}

	resp, err := hydra.AcceptConsent(s.httpClient, s.hydraAdminURL, state.ConsentChallenge, req)
	if err != nil {
		return "", status.Errorf(httputil.RPCCode(http.StatusServiceUnavailable), "%v", err)
	}

	return resp.RedirectTo, nil
}
