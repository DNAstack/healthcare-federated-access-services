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

package hydra

import (
	"fmt"
	"net/http"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common"
)

const (
	// StateIDKey uses to store stateID in hydra context.
	StateIDKey = "state"
)

// ExtractLoginChallenge extracts login_challenge from request.
func ExtractLoginChallenge(r *http.Request) (string, error) {
	n := common.GetParam(r, "login_challenge")
	if len(n) > 0 {
		return n, nil
	}
	return "", fmt.Errorf("request must include query 'login challenge'")
}

// ExtractConsentChallenge extracts consent_challenge from request.
func ExtractConsentChallenge(r *http.Request) (string, error) {
	n := common.GetParam(r, "consent_challenge")
	if len(n) > 0 {
		return n, nil
	}
	return "", fmt.Errorf("request must include query 'consent_challenge'")
}

// LoginSkip if hydra was already able to authenticate the user, skip will be true and we do not need to re-authenticate the user.
func LoginSkip(w http.ResponseWriter, r *http.Request, client *http.Client, login *hydraapi.LoginRequest, hydraAdminURL, challenge string) bool {
	if !login.Skip {
		return false
	}

	// You can apply logic here, for example update the number of times the user logged in.

	// TODO: provide metrics / audit logs for this case

	// Now it's time to grant the login request. You could also deny the request if something went terribly wrong
	resp, err := AcceptLoginRequest(client, hydraAdminURL, challenge, &hydraapi.HandledLoginRequest{Subject: &login.Subject})
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return true
	}

	common.SendRedirect(resp.RedirectTo, r, w)
	return true
}

// ConsentSkip if hydra was already able to consent the user, skip will be true and we do not need to re-consent the user.
func ConsentSkip(w http.ResponseWriter, r *http.Request, client *http.Client, consent *hydraapi.ConsentRequest, hydraAdminURL, challenge string) bool {
	if !consent.Skip {
		return false
	}

	// You can apply logic here, for example update the number of times the user consent.

	// TODO: provide metrics / audit logs for this case

	// Now it's time to grant the consent request. You could also deny the request if something went terribly wrong
	consentReq := &hydraapi.HandledConsentRequest{
		GrantedAudience: append(consent.RequestedAudience, consent.Client.ClientID),
		GrantedScope:    consent.RequestedScope,
		// TODO: need double check token has correct info.
	}
	resp, err := AcceptConsentRequest(client, hydraAdminURL, challenge, consentReq)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return true
	}

	common.SendRedirect(resp.RedirectTo, r, w)
	return true
}

// SendLoginSuccess sends login success to hydra.
func SendLoginSuccess(w http.ResponseWriter, r *http.Request, client *http.Client, hydraAdminURL, challenge, subject, stateID string) {
	req := &hydraapi.HandledLoginRequest{
		Subject: &subject,
		Context: map[string]interface{}{
			StateIDKey: stateID,
		},
	}
	resp, err := AcceptLoginRequest(client, hydraAdminURL, challenge, req)
	if err != nil {
		common.HandleError(http.StatusServiceUnavailable, err, w)
		return
	}

	common.SendRedirect(resp.RedirectTo, r, w)
}
