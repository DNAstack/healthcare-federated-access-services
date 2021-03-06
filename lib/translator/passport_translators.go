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

package translator

import (
	"context"
	"fmt"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms" /* copybara-comment: kms */

	dampb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	// DbGapTranslatorName is the name of the DbGap passport translator.
	DbGapTranslatorName = "dbgap_translator"
)

func PassportTranslators() map[string]*dampb.PassportTranslator {
	return map[string]*dampb.PassportTranslator{
		DbGapTranslatorName: {
			CompatibleIssuers: []string{
				"https://dbgap.nlm.nih.gov/aa",
			},
			Ui: map[string]string{
				"label": "dbGaP Passport Translator",
			},
		},
	}
}

func GetPassportTranslators() *dampb.PassportTranslatorsResponse {
	return &dampb.PassportTranslatorsResponse{
		PassportTranslators: PassportTranslators(),
	}
}

// CreateTranslator creates a Translator for a particular token issuer.
func CreateTranslator(ctx context.Context, iss, translateUsing, clientID, publicKey, selfIssuer string, signer kms.Signer) (Translator, error) {
	var s Translator
	var err error
	if translateUsing == "" {
		s, err = NewOIDCIdentityTranslator(ctx, iss, clientID)
		if err != nil {
			return nil, fmt.Errorf("failed to create identity translator: %v", err)
		}
	} else {
		switch translateUsing {
		case DbGapTranslatorName:
			s, err = NewDbGapTranslator(publicKey, selfIssuer, signer)
		default:
			return nil, fmt.Errorf("invalid translator: %q", translateUsing)
		}
		if err != nil {
			return nil, fmt.Errorf("failed to create %q translator: %v", translateUsing, err)
		}
	}
	return s, nil
}
