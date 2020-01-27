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

// Package appengine provides common functionality for applications running on
// Google Cloud Platform's appengine.
package appengine

import (
	"context"
	"os"

	glog "github.com/golang/glog" /* copybara-comment */
	"golang.org/x/oauth2/google" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp" /* copybara-comment: gcp */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds" /* copybara-comment: clouds */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
)

// MustBuildAccountWarehouse builds a *gcp.AccountWarehouse from the
// environment variables PROJECT, ROLE, and SCOPES.  It panics on failure.
func MustBuildAccountWarehouse(ctx context.Context, store storage.Store) clouds.ResourceTokenCreator {
	client, err := google.DefaultClient(context.Background(), "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		glog.Fatalf("Error creating HTTP client: %v", err)
		return nil
	}

	wh, err := gcp.NewAccountWarehouse(client, store)
	if err != nil {
		glog.Fatalf("Error creating account warehouse: %v", err)
		return nil
	}
	return wh
}

func mustGetenv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", key)
	}
	return v
}
