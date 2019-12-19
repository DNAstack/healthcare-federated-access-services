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

// This package provides a single-host reverse proxy that rewrites bearer
// tokens in Authorization headers to be Google Cloud Platform access tokens.
// For configuration information see app.yaml.
package main

import (
	"context"
	"net/http"
	"os"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp/internal/appengine" /* copybara-comment: appengine */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp/storage" /* copybara-comment: gcp_storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dam" /* copybara-comment: dam */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
)

const (
	DefaultServiceName = "dam"
)

func main() {
	ctx := context.Background()
	domain := os.Getenv("DAM_URL")
	if domain == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "DAM_URL")
	}
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "CONFIG_PATH")
	}
	storeName := os.Getenv("STORAGE")
	if storeName == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "STORAGE")
	}
	defaultBroker := os.Getenv("DEFAULT_BROKER")
	if len(defaultBroker) == 0 {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "DEFAULT_BROKER")
	}
	serviceName := os.Getenv("SERVICE_NAME")
	if serviceName == "" {
		serviceName = DefaultServiceName
	}
	var store storage.Store
	switch storeName {
	case "datastore":
		project := os.Getenv("PROJECT")
		if project == "" {
			glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "PROJECT")
		}
		store = gcp_storage.NewDatastoreStorage(ctx, project, serviceName, path)
	case "memory":
		store = storage.NewMemoryStorage(serviceName, path)
	default:
		glog.Fatalf("environment variable %q: unknown storage type %q", "STORAGE", storeName)
	}
	// ev := appengine.MustBuildEvaluator(ctx)
	wh := appengine.MustBuildAccountWarehouse(ctx, store)

	hydraAdminURL := os.Getenv("HYDRA_ADMIN_URL")
	if hydraAdminURL == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "HYDRA_ADMIN_URL")
	}
	// TODO will remove this flag after hydra integration complete.
	useHydra := os.Getenv("USE_HYDRA") != ""

	d := dam.NewService(ctx, domain, defaultBroker, hydraAdminURL, store, wh, useHydra)
	port := os.Getenv("DAM_PORT")
	if len(port) == 0 {
		port = "8080"
	}
	glog.Infof("Using port %v", port)
	glog.Fatal(http.ListenAndServe(":"+port, d.Handler))
}
