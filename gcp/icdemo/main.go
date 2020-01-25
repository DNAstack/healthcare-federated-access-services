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

// Binary icdemo is a demo of IC.
package main

import (
	"flag"
	"net/http"
	"strings"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/osenv" /* copybara-comment: osenv */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil" /* copybara-comment: srcutil */
)

var (
	hydraURL = osenv.MustVar("HYDRA_PUBLIC_URL")
	icURL    = osenv.MustVar("IC_URL")

	port = osenv.VarWithDefault("ICDEMO_PORT", "8091")
)

const htmlFile = "pages/hydra-ic-test.html"

func main() {
	flag.Parse()
	b, err := srcutil.Read(htmlFile)
	if err != nil {
		glog.Exitf("srcutil.Read(%v) failed: %v", htmlFile, err)
	}

	page := string(b)
	page = strings.ReplaceAll(page, "${HYDRA_URL}", hydraURL)
	page = strings.ReplaceAll(page, "${IC_URL}", icURL)

	h := func(w http.ResponseWriter, r *http.Request) { httputil.WriteHTMLResp(w, []byte(page)) }

	http.HandleFunc("/", h)

	glog.Exit(http.ListenAndServe(":"+port, nil))
}
