// Copyright 2020 Google LLC.
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

package auditlogsapi

import (
	"context"
	"regexp"
	"strings"

	glog "github.com/golang/glog" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */

	lgrpcpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_grpc */
	lpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_proto */
	apb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/auditlogs/v0" /* copybara-comment: auditlogs_go_proto */
)

// AuditLogs is implments the audit logs API for DAM.
// Currently support GCP tokens.
type AuditLogs struct {
	// sdl is the Stackdriver Logging Client.
	sdl lgrpcpb.LoggingServiceV2Client

	ProjectID string
}

// NewAuditLogs creates a new AuditLogs.
func NewAuditLogs(sdl lgrpcpb.LoggingServiceV2Client) *AuditLogs {
	return &AuditLogs{sdl: sdl, ProjectID: "fake-project-id"}
}

// ListAuditLogs lists the audit logs.
func (s *AuditLogs) ListAuditLogs(ctx context.Context, req *apb.ListAuditLogsRequest) (*apb.ListAuditLogsResponse, error) {
	glog.Infof("ListAuditLogsRequest")
	parent := req.GetParent()
	ids := parentRE.FindStringSubmatch(parent)
	if len(ids) < 2 {
		return nil, status.Errorf(codes.InvalidArgument, "invalud parent: %v", parent)
	}

	// TODO: read project ID from realm config.
	project := s.ProjectID

	subject := ids[1]
	// TODO: consider adding a userID to logs that contains both issuer and subject.

	filters := []string{
		`logName="projects/` + project + `/logs/federated-access-audit"`,
		`labels.token_subject="` + subject + `"`,
	}

	// TODO: Parse the filter into pieces and only allow AND and required subset.
	if req.GetFilter() != "" {
		filters = append(filters, "("+req.GetFilter()+")")
	}

	sdlReq := &lpb.ListLogEntriesRequest{
		ResourceNames: []string{"projects/" + project},
		PageSize:      req.GetPageSize(),
		PageToken:     req.GetPageToken(),
		OrderBy:       "timestamp desc",
		Filter:        strings.Join(filters, " AND "),
	}
	sdlResp, err := s.sdl.ListLogEntries(ctx, sdlReq)
	if err != nil {
		return nil, err
	}
	resp := &apb.ListAuditLogsResponse{}
	for _, e := range sdlResp.GetEntries() {
		a, err := ToAuditLog(e)
		if err != nil {
			glog.Warningf("ToAuditLog() failed: %v", err)
			continue
		}
		resp.AuditLogs = append(resp.AuditLogs, a)
	}
	return resp, nil
}

var (
	parentRE   = regexp.MustCompile("^users/([^/]*)$")
	resourceRE = regexp.MustCompile("^users/([^/]*)/auditlogs/([^/]*)$")
)
