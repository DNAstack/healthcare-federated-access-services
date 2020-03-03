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

package dam

import (
	"net/http"

	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

func (s *Service) realmFactory() *handlerfactory.HandlerFactory {
	return &handlerfactory.HandlerFactory{
		TypeName:            "realm",
		NameField:           "realm",
		PathPrefix:          realmPath,
		HasNamedIdentifiers: true,
		NewHandler: func(r *http.Request) handlerfactory.HandlerInterface {
			return newRealmHandler(s, r)
		},
	}
}

type realmHandler struct {
	s     *Service
	r     *http.Request
	input *pb.RealmRequest
	item  *pb.Realm
	cfg   *pb.DamConfig
	id    *ga4gh.Identity
	tx    storage.Tx
}

func newRealmHandler(s *Service, r *http.Request) *realmHandler {
	return &realmHandler{
		s:     s,
		r:     r,
		input: &pb.RealmRequest{},
	}
}

func (h *realmHandler) Setup(tx storage.Tx) (int, error) {
	cfg, id, status, err := h.s.handlerSetup(tx, h.r, noScope, h.input)
	h.cfg = cfg
	h.id = id
	h.tx = tx
	return status, err
}

func (h *realmHandler) LookupItem(name string, vars map[string]string) bool {
	// Accept any name that passes the name check.
	h.item = &pb.Realm{}
	return true
}

func (h *realmHandler) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(h.input, h.r); err != nil {
		return err
	}
	if h.input.Item == nil {
		h.input.Item = &pb.Realm{}
	}
	return nil
}

func (h *realmHandler) Get(name string) (proto.Message, error) {
	if h.item != nil {
		return h.item, nil
	}
	return nil, nil
}

func (h *realmHandler) Post(name string) (proto.Message, error) {
	// Accept, but do nothing.
	return nil, nil
}

func (h *realmHandler) Put(name string) (proto.Message, error) {
	// Accept, but do nothing.
	return nil, nil
}

func (h *realmHandler) Patch(name string) (proto.Message, error) {
	// Accept, but do nothing.
	return nil, nil
}

func (h *realmHandler) Remove(name string) (proto.Message, error) {
	if err := h.s.store.Wipe(name); err != nil {
		return nil, err
	}
	if name == storage.DefaultRealm {
		return nil, ImportConfig(h.s.store, h.s.serviceName, h.s.warehouse, nil)
	}
	cfg, err := h.s.loadConfig(h.tx, storage.DefaultRealm)
	if err != nil {
		return nil, err
	}
	if cfg.Options.GcpServiceAccountProject != h.cfg.Options.GcpServiceAccountProject {
		return nil, h.s.unregisterProject(h.cfg.Options.GcpServiceAccountProject, h.tx)
	}
	return nil, nil
}

func (h *realmHandler) CheckIntegrity() *status.Status {
	return nil
}

func (h *realmHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	// Accept, but do nothing.
	return nil
}
