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

package aws

import (
	"context"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
	"time"
)

// Run starts background processes of AccountWarehouse
func (wh *AccountWarehouse) Run(ctx context.Context)  {
	wh.keyGC.Run(ctx)
}

// Register AWS access key
func (wh *AccountWarehouse) RegisterAccountProject(project string, tx storage.Tx) error {
	_, err := wh.keyGC.RegisterWork(project, nil, tx)
	return err
}

func (wh *AccountWarehouse) UnregisterAccountProject(project string, tx storage.Tx) error {
	return wh.keyGC.UnregisterWork(project, tx)
}

func (wh *AccountWarehouse) UpdateSettings(maxRequestedTTL time.Duration, keysPerAccount int, tx storage.Tx) error  {
	return wh.keyGC.UpdateSettings(maxRequestedTTL, keysPerAccount, tx)
}
