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
