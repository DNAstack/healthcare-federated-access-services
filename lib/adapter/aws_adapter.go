package adapter

import (
	"context"
	"fmt"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/aws"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/processgc"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/srcutil"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

const (
	// AwsAdapterName is the name identifier exposed in config files.
	AwsAdapterName = "aws"
	platformName   = "aws"
)

// TODO: need to be moved to config, also the values
const (
	defaultGcFrequency    = 1 * 24 * time.Hour /* 1 day */
	defaultKeysPerAccount = 2
)

// AwsAdapter is the AWS IAM adapter.
type AwsAdapter struct {
	desc      map[string]*pb.ServiceDescriptor
	warehouse *aws.AccountWarehouse
}

// NewAwsAdapter creates a new AwsAdapter.
func NewAwsAdapter(store storage.Store, awsClient aws.APIClient) (ServiceAdapter, error) {
	var msg pb.ServicesResponse
	path := adapterFilePath(AwsAdapterName)
	if err := srcutil.LoadProto(path, &msg); err != nil {
		return nil, fmt.Errorf("reading %q service descriptors from path %q: %v", aggregatorName, path, err)
	}

	ctx := context.Background()
	wh, err := aws.NewWarehouse(ctx, awsClient)
	if err != nil {
		return nil, fmt.Errorf("error creating AWS key warehouse: %v", err)
	}

	keyGC := processgc.NewKeyGC("aws_key_gc", wh, store, defaultGcFrequency, defaultKeysPerAccount, func(account *clouds.Account) bool {
		return true
	})
	//Register Accounts
	if err := registerAccountGC(store, keyGC, wh); err != nil {
		return nil, fmt.Errorf("error registering AWS account key GC: %v", err)
	}

	// Update Settings
	ttl := defaultGcFrequency
	if err := keyGC.UpdateSettings(ttl, defaultKeysPerAccount, nil); err != nil {
		return nil, fmt.Errorf("error updating settings: %v", err)
	}
	go keyGC.Run(ctx)

	return &AwsAdapter{
		desc:      msg.Services,
		warehouse: wh,
	}, nil
}

// Name returns the name identifier of the adapter as used in configurations.
func (a *AwsAdapter) Name() string {
	return AwsAdapterName
}

// Descriptors returns a map of ServiceDescriptor descriptor.
func (a *AwsAdapter) Descriptors() map[string]*pb.ServiceDescriptor {
	return a.desc
}

// Platform returns the name identifier of the platform on which this adapter operates.
func (a *AwsAdapter) Platform() string {
	return platformName
}

// IsAggregator returns true if this adapter requires TokenAction.Aggregates.
func (a *AwsAdapter) IsAggregator() bool {
	return false
}

// CheckConfig validates that a new configuration is compatible with this adapter.
func (a *AwsAdapter) CheckConfig(_ string, _ *pb.ServiceTemplate, _, _ string, _ *pb.View, _ *pb.DamConfig, _ *ServiceAdapters) (string, error) {
	return "", nil
}

// MintToken has the adapter mint a token.
func (a *AwsAdapter) MintToken(ctx context.Context, input *Action) (*MintTokenResult, error) {
	if a.warehouse == nil {
		return nil, fmt.Errorf("AWS minting token: DAM service account warehouse not configured")
	}
	userID := ga4gh.TokenUserID(input.Identity, SawMaxUserIDLength)
	params, err := createAwsResourceTokenCreationParams(userID, input)
	if err != nil {
		return nil, fmt.Errorf("AWS minting token: %v", err)
	}
	result, err := a.warehouse.MintTokenWithTTL(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("AWS minting token: %v", err)
	}

	return &MintTokenResult{
		Credentials: map[string]string{
			"account":       result.Account,
			"access_key_id": result.AccessKeyID,
			"secret":        result.SecretAccessKey,
			"session_token": result.SessionToken,
		},
		TokenFormat: result.Format,
	}, nil
}

func createAwsResourceTokenCreationParams(userID string, input *Action) (*aws.ResourceParams, error) {
	var roles []string
	var scopes []string
	if input.ServiceRole != nil {
		rolesArg := input.ServiceRole.ServiceArgs["roles"]
		if rolesArg != nil && rolesArg.GetValues() != nil && len(rolesArg.GetValues()) > 0 {
			roles = append(roles, rolesArg.GetValues()...)
		}
		scopesArg := input.ServiceRole.ServiceArgs["scopes"]
		if scopesArg != nil && scopesArg.GetValues() != nil && len(scopesArg.GetValues()) > 0 {
			scopes = append(scopes, scopesArg.GetValues()...)
		}
	}
	var vars map[string]string
	if len(input.View.Items) == 0 {
		vars = make(map[string]string, 0)
	} else if len(input.View.Items) == 1 {
		vars = scrubVars(input.View.Items[0].Args)
	} else {
		return nil, fmt.Errorf("too many items declared")
	}
	maxKeyTTL := timeutil.ParseDurationWithDefault(input.Config.Options.GcpManagedKeysMaxRequestedTtl, input.MaxTTL)

	return &aws.ResourceParams{
		UserID:                userID,
		TTL:                   input.TTL,
		MaxKeyTTL:             maxKeyTTL,
		ManagedKeysPerAccount: int(input.Config.Options.GcpManagedKeysPerAccount),
		Vars:                  vars,
		TargetRoles:           roles,
		TargetScopes:          scopes,
		DamResourceID:         input.ResourceID,
		DamViewID:             input.ViewID,
		DamRoleID:             input.GrantRole,
		ServiceTemplate:       input.ServiceTemplate,
	}, nil
}

func registerAccountGC(_ storage.Store, keyGC *processgc.KeyGC, wh *aws.AccountWarehouse) error {
	_, err := keyGC.RegisterWork(wh.GetAwsAccount(), nil, nil)
	return err
}
