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

// Package gcp abstracts interacting with certain aspects of Google Cloud
// Platform, such as creating service account keys and access tokens.
package aws

import (
	"context"
	"fmt"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/processgc"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil"
	v1 "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/cenkalti/backoff"
	"github.com/golang/glog"
	"sort"
	"strings"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
)

const (
	TemporaryCredMaxTtl = 12 * time.Hour
	S3ItemFormat        = "s3bucket"
	RedshiftItemFormat  = "redshift"
)

type principalType int

const (
	emptyPType principalType = iota
	userType
	roleType
)

type resourceType int

const (
	otherRType resourceType = iota
	bucketType
)

const (
	backoffInitialInterval     = 1 * time.Second
	backoffRandomizationFactor = 0.5
	backoffMultiplier          = 1.5
	backoffMaxInterval         = 3 * time.Second
	backoffMaxElapsedTime      = 10 * time.Second
)

//FIXME need to be moved to config, also the values
const (
	defaultGcFrequency = 1 * 24 * time.Hour
	defaultKeysPerAccount = 2
)

var (
	exponentialBackoff = &backoff.ExponentialBackOff{
		InitialInterval:     backoffInitialInterval,
		RandomizationFactor: backoffRandomizationFactor,
		Multiplier:          backoffMultiplier,
		MaxInterval:         backoffMaxInterval,
		MaxElapsedTime:      backoffMaxElapsedTime,
		Clock:               backoff.SystemClock,
	}
)

type ApiClient interface {
	ListUsers(input *iam.ListUsersInput) (*iam.ListUsersOutput, error)
	ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error)
	DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error)
	GetCallerIdentity(input *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error)
	AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error)
	CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error)
	PutRolePolicy(input *iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error)
	PutUserPolicy(input *iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error)
	GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error)
	CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error)
	GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error)
	CreateRole(input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error)
}

// AccountWarehouse is used to create AWS IAM Users and temporary credentials
type AccountWarehouse struct {
	svcUserArn string
	store      storage.Store
	tmp        map[string]iam.AccessKey
	keyGC      *processgc.KeyGC
	apiClient  ApiClient
}

// NewWarehouse creates a new AccountWarehouse using the provided client
// and options.
func NewWarehouse(ctx context.Context, store storage.Store, awsClient ApiClient) (*AccountWarehouse, error) {
	wh := &AccountWarehouse{
		store:     store,
		tmp:       make(map[string]iam.AccessKey),
		keyGC:     nil,
		apiClient: awsClient,
	}
	if gcio, err := awsClient.GetCallerIdentity(&sts.GetCallerIdentityInput{}); err != nil {
		return nil, err
	} else {
		wh.svcUserArn = *gcio.Arn
	}

	wh.keyGC = processgc.NewKeyGC("aws_key_gc", wh, store, defaultGcFrequency, defaultKeysPerAccount, func(account *clouds.Account) bool {
		return true
	})
	go wh.Run(ctx)
	return wh, nil
}

func (wh *AccountWarehouse) GetServiceAccounts(ctx context.Context, project string) (<-chan *clouds.Account, error) {
	c := make(chan *clouds.Account)
	go func() {
		defer close(c)
		f := func(acct *iam.User) error {
			a := &clouds.Account{
				ID:          aws.StringValue(acct.UserName),
				DisplayName: aws.StringValue(acct.UserName),
			}
			select {
			case c <- a:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		}
		// FIXME: get PathPrefix from config
		accounts, err := wh.apiClient.ListUsers(&iam.ListUsersInput{
			PathPrefix: aws.String("/ddap/"),
		})
		if err != nil {
			glog.Errorf("getting users list: %v", err)
			return
		}
		users := accounts.Users
		for _, user := range users {
			if err := f(user); err != nil {
				glog.Errorf("getting user accounts list: %v", err)
				return
			}
		}

	}()
	return c, nil
}

func (wh *AccountWarehouse) RemoveServiceAccount(ctx context.Context, project, accountID string) error {
	// TODO
	// Unlike the AWS Management Console, when
	//       you delete a user programmatically, you must delete the items  attached
	//       to  the user manually, or the deletion fails. For more information, see
	//       Deleting an IAM User . Before attempting to delete a user,  remove  the
	//       following items
	// Refer: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_users_manage.html#id_users_deleting_cli
	return fmt.Errorf("removing service accounts is not yet implemented")
}

//This method is the main method where key removal happens
func (wh *AccountWarehouse) ManageAccountKeys(ctx context.Context, project, accountID string, ttl, maxKeyTTL time.Duration, now time.Time, keysPerAccount int64) (int, int, error) {
	expired := now.Add(-1 * maxKeyTTL).Format(time.RFC3339)
	accessKeys, err := wh.apiClient.ListAccessKeys(&iam.ListAccessKeysInput{
		UserName: aws.String(accountID),
	})
	if err != nil {
		return 0, 0, fmt.Errorf("error getting aws key list: %v", err)
	}
	keys := accessKeys.AccessKeyMetadata
	var actives []*iam.AccessKeyMetadata
	active := len(keys)
	for _, key := range keys {
		t := timeutil.TimestampProto(aws.TimeValue(key.CreateDate))
		if timeutil.RFC3339(t) < expired {
			// Access key deletion
			_, err := wh.apiClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{
				AccessKeyId: key.AccessKeyId,
				UserName:    aws.String(accountID),
			})
			if err != nil {
				return active, len(keys) - active, fmt.Errorf("error deleting aws access key: %v", err)
			}
			active--
			continue
		}
		actives = append(actives, key)
	}

	if int64(len(actives)) < keysPerAccount {
		return active, len(keys) - active, nil
	}

	// Remove earliest expiring keys
	sort.Slice(actives, func(i, j int) bool {
		return aws.TimeValue(actives[i].CreateDate).After(aws.TimeValue(actives[j].CreateDate))
	})
	for _, key := range actives[keysPerAccount:] {
		_, err := wh.apiClient.DeleteAccessKey(&iam.DeleteAccessKeyInput{
			AccessKeyId: key.AccessKeyId,
			UserName:    aws.String(accountID),
		})
		if err != nil {
			return active, len(keys) - active, fmt.Errorf("deleting key: %v", err)
		}
		active--
	}
	return active, len(keys) - active, nil
}

type ResourceParams struct {
	UserId                string
	Ttl                   time.Duration
	MaxKeyTtl             time.Duration
	ManagedKeysPerAccount int
	Vars                  map[string]string
	TargetRoles           []string
	TargetScopes          []string
	DamResourceId         string
	DamViewId             string
	DamRoleId             string
	ServiceTemplate       *v1.ServiceTemplate
}

type resourceSpec struct {
	rType resourceType
	arn   string
	id    string
}

type principalSpec struct {
	pType principalType
	// Used for roles that must be assumed
	damPrincipalArn string
	params          *ResourceParams
}

type policySpec struct {
	principal *principalSpec
	rSpecs    []*resourceSpec
	params    *ResourceParams
}

func (spec *policySpec) getId() string {
	return spec.principal.getDamResourceViewRoleId()
}

func (spec *principalSpec) getId() string {
	switch spec.pType {
	case userType:
		return convertDamUserIdToAwsName(spec.params.UserId, spec.damPrincipalArn)
	case roleType:
		return spec.getDamResourceViewRoleId()
	default:
		panic(fmt.Sprintf("cannot get ID for princpal type [%v]", spec.pType))
	}
}

func (spec *principalSpec) getDamResourceViewRoleId() string {
	return fmt.Sprintf("%s,%s,%s@%s", spec.params.DamResourceId, spec.params.DamViewId, spec.params.DamRoleId, extractUserName(spec.damPrincipalArn))
}

func (spec *principalSpec) getArn() string {
	switch spec.pType {
	case userType:
		return fmt.Sprintf("arn:aws:iam::%s:user/%s", extractAccount(spec.damPrincipalArn), spec.getId())
	case roleType:
		return fmt.Sprintf("arn:aws:iam::%s:role/%s", extractAccount(spec.damPrincipalArn), spec.getId())
	default:
		panic(fmt.Sprintf("cannot get ID for princpal type [%v]", spec.pType))
	}
}

func calculateUserArn(clusterArn string, userName string) string {
	parts := strings.Split(clusterArn, ":")

	return fmt.Sprintf( "%s:%s:%s:%s:%s:dbuser:%s/%s", parts[0], parts[1], parts[2], parts[3], parts[4], parts[6], userName)
}

func extractAccount(arn string) string {
	parts := strings.Split(arn, ":")
	return parts[4]
}

func extractClusterName(arn string) string {
	parts := strings.Split(arn, ":")
	return parts[6]
}

func extractDBGroupName(arn string) string {
	arnParts := strings.Split(arn, ":")
	pathParts := strings.Split(arnParts[6], "/")

	return pathParts[len(pathParts)-1]
}

func RegisterAccountGC(store storage.Store, wh *AccountWarehouse) error {
	// IMPORTANT this transaction is closed in `process.go`
	// FIXME, maybe move this transaction creation closer to where it is used/closed?
	tx, err := store.Tx(true)
	if err != nil {
		return err
	}
	return wh.RegisterAccountProject(extractAccount(wh.svcUserArn), tx)
}

// MintTokenWithTTL returns an AccountKey or an AccessToken depending on the TTL requested.
func (wh *AccountWarehouse) MintTokenWithTTL(ctx context.Context, params *ResourceParams) (*clouds.AwsResourceTokenResult, error) {
	if params.Ttl > params.MaxKeyTtl {
		return nil, fmt.Errorf("given ttl [%s] is greater than max ttl [%s]", params.Ttl, params.MaxKeyTtl)
	}

	princSpec := determinePrincipalSpec(wh.svcUserArn, params)

	rSpecs, err := determineResourceSpecs(params)
	if err != nil {
		return nil, err
	}
	polSpec := &policySpec{
		principal: princSpec,
		rSpecs:    rSpecs,
		params:    params,
	}

	principalArn, err := wh.ensurePrincipal(princSpec)
	if err != nil {
		return nil, err
	}
	err = wh.ensurePolicy(polSpec)
	if err != nil {
		return nil, err
	}

	return wh.ensureTokenResult(ctx, principalArn, princSpec)
}

func determineResourceSpecs(params *ResourceParams) ([]*resourceSpec, error) {
	var rSpecs []*resourceSpec
	switch params.ServiceTemplate.ServiceName {
	case S3ItemFormat:
		bucket, ok := params.Vars["bucket"]
		if !ok {
			return nil, fmt.Errorf("no bucket specified")
		}
		rSpecs = []*resourceSpec{
			{
				id:    bucket,
				arn:   fmt.Sprintf("arn:aws:s3:::%s/*", bucket),
				rType: bucketType,
			},
		}
	case RedshiftItemFormat:
		clusterArn, ok := params.Vars["cluster"]
		if !ok {
			return nil, fmt.Errorf("no cluster specified")
		}
		clusterSpec := &resourceSpec{
			rType: otherRType,
			arn:   clusterArn,
			id:    extractClusterName(clusterArn),
		}
		dbuser := convertToAwsSafeIdentifier(params.UserId)
		userSpec := &resourceSpec{
			rType: otherRType,
			arn:   calculateUserArn(clusterArn, dbuser),
			id:    dbuser,
		}
		group, ok := params.Vars["group"]
		if ok {
			rSpecs = []*resourceSpec{
				clusterSpec,
				userSpec,
				{
					rType: otherRType,
					arn:   group,
					id:    extractDBGroupName(group),
				},
			}
		} else {
			rSpecs = []*resourceSpec{clusterSpec, userSpec}
		}

	default:
		return nil, fmt.Errorf("unrecognized item format [%s] for AWS target adapter", params.ServiceTemplate.ServiceName)
	}
	return rSpecs, nil
}

func determinePrincipalSpec(svcUserArn string, params *ResourceParams) *principalSpec {
	princSpec := &principalSpec{
		damPrincipalArn: svcUserArn,
		params:          params,
	}

	if params.Ttl > TemporaryCredMaxTtl {
		princSpec.pType = userType
	} else {
		princSpec.pType = roleType
	}
	return princSpec
}

func (wh *AccountWarehouse) ensureTokenResult(ctx context.Context, principalArn string, princSpec *principalSpec) (*clouds.AwsResourceTokenResult, error) {
	switch princSpec.pType {
	case userType:
		return wh.ensureAccessKeyResult(ctx, principalArn, princSpec)
	case roleType:
		return wh.createTempCredentialResult(principalArn, princSpec.params)
	default:
		return nil, fmt.Errorf("cannot generate token for invalid spec with [%v] principal type", princSpec.pType)
	}
}

func(wh *AccountWarehouse) createTempCredentialResult(principalArn string, params *ResourceParams) (*clouds.AwsResourceTokenResult, error) {
	userId := convertDamUserIdToAwsName(params.UserId, wh.svcUserArn)
	aro, err := wh.assumeRole(userId, principalArn, params.Ttl)
	if err != nil {
		return nil, err
	}
	return &clouds.AwsResourceTokenResult{
		Account: *aro.AssumedRoleUser.Arn,
		AccessKeyId:   *aro.Credentials.AccessKeyId,
		SecretAccessKey:   *aro.Credentials.SecretAccessKey,
		SessionToken:   *aro.Credentials.SessionToken,
		Format:  "aws",
	}, nil
}

func (wh *AccountWarehouse) ensureAccessKeyResult(ctx context.Context, principalArn string, princSpec *principalSpec) (*clouds.AwsResourceTokenResult, error) {
	accessKey, err := wh.ensureAccessKey(ctx, princSpec, wh.svcUserArn)
	if err != nil {
		return nil, err
	}
	return &clouds.AwsResourceTokenResult{
		Account: principalArn,
		AccessKeyId: *accessKey.AccessKeyId,
		SecretAccessKey: *accessKey.SecretAccessKey,
		Format:  "aws",
	}, nil
}

func(wh *AccountWarehouse) ensurePrincipal(princSpec *principalSpec) (string, error) {
	if princSpec.params.Ttl > TemporaryCredMaxTtl {
		return wh.ensureUser(princSpec)
	} else {
		return wh.ensureRole(princSpec)
	}
}

func(wh *AccountWarehouse) ensurePolicy(spec *policySpec) error {
	if len(spec.rSpecs) == 0 {
		return fmt.Errorf("cannot have policy without any resources")
	} else {
		return wh.ensureIdentityBasedPolicy(spec)
	}
}

func(wh *AccountWarehouse) ensureIdentityBasedPolicy(spec *policySpec) error {
	switch spec.principal.pType {
	case userType:
		return wh.ensureUserPolicy(spec)
	case roleType:
		return wh.ensureRolePolicy(spec)
	default:
		return fmt.Errorf("cannot generate policy for invalid spec with [%v] principal type", spec.principal.pType)
	}
}

func convertDamUserIdToAwsName(damUserId, damSvcArn string) string{
	parts := strings.SplitN(damUserId, "|", 2)
	sessionName := parts[0] + "@" + extractUserName(damSvcArn)
	maxLen := 64
	if len(sessionName) < 64 {
		maxLen = len(sessionName)
	}
	return sessionName[0:maxLen]
}

func convertToAwsSafeIdentifier(val string) string {
	return strings.ReplaceAll(val, "|", "@")
}

func(wh *AccountWarehouse) assumeRole(sessionName string, roleArn string, ttl time.Duration) (*sts.AssumeRoleOutput, error) {
	var aro *sts.AssumeRoleOutput
	f := func() error {
		var err error
		aro, err = wh.apiClient.AssumeRole(&sts.AssumeRoleInput{
			RoleArn:         aws.String(roleArn),
			RoleSessionName: aws.String(sessionName),
			DurationSeconds: toSeconds(ttl),
		})

		return err
	}

	err := backoff.Retry(f, exponentialBackoff)
	if err != nil {
		return nil, fmt.Errorf("unable to assume role %s: %v", roleArn, err)
	} else {
		return aro, nil
	}
}

func (wh *AccountWarehouse) ensureAccessKey(ctx context.Context, princSpec *principalSpec, svcUserArn string) (iam.AccessKey, error) {
	// garbage collection call
	makeRoom := princSpec.params.ManagedKeysPerAccount - 1
	keyTTL := timeutil.KeyTTL(princSpec.params.MaxKeyTtl, princSpec.params.ManagedKeysPerAccount)
	userId := princSpec.getId()
	if _, _, err := wh.ManageAccountKeys(ctx, svcUserArn, userId, princSpec.params.Ttl, keyTTL, time.Now(), int64(makeRoom)); err != nil {
		return iam.AccessKey{}, fmt.Errorf("garbage collecting keys: %v", err)
	}
	accessKey, ok := wh.tmp[userId]
	if !ok {
		kres, err := wh.apiClient.CreateAccessKey(&iam.CreateAccessKeyInput{
			UserName: aws.String(userId),
		})
		if err != nil {
			return iam.AccessKey{}, fmt.Errorf("unable to create access key for user %s: %v", userId, err)
		}
		accessKey = *kres.AccessKey
		wh.tmp[userId] = accessKey
	}
	return accessKey, nil
}

func(wh *AccountWarehouse) ensureRolePolicy(spec *policySpec) error {
	// FIXME handle versioning
	actions := valuesToJsonStringArray(spec.params.TargetRoles)
	resourceArns := resourceArnsToJsonStringArray(spec.rSpecs)
	// FIXME use serialization library
	policy := fmt.Sprintf(
		`{
								"Version":"2012-10-17",
								"Statement":
								{
									"Effect":"Allow",
									"Action":%s,
									"Resource":%s
								}
							}`, actions, resourceArns)
	f := func() error { return wh.putRolePolicy(spec, policy) }
	return backoff.Retry(f, exponentialBackoff)
}

func (wh *AccountWarehouse) putRolePolicy(spec *policySpec, policy string) error {
	_, err := wh.apiClient.PutRolePolicy(&iam.PutRolePolicyInput{
		PolicyName:     aws.String(spec.getId()),
		RoleName:       aws.String(spec.principal.getId()),
		PolicyDocument: aws.String(policy),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "MalformedPolicy" && strings.Contains(aerr.Message(), "Invalid principal in policy") {
			return fmt.Errorf("unable to create AWS user policy %s: %v", spec.principal.getId(), err)
		} else {
			return backoff.Permanent(fmt.Errorf("unable to create AWS role policy %s: %v", spec.principal.getId(), err))
		}
	} else {
		return nil
	}
}

func(wh *AccountWarehouse) ensureUserPolicy(spec *policySpec) error {
	// FIXME handle versioning
	actions := valuesToJsonStringArray(spec.params.TargetRoles)
	resources := resourceArnsToJsonStringArray(spec.rSpecs)
	// FIXME use serialization library
	policy := fmt.Sprintf(
		`{
								"Version":"2012-10-17",
								"Statement":
								{
									"Effect":"Allow",
									"Action":%s,
									"Resource":%s,
									"Condition": {
										"DateLessThanEquals": {"aws:CurrentTime": "%s"}
									}
								}
							}`, actions, resources, (time.Now().Add(spec.params.Ttl)).Format(time.RFC3339) )
	f := func() error { return wh.putUserPolicy(spec, policy) }
	return backoff.Retry(f, exponentialBackoff)
}

func(wh *AccountWarehouse) putUserPolicy(spec *policySpec, policy string) error {
	_, err := wh.apiClient.PutUserPolicy(&iam.PutUserPolicyInput{
		PolicyName:     aws.String(spec.getId()),
		UserName:       aws.String(spec.principal.getId()),
		PolicyDocument: aws.String(policy),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == "MalformedPolicy" && strings.Contains(aerr.Message(), "Invalid principal in policy") {
			return fmt.Errorf("unable to create AWS user policy %s: %v", spec.principal.getId(), err)
		} else {
			return backoff.Permanent(fmt.Errorf("unable to create AWS user policy %s: %v", spec.principal.getId(), err))
		}
	} else {
		return nil
	}
}


// ensures user is created and returns non-empty user ARN if successful
func(wh *AccountWarehouse) ensureUser(spec *principalSpec) (string, error) {
	var userArn string
	guo, err := wh.apiClient.GetUser(&iam.GetUserInput{
		UserName: aws.String(spec.getId()),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == iam.ErrCodeNoSuchEntityException {
			cuo, err := wh.apiClient.CreateUser(&iam.CreateUserInput{
				UserName: aws.String(spec.getId()),
				// TODO: Make prefix configurable for different dam deployments GcpServiceAccountProject
				Path: aws.String("/ddap/"),
			})
			if err != nil {
				return "", fmt.Errorf("unable to create IAM user %s: %v", spec.getId(), err)
			} else {
				userArn = *cuo.User.Arn
			}
		} else {
			return "", fmt.Errorf("unable to send AWS IAM request for user %s: %v", spec.getId(), err)
		}
	} else {
		userArn = *guo.User.Arn
		fmt.Printf("USER: %v \n", aws.StringValue(guo.User.UserName))
	}
	return userArn, nil
}

func(wh *AccountWarehouse) ensureRole(spec *principalSpec) (string, error) {
	gro, err := wh.apiClient.GetRole(&iam.GetRoleInput{
		RoleName: aws.String(spec.getId()),
	})
	if err != nil {
		if aerr, ok := err.(awserr.Error); ok && aerr.Code() == iam.ErrCodeNoSuchEntityException {
			policy := fmt.Sprintf(
				`{
								"Version":"2012-10-17",
								"Statement":
								{
									"Effect":"Allow",
									"Principal": { "AWS": "%s" },
									"Action": "sts:AssumeRole"
								}
							}`, spec.damPrincipalArn)
			cro, err := wh.apiClient.CreateRole(&iam.CreateRoleInput{
				AssumeRolePolicyDocument: aws.String(policy),
				RoleName:                 aws.String(spec.getId()),
				// FIXME should get path from config
				Path:                     aws.String("/ddap/"),
				MaxSessionDuration:       toSeconds(TemporaryCredMaxTtl),
				Tags: []*iam.Tag{
					{
						Key:   aws.String("DamResource"),
						Value: aws.String(spec.params.DamResourceId),
					},
					{
						Key:   aws.String("DamView"),
						Value: aws.String(spec.params.DamViewId),
					},
					{
						Key:   aws.String("DamRole"),
						Value: aws.String(spec.params.DamRoleId),
					},
				},
			})
			if err != nil {
				return "", fmt.Errorf("unable to create AWS role %s: %v", spec.getId(), err)
			} else {
				return *cro.Role.Arn, nil
			}
		} else {
			return "", fmt.Errorf("unable to retrieve AWS role %s: %v", spec.getId(), err)
		}
	} else {
		return *gro.Role.Arn, nil
	}
}

func extractUserName(userArn string) string {
	arnParts := strings.Split(userArn, ":")
	pathParts := strings.Split(arnParts[5], "/")

	return pathParts[len(pathParts)-1]
}

func toSeconds(duration time.Duration) *int64 {
	seconds := duration.Nanoseconds() / time.Second.Nanoseconds()
	return &seconds
}

func resourceArnsToJsonStringArray(rSpecs []*resourceSpec) string {
	arns := make([]string, len(rSpecs))
	for i, rSpec := range rSpecs {
		arns[i] = rSpec.arn
	}

	return valuesToJsonStringArray(arns)
}

func valuesToJsonStringArray(targetRoles []string) string {
	builder := strings.Builder{}
	builder.WriteByte('[')
	for i, role := range targetRoles {
		builder.WriteByte('"')
		builder.WriteString(role)
		builder.WriteByte('"')
		if (i + 1) < len(targetRoles) {
			builder.WriteByte(',')
		}
	}
	builder.WriteByte(']')

	return builder.String()
}
