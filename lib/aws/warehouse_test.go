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
	"fmt"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/clouds"
	v1 "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
	"math/rand"
	"strings"
	"testing"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakestore" /* copybara-comment: fakestore */
)

func NewMockApiClient(account string, userId string) *MockAwsClient {
	return &MockAwsClient{
		Account:       account,
		UserId:        userId,
	}
}

// Mock AWS Client
type MockAwsClient struct {
	Account      string
	UserId       string
	Roles        []*iam.Role
	RolePolicies []*iam.PutRolePolicyInput
	Users        []*iam.User
	UserPolicies []*iam.PutUserPolicyInput
	AccessKeys   []*iam.AccessKey
}

func (m *MockAwsClient) ListUsers(input *iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	panic("implement me")
}

func (m *MockAwsClient) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	if _, err := m.GetUser(&iam.GetUserInput{UserName: input.UserName}); err != nil {
		return nil, err
	}

	var list []*iam.AccessKey
	for _, key := range m.AccessKeys {
		if *key.UserName == *input.UserName {
			list = append(list, key)
		}
	}

	return &iam.ListAccessKeysOutput{
		AccessKeyMetadata: []*iam.AccessKeyMetadata{},
		IsTruncated:       aws.Bool(false),
		Marker:            nil,
	}, nil
}

func (m *MockAwsClient) DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	panic("implement me")
}

func (m *MockAwsClient) GetCallerIdentity(_ *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	return &sts.GetCallerIdentityOutput{
		Account: &m.Account,
		Arn:     aws.String(fmt.Sprintf("arn:aws:iam::%s:user/%s", m.Account, m.UserId)),
		UserId:  &m.UserId,
	}, nil
}

func (m *MockAwsClient) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	for _, role := range m.Roles {
		if *input.RoleArn == *role.Arn {
			duration := time.Duration(*input.DurationSeconds) * time.Second
			cred := fmt.Sprintf("%s-%d", time.Now().String(), rand.Int())
			return &sts.AssumeRoleOutput{
				AssumedRoleUser: &sts.AssumedRoleUser{
					Arn:           input.RoleArn,
					AssumedRoleId: role.RoleId,
				},
				Credentials: &sts.Credentials{
					AccessKeyId:     aws.String(cred + "-id"),
					Expiration:      aws.Time(time.Now().Add(duration)),
					SecretAccessKey: aws.String(cred + "-key"),
					SessionToken:    aws.String(cred + "-session-token"),
				},
				PackedPolicySize: aws.Int64(0),
			}, nil
		}
	}

	return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "shouldn't depend on this message", nil)
}

func (m *MockAwsClient) CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	if _, err := m.GetUser(&iam.GetUserInput{UserName: input.UserName}); err != nil {
		return nil, err
	}

	cred := fmt.Sprintf("%s-%d", time.Now().String(), rand.Int())
	key := &iam.AccessKey{
		AccessKeyId:     aws.String(cred + "-id"),
		CreateDate:      aws.Time(time.Now()),
		SecretAccessKey: aws.String(cred + "-key"),
		Status:          aws.String("Active"),
		UserName:        input.UserName,
	}
	m.AccessKeys = append(m.AccessKeys, key)

	return &iam.CreateAccessKeyOutput{
		AccessKey: key,
	}, nil
}

func (m *MockAwsClient) PutRolePolicy(input *iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
	if _, err := m.GetRole(&iam.GetRoleInput{RoleName: input.RoleName}); err != nil {
		return nil, err
	} else {
		m.RolePolicies = append(m.RolePolicies, input)
		return &iam.PutRolePolicyOutput{}, nil
	}
}

func (m *MockAwsClient) PutUserPolicy(input *iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error) {
	if _, err := m.GetUser(&iam.GetUserInput{UserName: input.UserName}); err != nil {
		return nil, err
	} else {
		m.UserPolicies = append(m.UserPolicies, input)
		return &iam.PutUserPolicyOutput{}, nil
	}
}

func (m *MockAwsClient) GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error) {
	for _, user := range m.Users {
		if *input.UserName == *user.UserName {
			return &iam.GetUserOutput{
				User: user,
			}, nil
		}
	}

	return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "shouldn't depend on this message", nil)
}

func (m *MockAwsClient) CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	if user, _ := m.GetUser(&iam.GetUserInput{UserName: input.UserName}); user != nil {
		return nil, awserr.New(iam.ErrCodeEntityAlreadyExistsException, "shouldn't depend on this message", nil)
	}

	var nameWithPath string
	if input.Path != nil {
		nameWithPath = *input.UserName
	} else {
		nameWithPath = (*input.Path)[1:] + *input.UserName
	}
	user := &iam.User{
		Arn:                 aws.String(fmt.Sprintf("arn:aws:iam::%s:user/%s", m.Account, nameWithPath)),
		CreateDate:          aws.Time(time.Now()),
		PasswordLastUsed:    nil,
		Path:                input.Path,
		PermissionsBoundary: nil,
		Tags:                input.Tags,
		UserId:              aws.String(nameWithPath),
		UserName:            input.UserName,
	}
	m.Users = append(m.Users, user)

	return &iam.CreateUserOutput{
		User: user,
	}, nil
}

func (m *MockAwsClient) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	for _, role := range m.Roles {
		if *role.RoleName == *input.RoleName {
			return &iam.GetRoleOutput{
				Role: role,
			}, nil
		}
	}

	return nil, awserr.New(iam.ErrCodeNoSuchEntityException, "shouldn't depend on this message", nil)
}

func (m *MockAwsClient) CreateRole(input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	if role, _ := m.GetRole(&iam.GetRoleInput{RoleName: input.RoleName}); role != nil {
		return nil, awserr.New(iam.ErrCodeEntityAlreadyExistsException, "shouldn't depend on this message", nil)
	}

	var nameWithPath string
	if input.Path == nil {
		nameWithPath = *input.RoleName
	} else {
		nameWithPath = (*input.Path)[1:] + *input.RoleName
	}

	role := &iam.Role{
		Arn:                      aws.String(fmt.Sprintf("arn:aws:iam::%s:role/%s", m.Account, nameWithPath)),
		AssumeRolePolicyDocument: input.AssumeRolePolicyDocument,
		Description:              input.Description,
		MaxSessionDuration:       input.MaxSessionDuration,
		Path:                     input.Path,
		PermissionsBoundary:      nil,
		RoleId:                   aws.String(nameWithPath),
		RoleName:                 input.RoleName,
		Tags:                     input.Tags,
	}
	m.Roles = append(m.Roles, role)

	return &iam.CreateRoleOutput{
		Role: role,
	}, nil
}
// end Mock AWS Client

func TestNewAwsWarehouse(t *testing.T) {
	store := fakestore.New()
	apiClient := NewMockApiClient("12345678", "dam-user-id")
	wh, err := NewWarehouse(context.Background(), store, apiClient)

	if err != nil {
		t.Errorf("expected no error but observed: %v", err)
	}
	if wh == nil {
		t.Errorf("expected non-nil warehouse")
	}
}

func TestAWS_MintTokenWithShortLivedTTL_Bucket(t *testing.T) {
	store := fakestore.New()
	apiClient := NewMockApiClient("12345678", "dam-user-id")
	wh, _ := NewWarehouse(context.Background(), store, apiClient)

	vars := map[string]string{
		"bucket": "test-bucket-name",
	}
	serviceTemplate := &v1.ServiceTemplate{
		ServiceName: "s3bucket",
	}

	params := &ResourceParams{
		UserId:                "ic_abc123|fake-ic",
		Ttl:                   time.Hour,
		MaxKeyTtl:             (24 * 30) * time.Hour,
		ManagedKeysPerAccount: 2,
		Vars:                  vars,
		TargetRoles:           []string{"s3:GetObject"},
		TargetScopes:          []string{},
		DamResourceId:         "res-id",
		DamViewId:             "view-id",
		DamRoleId:             "role-id",
		ServiceTemplate:       serviceTemplate,
	}

	result, err := wh.MintTokenWithTTL(context.Background(), params)

	expectedAccount := fmt.Sprintf("%s,%s,%s", params.DamResourceId, params.DamViewId, params.DamRoleId)
	validateMintedRoleCredentials(t, expectedAccount, result, err)
	validateCreatedRolePolicy(t, apiClient, expectedAccount, params.TargetRoles)
}

func TestAWS_MintTokenWithShortLivedTTL_Redshift(t *testing.T) {
	store := fakestore.New()
	apiClient := NewMockApiClient("12345678", "dam-user-id")
	wh, _ := NewWarehouse(context.Background(), store, apiClient)

	vars := map[string]string{
		"cluster": "arn:aws:redshift:us-east-1:12345678:cluster:test-cluster",
		"group": "arn:aws:redshift:us-east-1:12345678:dbgroup:test-cluster/admin",
	}
	serviceTemplate := &v1.ServiceTemplate{
		ServiceName: "redshift",
	}
	roles := []string{
		"redshift:GetClusterCredentials",
		"redshift:CreateClusterUser",
		"redshift:JoinGroup",
	}

	params := &ResourceParams{
		UserId:                "ic_abc123|fake-ic",
		Ttl:                   time.Hour,
		MaxKeyTtl:             (24 * 30) * time.Hour,
		ManagedKeysPerAccount: 2,
		Vars:                  vars,
		TargetRoles:           roles,
		TargetScopes:          []string{},
		DamResourceId:         "res-id",
		DamViewId:             "view-id",
		DamRoleId:             "role-id",
		ServiceTemplate:       serviceTemplate,
	}

	result, err := wh.MintTokenWithTTL(context.Background(), params)

	expectedAccount := fmt.Sprintf("%s,%s,%s", params.DamResourceId, params.DamViewId, params.DamRoleId)
	validateMintedRoleCredentials(t, expectedAccount, result, err)
	validateCreatedRolePolicy(t, apiClient, expectedAccount, params.TargetRoles)
}

func TestAWS_MintTokenWithLongLivedTTL_Bucket(t *testing.T) {
	store := fakestore.New()
	awsAccount := "12345678"
	apiClient := NewMockApiClient(awsAccount, "dam-user-id")
	wh, _ := NewWarehouse(context.Background(), store, apiClient)

	vars := map[string]string{
		"bucket": "test-bucket-name",
	}
	serviceTemplate := &v1.ServiceTemplate{
		ServiceName: "s3bucket",
	}

	params := &ResourceParams{
		UserId:                "ic_abc123|fake-ic",
		Ttl:                   13 * time.Hour, // AWS has 12-hour threshold for role access tokens
		MaxKeyTtl:             (24 * 30) * time.Hour,
		ManagedKeysPerAccount: 2,
		Vars:                  vars,
		TargetRoles:           []string{"s3:GetObject"},
		TargetScopes:          []string{},
		DamResourceId:         "res-id",
		DamViewId:             "view-id",
		DamRoleId:             "role-id",
		ServiceTemplate:       serviceTemplate,
	}

	result, err := wh.MintTokenWithTTL(context.Background(), params)

	expectedUserName := "ic_abc123@fake-ic"
	expectedUserArn := fmt.Sprintf("arn:aws:iam::%s:user/%s", awsAccount, expectedUserName)
	validateMintedAccessKey(t, expectedUserArn, result, err)
	validateCreatedUserPolicy(t, apiClient, expectedUserName, params.TargetRoles)
}

func TestAWS_MintTokenWithLongLivedTTL_Redshift(t *testing.T) {
	store := fakestore.New()
	awsAccount := "12345678"
	apiClient := NewMockApiClient(awsAccount, "dam-user-id")
	wh, _ := NewWarehouse(context.Background(), store, apiClient)

	vars := map[string]string{
		"cluster": "arn:aws:redshift:us-east-1:12345678:cluster:test-cluster",
		"group": "arn:aws:redshift:us-east-1:12345678:dbgroup:test-cluster/admin",
	}
	serviceTemplate := &v1.ServiceTemplate{
		ServiceName: "redshift",
	}
	roles := []string{
		"redshift:GetClusterCredentials",
		"redshift:CreateClusterUser",
		"redshift:JoinGroup",
	}

	params := &ResourceParams{
		UserId:                "ic_abc123|fake-ic",
		Ttl:                   13 * time.Hour, // AWS has 12-hour threshold for role access tokens
		MaxKeyTtl:             (24 * 30) * time.Hour,
		ManagedKeysPerAccount: 2,
		Vars:                  vars,
		TargetRoles:           roles,
		TargetScopes:          []string{},
		DamResourceId:         "res-id",
		DamViewId:             "view-id",
		DamRoleId:             "role-id",
		ServiceTemplate:       serviceTemplate,
	}

	result, err := wh.MintTokenWithTTL(context.Background(), params)

	expectedUserName := "ic_abc123@fake-ic"
	expectedUserArn := fmt.Sprintf("arn:aws:iam::%s:user/%s", awsAccount, expectedUserName)
	validateMintedAccessKey(t, expectedUserArn, result, err)
	validateCreatedUserPolicy(t, apiClient, expectedUserName, params.TargetRoles)
}

func validateMintedRoleCredentials(t *testing.T, expectedAccount string, result *clouds.AwsResourceTokenResult, err error) {
	if err != nil {
		t.Errorf("expected minting a token but got error: %v", err)
		return
	}
	if result == nil {
		t.Error("expected non-nil result but result was nil")
		return
	}

	if result.Account != expectedAccount {
		t.Errorf("expected account [%s] but observed [%s]", expectedAccount, result.Account)
	}
	if !strings.HasSuffix(result.AccessKeyId, "-id") {
		t.Errorf("expected AccessKeyId to be mocked id value but was [%s]", result.AccessKeyId)
	}
	if !strings.HasSuffix(result.SecretAccessKey, "-key") {
		t.Errorf("expected SecretAccessKey to be mocked key value but was [%s]", result.SecretAccessKey)
	}
	if !strings.HasSuffix(result.SessionToken, "-session-token") {
		t.Errorf("expected SessionToken to be mocked session token value but was [%s]", result.SessionToken)
	}
}

func validateMintedAccessKey(t *testing.T, expectedAccount string, result *clouds.AwsResourceTokenResult, err error) {
	if err != nil {
		t.Errorf("expected minting a token but got error: %v", err)
		return
	}
	if result == nil {
		t.Error("expected non-nil result but result was nil")
		return
	}

	if result.Account != expectedAccount {
		t.Errorf("expected account [%s] but observed [%s]", expectedAccount, result.Account)
	}
	if !strings.HasSuffix(result.AccessKeyId, "-id") {
		t.Errorf("expected AccessKeyId to be mocked id value but was [%s]", result.AccessKeyId)
	}
	if !strings.HasSuffix(result.SecretAccessKey, "-key") {
		t.Errorf("expected SecretAccessKey to be mocked key value but was [%s]", result.SecretAccessKey)
	}
	if result.SessionToken != "" {
		t.Errorf("expected SessionToken to be empty for access key but was [%s]", result.SessionToken)
	}
}

func validateCreatedRolePolicy(t *testing.T, apiClient *MockAwsClient, expectedAccount string, targetRoles []string) {
	if len(apiClient.Roles) != 1 {
		t.Errorf("expected a single role to be created but found %v", apiClient.Roles)
	} else {
		role := apiClient.Roles[0]
		if *role.RoleName != expectedAccount {
			t.Errorf("expected created role name to be [%s] but was [%s]", expectedAccount, *role.RoleName)
		}
	}

	if len(apiClient.RolePolicies) != 1 {
		t.Errorf("expected a single role policy to be created but found %v", apiClient.RolePolicies)
	} else {
		policy := apiClient.RolePolicies[0]
		if *policy.RoleName != expectedAccount {
			t.Errorf("expected policy to be created for role [%s] but was created for role [%s]",
				expectedAccount,
				*policy.RoleName)
		}
		for _, targetRole := range targetRoles {
			if !strings.Contains(*policy.PolicyDocument, targetRole) {
				t.Errorf("expected policy document to contain target role [%s] but this was the policy document:\n%s",
					targetRole,
					*policy.PolicyDocument)
			}
		}
	}
}

func validateCreatedUserPolicy(t *testing.T, apiClient *MockAwsClient, expectedAccount string, targetRoles []string) {
	if len(apiClient.Users) != 1 {
		t.Errorf("expected a single user to be created but found %v", apiClient.Users)
	} else {
		user := apiClient.Users[0]
		if *user.UserName != expectedAccount {
			t.Errorf("expected created user name to be [%s] but was [%s]", expectedAccount, *user.UserName)
		}
	}

	if len(apiClient.UserPolicies) != 1 {
		t.Errorf("expected a single user policy to be created but found %v", apiClient.UserPolicies)
	} else {
		policy := apiClient.UserPolicies[0]
		if *policy.UserName != expectedAccount {
			t.Errorf("expected policy to be created for user [%s] but was created for user [%s]",
				expectedAccount,
				*policy.UserName)
		}
		for _, targetUser := range targetRoles {
			if !strings.Contains(*policy.PolicyDocument, targetUser) {
				t.Errorf("expected policy document to contain target role [%s] but this was the policy document:\n%s",
					targetUser,
					*policy.PolicyDocument)
			}
		}
	}
}