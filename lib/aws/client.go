package aws

import (
	"fmt"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/sts"
)

type SdkApiClient struct {
}

func(sac *SdkApiClient) createSession() (*session.Session, error) {
	rootSess, err := session.NewSession(&aws.Config{})
	if err != nil {
		return nil, fmt.Errorf("unable to create AWS root session: %v", err)
	} else {
		return rootSess, err
	}
}

func(sac *SdkApiClient) createIamSvc() (*iam.IAM, error) {
	sess, err := sac.createSession()
	if err != nil {
		return nil, fmt.Errorf("error creating AWS SDK session: %v", err)
	}
	return iam.New(sess), nil
}

func(sac *SdkApiClient) createStsSvc() (*sts.STS, error) {
	sess, err := sac.createSession()
	if err != nil {
		return nil, fmt.Errorf("error creating AWS SDK session: %v", err)
	}
	return sts.New(sess), nil
}

func (sac *SdkApiClient) ListUsers(input *iam.ListUsersInput) (*iam.ListUsersOutput, error) {
	svc, err := sac.createIamSvc()
	if err != nil {
		return nil, err
	}
	accounts, err := svc.ListUsers(input)
	if err != nil {
		return nil, fmt.Errorf("failed to list users with AWS sdk: %v", err)
	}

	return accounts, nil
}

func (sac *SdkApiClient) ListAccessKeys(input *iam.ListAccessKeysInput) (*iam.ListAccessKeysOutput, error) {
	svc, err := sac.createIamSvc()
	if err != nil {
		return nil, err
	}
	return svc.ListAccessKeys(input)
}

func (sac *SdkApiClient) DeleteAccessKey(input *iam.DeleteAccessKeyInput) (*iam.DeleteAccessKeyOutput, error) {
	svc, err := sac.createIamSvc()
	if err != nil {
		return nil, err
	}
	return svc.DeleteAccessKey(input)
}

func (sac *SdkApiClient) GetCallerIdentity(input *sts.GetCallerIdentityInput) (*sts.GetCallerIdentityOutput, error) {
	svc, err := sac.createStsSvc()
	if err != nil {
		return nil, err
	}

	return svc.GetCallerIdentity(input)
}

func (sac *SdkApiClient) AssumeRole(input *sts.AssumeRoleInput) (*sts.AssumeRoleOutput, error) {
	svc, err := sac.createStsSvc()
	if err != nil {
		return nil, err
	}

	return svc.AssumeRole(input)
}

func (sac *SdkApiClient) CreateAccessKey(input *iam.CreateAccessKeyInput) (*iam.CreateAccessKeyOutput, error) {
	svc, err := sac.createIamSvc()
	if err != nil {
		return nil, err
	}
	return svc.CreateAccessKey(input)
}

func (sac *SdkApiClient) PutRolePolicy(input *iam.PutRolePolicyInput) (*iam.PutRolePolicyOutput, error) {
	svc, err := sac.createIamSvc()
	if err != nil {
		return nil, err
	}
	return svc.PutRolePolicy(input)
}

func (sac *SdkApiClient) PutUserPolicy(input *iam.PutUserPolicyInput) (*iam.PutUserPolicyOutput, error) {
	svc, err := sac.createIamSvc()
	if err != nil {
		return nil, err
	}
	return svc.PutUserPolicy(input)
}

func (sac *SdkApiClient) GetUser(input *iam.GetUserInput) (*iam.GetUserOutput, error) {
	svc, err := sac.createIamSvc()
	if err != nil {
		return nil, err
	}
	return svc.GetUser(input)
}

func (sac *SdkApiClient) CreateUser(input *iam.CreateUserInput) (*iam.CreateUserOutput, error) {
	svc, err := sac.createIamSvc()
	if err != nil {
		return nil, err
	}
	return svc.CreateUser(input)
}

func (sac *SdkApiClient) GetRole(input *iam.GetRoleInput) (*iam.GetRoleOutput, error) {
	svc, err := sac.createIamSvc()
	if err != nil {
		return nil, err
	}
	return svc.GetRole(input)
}

func (sac *SdkApiClient) CreateRole(input *iam.CreateRoleInput) (*iam.CreateRoleOutput, error) {
	svc, err := sac.createIamSvc()
	if err != nil {
		return nil, err
	}
	return svc.CreateRole(input)
}
