#!/bin/bash

# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# TODO: initial steps

# You need to loging to gcloud and createa a project using gcloud cli.
# Export the id of your project to environment variable PROJECT.

gcloud config set project ${PROJECT?}

export PROJECT_NUMBER=$(gcloud projects list --filter="${PROJECT?}" --format="value(PROJECT_NUMBER)")

# Enbable the required APIs.
gcloud services enable \
  appengine.googleapis.com \
  appengineflex.googleapis.com \
  appenginestandard.googleapis.com \
  sql-component.googleapis.com \
  sqladmin.googleapis.com \
  datastore.googleapis.com \
  iam.googleapis.com \
  cloudbuild.googleapis.com \
  bigquery.googleapis.com \
  storage-component.googleapis.com \
  cloudkms.googleapis.com

# Grant the required permissions.
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:${PROJECT?}@appspot.gserviceaccount.com --role roles/cloudkms.cryptoKeyEncrypterDecrypter
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/cloudkms.cryptoKeyEncrypterDecrypter
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/cloudsql.client
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/editor
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/iam.serviceAccountTokenCreator
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/resourcemanager.projectIamAdmin

# Create a GAE app.
gcloud app create --region=us-central
# TODO: make region configurable.

# Setup Cloud SQL
# Create a CloudSQL D0 (memory=128M, disk=250G) postgres 11 instance in us-central-1.
gcloud sql instances create hydra --database-version=POSTGRES_11 \
  --tier=db-f1-micro --region=us-central1
# Create user: name="${NAME}", password="${PASSWORD}"
gcloud sql users create hydra --instance=hydra --password=hydra
# Create database ic
gcloud sql databases create ic --instance=hydra
# Create database dam
gcloud sql databases create dam --instance=hydra

# Update the config files
cp -R ./deploy/config/ic-template ./deploy/config/ic

sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/gae-flex/build/Dockerfile
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/gae-flex/config/ic.yaml
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/config/ic/config_master_main_latest.json
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/config/ic/secrets_master_main_latest.json

# Deploy a simple defaut app to GAE default service.
pushd $HOME
git clone https://github.com/GoogleCloudPlatform/golang-samples.git
pushd golang-samples/appengine/go11x/helloworld
gcloud -q app deploy .
popd
popd

# Build Images
pushd deploy/gae-flex/base-image
gcloud builds submit --config cloudbuild.yaml .
popd

# Build the IC and DAM image
gcloud builds submit --config gae-cloudbuild.yaml --substitutions=_VERSION_=latest

# Deploy IC and DAM
gcloud -q app deploy deploy/gae-flex/config/ic.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-gae:latest

# TODO: gcloud -q app deploy deploy/gae-flex/config/dam.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-gae:latest



