#!/bin/bash

export PROJECT_ROOT=`pwd`
# Need this to run adapters tests without live AWS credentials and API access
export AWS_ADAPTER_TEST_MODE=true
go test ./...
