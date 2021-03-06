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

// Code generated by go-swagger; DO NOT EDIT.

package hydraapi

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the swagger generate command

// GenericError Error response
//
// Error responses are sent when an error (e.g. unauthorized, bad request, ...) occurred.
// swagger:model genericError
type GenericError struct {

	// Code represents the error status code (404, 403, 401, ...).
	Code int64 `json:"status_code,omitempty"`

	// Debug contains debug information. This is usually not available and has to be enabled.
	Debug string `json:"debug,omitempty"`

	// Description contains further information on the nature of the error.
	Description string `json:"error_description,omitempty"`

	// Name is the error name.
	// Required: true
	Name *string `json:"error"`
}
