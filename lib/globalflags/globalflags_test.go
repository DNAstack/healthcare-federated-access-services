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

package globalflags

import (
	"testing"
)

func TestIsExperimental(t *testing.T) {
	tests := []struct {
		experimental string
		want         bool
	}{
		{
			experimental: "",
			want:         false,
		},
		{
			experimental: "true",
			want:         true,
		},
		{
			experimental: "invalid",
			want:         false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.experimental, func(t *testing.T) {
			experimental = tc.experimental
			if IsExperimental() != tc.want {
				t.Errorf("IsExperimental() wants %v", tc.want)
			}
		})
	}
}
