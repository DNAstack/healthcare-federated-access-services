/*
 * Copyright 2019 Google LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package common

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestJoinNonEmpty(t *testing.T) {
	tests := []struct {
		Name      string
		Input     []string
		Separator string
		Expect    string
	}{
		{
			Name:   "empty input",
			Input:  []string{},
			Expect: "",
		},
		{
			Name:   "one string",
			Input:  []string{"one"},
			Expect: "one",
		},
		{
			Name:   "two strings",
			Input:  []string{"one", "two"},
			Expect: "one two",
		},
		{
			Name:      "non-space multi-character separator",
			Input:     []string{"one", "two"},
			Separator: "@@@",
			Expect:    "one@@@two",
		},
		{
			Name:   "empty strings",
			Input:  []string{"", "one", "", "", "two", "", "three", ""},
			Expect: "one two three",
		},
	}

	for _, test := range tests {
		sep := " "
		if len(test.Separator) > 0 {
			sep = test.Separator
		}
		got := JoinNonEmpty(test.Input, sep)
		if got != test.Expect {
			t.Errorf("test %q: want %q, got %q", test.Name, test.Expect, got)
		}
	}
}

func TestRemoveStringsByPrefix(t *testing.T) {
	tests := []struct {
		name   string
		input  []string
		prefix string
		expect []string
	}{
		{
			name:   "nil input",
			input:  nil,
			expect: nil,
		},
		{
			name:   "empty input",
			input:  []string{},
			expect: nil,
		},
		{
			name:   "one string no match",
			input:  []string{"one"},
			prefix: "foo",
			expect: []string{"one"},
		},
		{
			name:   "one string match",
			input:  []string{"one"},
			prefix: "o",
			expect: nil,
		},
		{
			name:   "two strings remove first",
			input:  []string{"one", "two"},
			prefix: "one",
			expect: []string{"two"},
		},
		{
			name:   "two strings remove second",
			input:  []string{"one", "two"},
			prefix: "two",
			expect: []string{"one"},
		},
		{
			name:   "remove all",
			input:  []string{"none", "nothing"},
			prefix: "no",
			expect: nil,
		},
		{
			name:   "empty strings",
			input:  []string{"", "one", "", "", "two", "", "three", ""},
			prefix: "t",
			expect: []string{"", "one", "", "", "", ""},
		},
		{
			name:   "paths",
			input:  []string{"aaa/bbbb/ccc", "aaa/bbb/ccc", "zzz", "aaa/bbb"},
			prefix: "aaa/bbb/",
			expect: []string{"aaa/bbbb/ccc", "zzz", "aaa/bbb"},
		},
	}

	for _, tc := range tests {
		got := FilterStringsByPrefix(tc.input, tc.prefix)
		if diff := cmp.Diff(got, tc.expect); diff != "" {
			t.Errorf("test case %q: FilterStringsByPrefix(%v, %q) returned diff (-want +got):\n%s", tc.name, tc.input, tc.prefix, diff)
		}
	}
}

func TestToTitle(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "simple string",
			input: "hello",
			want:  "Hello",
		},
		{
			name:  "two words",
			input: "hello there",
			want:  "Hello There",
		},
		{
			name:  "camel case",
			input: "camelCase",
			want:  "Camel Case",
		},
		{
			name:  "snake case",
			input: "snake_case",
			want:  "Snake Case",
		},
	}

	for _, tc := range tests {
		got := ToTitle(tc.input)
		if got != tc.want {
			t.Errorf("test case %q: ToTitle(%q) = %q, want %q", tc.name, tc.input, got, tc.want)
		}
	}
}

func TestIsURL(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool
	}{
		{
			name:  "empty input",
			input: "",
			want:  false,
		},
		{
			name:  "simple string",
			input: "hello",
			want:  false,
		},
		{
			name:  "partial prefix but not a URL",
			input: "http://",
			want:  false,
		},
		{
			name:  "simple http URL",
			input: "http://a.org",
			want:  true,
		},
		{
			name:  "simple https URL",
			input: "https://a.org",
			want:  true,
		},
		{
			name:  "case mismatch",
			input: "Https://a.org",
			want:  false,
		},
		{
			name:  "longer URL",
			input: "https://my.longer.example.org/hello/world/how/are/you/today?fruit=apples&mood=happy",
			want:  true,
		},
	}

	for _, tc := range tests {
		got := IsURL(tc.input)
		if got != tc.want {
			t.Errorf("test case %q: IsURL(%q) = %v, want %v", tc.name, tc.input, got, tc.want)
		}
	}
}

func TestReplaceVariables(t *testing.T) {
	tests := []struct {
		name  string
		input string
		args  map[string]string
		want  string
	}{
		{
			name:  "empty input",
			input: "",
			want:  "",
		},
		{
			name:  "simple string",
			input: "hello",
			want:  "hello",
		},
		{
			name:  "simple string with args",
			input: "hello",
			args:  map[string]string{"foo": "bar"},
			want:  "hello",
		},
		{
			name:  "whole string replace",
			input: "${foo}",
			args:  map[string]string{"foo": "bar"},
			want:  "bar",
		},
		{
			name:  "prefix string replace",
			input: "${foo}maid",
			args:  map[string]string{"foo": "bar"},
			want:  "barmaid",
		},
		{
			name:  "prefix string replace",
			input: "wonder${foo}",
			args:  map[string]string{"foo": "bar"},
			want:  "wonderbar",
		},
		{
			name:  "multiple replace of same variable",
			input: "a_${foo}_b_${foo}_c",
			args:  map[string]string{"foo": "bar"},
			want:  "a_bar_b_bar_c",
		},
		{
			name:  "multiple variables",
			input: "${toy} is fun to play with when eating an ${food}",
			args:  map[string]string{"food": "apple", "toy": "LEGO"},
			want:  "LEGO is fun to play with when eating an apple",
		},
	}

	for _, tc := range tests {
		got, err := ReplaceVariables(tc.input, tc.args)
		if err != nil {
			t.Errorf("test case %q: ReplaceVariables(%q, %v) = (%v, %v) unexpected error", tc.name, tc.input, tc.args, got, err)
			continue
		}
		if got != tc.want {
			t.Errorf("test case %q: ReplaceVariables(%q, %v) = (%v, nil), want %q", tc.name, tc.input, tc.args, got, tc.want)
		}
	}
}

func TestReplaceVariablesErrors(t *testing.T) {
	tests := []struct {
		name  string
		input string
		args  map[string]string
	}{
		{
			name:  "no variables not defined",
			input: "${foo}",
		},
		{
			name:  "wrong variables defined",
			input: "${foo}",
			args:  map[string]string{"food": "apple", "toy": "LEGO"},
		},
	}

	for _, tc := range tests {
		got, err := ReplaceVariables(tc.input, tc.args)
		if err == nil {
			t.Errorf("test case %q: ReplaceVariables(%q, %v) = (%v, %v) was expecting an error", tc.name, tc.input, tc.args, got, err)
			continue
		}
	}
}
