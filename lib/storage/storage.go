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

package storage

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/strutil" /* copybara-comment: strutil */
)

const (
	LatestRev      = int64(-1)
	LatestRevName  = "latest"
	HistoryRevName = "history"
	DefaultRealm   = "master"
	DefaultUser    = ""
	DefaultID      = "main"
	AllRealms      = ""
	MatchAllGroups = "" // alias for MatchAllUsers
	MatchAllUsers  = "" // alias for MatchAllGroups
	MatchAllIDs    = ""

	AccountDatatype                   = "account"
	AccountLookupDatatype             = "acct_lookup"
	CliAuthDatatype                   = "cli_auth"
	ClientDatatype                    = "client"
	ConfigDatatype                    = "config"
	GroupDatatype                     = "group"
	GroupMemberDatatype               = "member"
	LockDatatype                      = "lock"
	LoginStateDatatype                = "login_state"
	LongRunningOperationDatatype      = "lro"
	ProcessDataType                   = "process"
	PermissionsDatatype               = "permissions"
	SecretsDatatype                   = "secrets"
	TokensDatatype                    = "tokens"
	PendingDeleteTokenDatatype        = "pending_delete_token"
	ResourceTokenRequestStateDataType = "resource_token_state"
	RememberedConsentDatatype         = "remembered_consent"

	// StateActive indicates an object is active.
	StateActive = "ACTIVE"
	// StateDeleted indicates an object is deleted (can still be referenced by an admin).
	StateDeleted = "DELETED"
	// StateDisabled indicates an object is disabled (may be reactived later).
	StateDisabled = "DISABLED"

	// DefaultPageSize is the default number of entries returned by a list.
	DefaultPageSize = 50
	// MaxPageSize is the maximum number of entries returned by a list.
	MaxPageSize = 1000
)

var (
	// orCheckRE checks that an entire OR-expression filter matches the pattern expected.
	orCheckRE = regexp.MustCompile(`^(?i)\s*[^\s]+\s+(eq|ne|co|sw|ew|pr|gt|ge|lt|le)\s+("[^"]*"|true|false)(\s+or\s+[^\s]+\s+(eq|ne|co|sw|ew|pr|gt|ge|lt|le)\s+("[^"]*"|true|false))*\s*$`)
	// orFilterRE extracts single clauses from an OR-expression filter.
	orFilterRE = regexp.MustCompile(`(?i)([^\s]+)\s+(eq|ne|co|sw|ew|pr|gt|ge|lt|le)\s+("[^"]*"|true|false)`)
)

// Entry represents a single storage item and its metadata.
type Entry struct {
	// Realm is the realm to which this entry belongs.
	Realm string
	// GroupID is a logical grouping for a set of items.
	GroupID string
	// ItemID is the identifier for the proto item being stored.
	ItemID string
	// Item is the proto that is being stored.
	Item proto.Message
}

// Results represents a set of entries returned as part of a query.
type Results struct {
	// Entries contains the list of entries returned by the query.
	Entries []*Entry
	// MatchCount is the number of matches that exist, starting at any offset provided by the query.
	MatchCount int
}

// Store is an interface to the storage layer.
type Store interface {
	Info() map[string]string
	Exists(datatype, realm, user, id string, rev int64) (bool, error)
	Read(datatype, realm, user, id string, rev int64, content proto.Message) error
	ReadTx(datatype, realm, user, id string, rev int64, content proto.Message, tx Tx) error
	// MultiReadTx reads a set of objects matching the input parameters and filters. Returns total count and error.
	MultiReadTx(datatype, realm, user, id string, filters [][]Filter, offset, pageSize int, typ proto.Message, tx Tx) (*Results, error)
	ReadHistory(datatype, realm, user, id string, content *[]proto.Message) error
	ReadHistoryTx(datatype, realm, user, id string, content *[]proto.Message, tx Tx) error
	Write(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message) error
	WriteTx(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message, tx Tx) error
	Delete(datatype, realm, user, id string, rev int64) error
	DeleteTx(datatype, realm, user, id string, rev int64, tx Tx) error
	MultiDeleteTx(datatype, realm, user string, tx Tx) error
	// Wipe removes any items from a realm up to maxEntries (if > 0). Returns count of deleted items and error.
	Wipe(ctx context.Context, realm string, batchNum, maxEntries int) (int, error)
	Tx(update bool) (Tx, error)
	LockTx(lockName string, minFrequency time.Duration, tx Tx) Tx
}

type Tx interface {
	Finish() error
	Rollback() error
	// MakeUpdate will upgrade a read-only transaction to an update transaction.
	MakeUpdate() error
	IsUpdate() bool
}

// Filter is a means to filter which entries are returned from MultiReadTx.
type Filter struct {
	// Field is the name of the field
	extract func(p proto.Message) string
	compare string
	value   string
}

// NewResults returns a new Results object.
func NewResults() *Results {
	return &Results{
		Entries: []*Entry{},
	}
}

func ErrNotFound(err error) bool {
	// TODO: make this smarter.
	return strings.Contains(err.Error(), "not found") || strings.Contains(err.Error(), "no such file")
}

// BuildFilters creates a set of filters based on an input string.
// Within the field map, SCIM path names are expected to be lowercase.
// Example:
//   BuildFilters(`name.formatted eq "Joe" or name.familyName sw "Smith"`, map[string]func(p proto.Message) string {
//     "name.formatted": func(p proto.Message) string {
//       return myProtoCast(p).Profile.Name
//     },
//     "name.familyname": func(p proto.Message) string {
//       return myProtoCast(p).Profile.FamilyName
//     },
//   })
// The filters generated by this method can be evaluated with a proto input using
// MatchProtoFilters(filters, myProto).
func BuildFilters(str string, fields map[string]func(p proto.Message) string) ([][]Filter, error) {
	if len(str) == 0 {
		return nil, nil
	}
	var out [][]Filter
	ands := strutil.QuoteSplit(str, " and ", false)
	for _, a := range ands {
		var ors []Filter
		a = strings.Trim(a, " ")
		brackets := false
		if strings.HasPrefix(a, "(") && strings.HasSuffix(a, ")") {
			brackets = true
			// Strip off the brackets
			a = a[1 : len(a)-1]
		}
		// Perform additional checks to improve error handling.
		parts := strutil.QuoteSplit(a, " ", false)
		for _, p := range parts {
			if strings.HasPrefix(p, `"`) {
				continue
			}
			if strings.Contains(p, "(") || strings.Contains(p, ")") {
				return nil, fmt.Errorf("mismatched or nested brackets on filter %q", str)
			}
			if strings.ToLower(p) == "or" && !brackets && len(ands) > 1 {
				return nil, fmt.Errorf("brackets around OR clauses are required in filter %q", str)
			}
		}
		// Use regexp to parse the OR clause or simple expression.
		if !orCheckRE.MatchString(a) {
			return nil, fmt.Errorf("invalid filter %q", str)
		}
		match := orFilterRE.FindAllStringSubmatch(a, -1)
		if len(match) == 0 {
			return nil, fmt.Errorf("invalid filter %q", str)
		}
		for _, m := range match {
			fn, ok := fields[strings.ToLower(m[1])]
			if !ok {
				return nil, fmt.Errorf("field %q not defined", m[1])
			}
			val := strings.ToLower(m[3])
			if strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`) {
				val = val[1 : len(val)-1]
			}
			ors = append(ors, Filter{extract: fn, compare: strings.ToLower(m[2]), value: val})
		}
		out = append(out, ors)
	}
	return out, nil
}

// MatchProtoFilters returns true if any of the filter conditions are met
// (i.e. evaluates a Conjunctive Normal Form (CNF) of this array of filters).
// Simplified version of: https://tools.ietf.org/html/rfc7644#section-3.4.2.2
func MatchProtoFilters(cnfFilters [][]Filter, p proto.Message) bool {
	if len(cnfFilters) == 0 {
		return true
	}
	// Perform an AND over the inner OR filters (i.e. CNF).
	for _, orFilters := range cnfFilters {
		if !matchOrFilters(orFilters, p) {
			return false
		}
	}
	return true
}

func matchOrFilters(orFilters []Filter, p proto.Message) bool {
	for _, f := range orFilters {
		a := strings.ToLower(f.extract(p))
		b := f.value
		switch {
		// Starts with
		case f.compare == "sw" && strings.HasPrefix(a, b):
			return true
		// Equals
		case f.compare == "eq" && a == b:
			return true
		// Not equals
		case f.compare == "ne" && a != b:
			return true
		// Contains
		case f.compare == "co" && strings.Contains(a, b):
			return true
		// Ends with
		case f.compare == "ew" && strings.HasSuffix(a, b):
			return true
		// Present
		case f.compare == "pr" && len(a) > 0:
			return true
		// Greater than
		case f.compare == "gt" && strings.Compare(a, b) > 0:
			return true
		// Greater than or equal to
		case f.compare == "ge" && strings.Compare(a, b) >= 0:
			return true
		// Less than
		case f.compare == "lt" && strings.Compare(a, b) < 0:
			return true
		// Less than or equal to
		case f.compare == "le" && strings.Compare(a, b) <= 0:
			return true
		}
	}
	return false
}
