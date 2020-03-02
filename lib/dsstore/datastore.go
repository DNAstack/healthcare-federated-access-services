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

// Package dsstore is a Datastore-based storage for DAM/IC.
package dsstore

import (
	"context"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"cloud.google.com/go/datastore" /* copybara-comment: datastore */
	"google.golang.org/api/iterator" /* copybara-comment: iterator */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const (
	storageType    = "gcpDatastore"
	storageVersion = "v0"

	entityKind  = "entity"
	historyKind = "history"
	metaKind    = "meta"

	metaVersion = "version"

	multiDeleteChunkSize = 400     // must not exceed 500 as per Datastore API
	minJitter            = 1 * 1e9 // nanoseconds as integer for math
	maxJitter            = 3 * 1e9 // nanoseconds as integer for math
)

var (
	mutex     = &sync.Mutex{}
	wipeKinds = []string{historyKind, entityKind}
)

// DatastoreStorage is a datastore based implementation of storage.
type DatastoreStorage struct {
	client *datastore.Client

	// TODO: these fileds are only used for Info and are not related to the store.
	// Move them to lib/serviceinfo.
	//   project: the GCP project in which the datastore resides.
	project string
	//   service: the name of the service (e.g. "dam" or "ic").
	service string
	//   path:    the path to the config file.
	path string
}

type DatastoreEntity struct {
	Key      *datastore.Key `datastore:"__key__"`
	Service  string         `datastore:"service"`
	Datatype string         `datastore:"type"`
	Realm    string         `datastore:"realm"`
	User     string         `datastore:"user_id"`
	Id       string         `datastore:"id"`
	Rev      int64          `datastore:"rev"`
	Version  string         `datastore:"version,noindex"`
	Modified int64          `datastore:"modified"`
	Content  string         `datastore:"content,noindex"`
}

type DatastoreHistory struct {
	Key      *datastore.Key `datastore:"__key__"`
	Service  string         `datastore:"service"`
	Datatype string         `datastore:"type"`
	Realm    string         `datastore:"realm"`
	User     string         `datastore:"user_id"`
	Id       string         `datastore:"id"`
	Rev      int64          `datastore:"rev"`
	Version  string         `datastore:"version,noindex"`
	Modified int64          `datastore:"modified"`
	Content  string         `datastore:"content,noindex"`
}

type DatastoreMeta struct {
	Key   *datastore.Key `datastore:"__key__"`
	Name  string         `datastore:"name"`
	Value string         `datastore:"value,noindex"`
}

// NewDatastoreStorage creates a new datastore storace and initilizes it.
// TODO: create the client for datastore in the main and inject it.
func NewDatastoreStorage(ctx context.Context, project, service, path string) *DatastoreStorage {
	client, err := datastore.NewClient(ctx, project)
	if err != nil {
		glog.Fatalf("cannot initialize datastore: %v", err)
	}
	s := New(client, project, service, path)
	if err := s.Init(); err != nil {
		glog.Fatalf("Datastore failed to initialize: %v", err)
	}
	return s
}

// New creates a new storage.
func New(client *datastore.Client, project, service, path string) *DatastoreStorage {
	return &DatastoreStorage{
		client:  client,
		project: project,
		service: service,
		path:    path,
	}
}

func (s *DatastoreStorage) Info() map[string]string {
	return map[string]string{
		"type":    storageType,
		"version": storageVersion,
		"service": s.service,
		"path":    s.path,
	}
}

// Exists checks if a data entity with the given name exists.
func (s *DatastoreStorage) Exists(datatype, realm, user, id string, rev int64) (bool, error) {
	k := datastore.NameKey(entityKind, s.entityKey(datatype, realm, user, id, rev), nil)
	e := new(DatastoreEntity)
	err := s.client.Get(context.Background() /* TODO: pass ctx from request */, k, e)
	if err == nil {
		return true, nil
	} else if err == datastore.ErrNoSuchEntity {
		return false, nil
	}
	return false, err
}

// Read reads a data entity.
func (s *DatastoreStorage) Read(datatype, realm, user, id string, rev int64, content proto.Message) error {
	return s.ReadTx(datatype, realm, user, id, rev, content, nil)
}

// ReadTx reads a data entity inside a transaction.
// ReadTx will not see the writes inside the transaction.
func (s *DatastoreStorage) ReadTx(datatype, realm, user, id string, rev int64, content proto.Message, tx storage.Tx) (ferr error) {
	if tx == nil {
		var err error
		tx, err = s.Tx(false)
		if err != nil {
			return err
		}
		defer func() {
			err := tx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}
	dstx, ok := tx.(*DatastoreTx)
	if !ok {
		return status.Errorf(codes.InvalidArgument, "invalid transaction")
	}

	k := datastore.NameKey(entityKind, s.entityKey(datatype, realm, user, id, rev), nil)
	e, err := s.datastoreEntity(k, datatype, realm, user, id, rev, content)
	if err != nil {
		return err
	}
	if err = dstx.Tx.Get(k, e); err != nil {
		if err == datastore.ErrNoSuchEntity {
			return status.Errorf(codes.NotFound, "not found: %q", k)
		}
		return err
	}
	if err := jsonpb.Unmarshal(strings.NewReader(e.Content), content); err != nil {
		return err
	}
	return nil
}

// MultiReadTx reads a set of data entities matching the filters.
// MultiReadTx will not see the writes inside the transaction.
// If realm is "" reads all realms.
// if user is "" reads all users.
// Returns the number of items matching the filter.
// content is a map of user and id to values.
func (s *DatastoreStorage) MultiReadTx(datatype, realm, user string, filters [][]storage.Filter, offset, pageSize int, content map[string]map[string]proto.Message, typ proto.Message, tx storage.Tx) (_ int, ferr error) {
	if tx == nil {
		var err error
		tx, err = s.Tx(false)
		if err != nil {
			return 0, err
		}
		defer func() {
			err := tx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}
	if pageSize > storage.MaxPageSize {
		pageSize = storage.MaxPageSize
	}

	q := datastore.NewQuery(entityKind).Filter("service =", s.service).Filter("type =", datatype)
	if realm != storage.AllRealms {
		q = q.Filter("realm =", realm)
	}
	if user != storage.DefaultUser {
		q = q.Filter("user_id = ", user)
	}
	q = q.Filter("rev = ", storage.LatestRev).Order("id")
	if len(filters) == 0 {
		// No post-filtering, so limit the query directly as an optimization.
		// Still can't use q.Limit(pageSize) because we want the total number of matches.
		q = q.Offset(offset)
		offset = 0
	}

	it := s.client.Run(context.Background() /* TODO: pass ctx from request */, q)
	count := 0
	for {
		var e DatastoreEntity
		_, err := it.Next(&e)
		if err == iterator.Done {
			break
		}
		if err != nil {
			return 0, err
		}
		if len(e.Content) == 0 {
			continue
		}
		p := proto.Clone(typ)
		if err := jsonpb.Unmarshal(strings.NewReader(e.Content), p); err != nil {
			return 0, err
		}
		if !storage.MatchProtoFilters(filters, p) {
			continue
		}
		// Offset cannot use q.Offset(x) because it must match complex filters above.
		// For pagination, decrease any remaining offset before accepting this entry.
		if offset > 0 {
			offset--
			continue
		}
		if pageSize == 0 || pageSize > count {
			userContent, ok := content[e.User]
			if !ok {
				content[e.User] = make(map[string]proto.Message)
				userContent = content[e.User]
			}
			userContent[e.Id] = p
		}
		count++
	}
	return count, nil
}

// ReadHistory reads the history.
func (s *DatastoreStorage) ReadHistory(datatype, realm, user, id string, content *[]proto.Message) error {
	return s.ReadHistoryTx(datatype, realm, user, id, content, nil)
}

// ReadHistoryTx reads the history inside a transaction.
func (s *DatastoreStorage) ReadHistoryTx(datatype, realm, user, id string, content *[]proto.Message, tx storage.Tx) (ferr error) {
	if tx == nil {
		var err error
		tx, err = s.Tx(false)
		if err != nil {
			return err
		}
		defer func() {
			err := tx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}

	// TODO: handle pagination.
	q := datastore.NewQuery(historyKind).Filter("service =", s.service).Filter("type =", datatype).Filter("realm =", realm).Filter("user_id =", user).Filter("id =", id).Order("rev").Limit(storage.MaxPageSize)
	results := make([]DatastoreHistory, storage.MaxPageSize)
	if _, err := s.client.GetAll(context.Background() /* TODO: pass ctx from request */, q, &results); err != nil {
		return err
	}
	for _, e := range results {
		he := new(cpb.HistoryEntry)
		if len(e.Content) == 0 {
			continue
		}
		if err := jsonpb.Unmarshal(strings.NewReader(e.Content), he); err != nil {
			return err
		}
		*content = append(*content, he)
	}
	return nil
}

// Write writes a data entity.
func (s *DatastoreStorage) Write(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message) error {
	return s.WriteTx(datatype, realm, user, id, rev, content, history, nil)
}

// WriteTx writes a data entity inside a transaction.
func (s *DatastoreStorage) WriteTx(datatype, realm, user, id string, rev int64, content proto.Message, history proto.Message, tx storage.Tx) (ferr error) {
	if tx == nil {
		var err error
		tx, err = s.Tx(true)
		if err != nil {
			return err
		}
		defer func() {
			err := tx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}
	dstx, ok := tx.(*DatastoreTx)
	if !ok {
		return status.Errorf(codes.InvalidArgument, "invalid transaction")
	}

	if rev != storage.LatestRev {
		rk := datastore.NameKey(entityKind, s.entityKey(datatype, realm, user, id, rev), nil)
		re, err := s.datastoreEntity(rk, datatype, realm, user, id, rev, content)
		if err != nil {
			return err
		}
		if _, err = dstx.Tx.Put(rk, re); err != nil {
			dstx.Rollback()
			return err
		}
	}
	if history != nil {
		hk := datastore.NameKey(historyKind, s.historyKey(datatype, realm, user, id, rev), nil)
		he, err := s.datastoreHistory(hk, datatype, realm, user, id, rev, history)
		if err != nil {
			dstx.Rollback()
			return err
		}
		if _, err = dstx.Tx.Put(hk, he); err != nil {
			dstx.Rollback()
			return err
		}
	}
	k := datastore.NameKey(entityKind, s.entityKey(datatype, realm, user, id, storage.LatestRev), nil)
	e, err := s.datastoreEntity(k, datatype, realm, user, id, storage.LatestRev, content)
	if err != nil {
		dstx.Rollback()
		return err
	}
	if _, err := dstx.Tx.Put(k, e); err != nil {
		dstx.Rollback()
		return err
	}
	return nil
}

// Delete deletes a data entity.
func (s *DatastoreStorage) Delete(datatype, realm, user, id string, rev int64) error {
	return s.DeleteTx(datatype, realm, user, id, rev, nil)
}

// DeleteTx deletes a data entity inside a transaction.
func (s *DatastoreStorage) DeleteTx(datatype, realm, user, id string, rev int64, tx storage.Tx) (ferr error) {
	if tx == nil {
		var err error
		tx, err = s.Tx(true)
		if err != nil {
			return err
		}
		defer func() {
			err := tx.Finish()
			if ferr == nil {
				ferr = err
			}
		}()
	}
	dstx, ok := tx.(*DatastoreTx)
	if !ok {
		return status.Errorf(codes.InvalidArgument, "invalid transaction")
	}

	k := datastore.NameKey(entityKind, s.entityKey(datatype, realm, user, id, rev), nil)
	if err := dstx.Tx.Delete(k); err != nil {
		dstx.Rollback()
		return err
	}
	return nil
}

// MultiDeleteTx deletes all records of a certain data type within a realm.
// If user is "", deletes for all users.
func (s *DatastoreStorage) MultiDeleteTx(datatype, realm, user string, tx storage.Tx) error {
	q := datastore.NewQuery(entityKind).Filter("service =", s.service).Filter("type =", datatype).Filter("realm =", realm)
	if user != storage.DefaultUser {
		q = q.Filter("user_id =", user)
	}
	q = q.Filter("rev = ", storage.LatestRev).Order("id")
	_, err := s.multiDelete(q)
	return err
}

// Wipe deletes all data and history within a realm.
// If realm is "" deletes for all realms.
func (s *DatastoreStorage) Wipe(realm string) error {
	glog.Infof("Datastore wipe project %q service %q realm %q: started", s.project, s.service, realm)
	results := make(map[string]int)
	for _, kind := range wipeKinds {
		q := datastore.NewQuery(kind).Filter("service =", s.service)
		if realm != storage.AllRealms {
			q = q.Filter("realm =", realm)
		}
		total, err := s.multiDelete(q)
		if err != nil {
			return err
		}
		results[kind] = total
	}
	glog.Infof("Datastore wipe project %q service %q realm %q: completed results: %#v", s.project, s.service, realm, results)
	return nil
}

func (s *DatastoreStorage) multiDelete(q *datastore.Query) (int, error) {
	keys, err := s.client.GetAll(context.Background() /* TODO: pass ctx from request */, q.KeysOnly(), nil)
	if err != nil {
		return 0, err
	}
	total := len(keys)
	for i := 0; i < total; i += multiDeleteChunkSize {
		end := i + multiDeleteChunkSize
		if total < end {
			end = total
		}
		chunk := keys[i:end]
		if err := s.client.DeleteMulti(context.Background() /* TODO: pass ctx from request */, chunk); err != nil {
			return total, err
		}
	}
	return total, nil
}

func (s *DatastoreStorage) Tx(update bool) (storage.Tx, error) {
	var err error
	var dstx *datastore.Transaction
	if update {
		dstx, err = s.client.NewTransaction(context.Background() /* TODO: pass ctx from request */)
	} else {
		dstx, err = s.client.NewTransaction(context.Background() /* TODO: pass ctx from request */, datastore.ReadOnly)
	}
	if err != nil {
		return nil, err
	}
	return &DatastoreTx{
		writer: update,
		Tx:     dstx,
	}, nil
}

// LockTx returns a storage-wide lock by the given name. Only one such lock should
// be requested at a time. If Tx is provided, it must be an update Tx.
func (s *DatastoreStorage) LockTx(lockName string, minFrequency time.Duration, tx storage.Tx) storage.Tx {
	if tx == nil {
		var err error
		tx, err = s.Tx(true)
		if err != nil {
			return nil
		}
		// Do not defer tx.Finish() as it must be not be freed unless the lock attempt fails.
	} else if !tx.IsUpdate() {
		return nil
	}
	entry := cpb.HistoryEntry{}
	locked := false
	for try := 0; try < 5; try++ {
		if err := s.ReadTx(storage.LockDatatype, storage.DefaultRealm, storage.DefaultUser, lockName, storage.LatestRev, &entry, tx); err == nil || storage.ErrNotFound(err) {
			// Will setup the object below.
			locked = true
			break
		}
		jitter := minJitter + rand.Float64()*(maxJitter-minJitter)
		time.Sleep(time.Duration(jitter))
	}
	if !locked {
		tx.Finish()
		return nil
	}
	if diff := time.Now().Sub(time.Unix(int64(entry.CommitTime), 0)); diff < minFrequency {
		tx.Finish()
		return nil
	}

	entry.CommitTime = float64(time.Now().Unix())
	if err := s.WriteTx(storage.LockDatatype, storage.DefaultRealm, storage.DefaultUser, lockName, storage.LatestRev, &entry, nil, tx); err != nil {
		tx.Finish()
		return nil
	}
	return tx
}

// Init initilizes the storage.
func (s *DatastoreStorage) Init() error {
	k := datastore.NameKey(metaKind, s.metaKey(metaVersion), nil)
	meta := new(DatastoreMeta)
	if err := s.client.Get(context.Background() /* TODO: pass ctx from request */, k, meta); err == datastore.ErrNoSuchEntity {
		meta = &DatastoreMeta{
			Key:   k,
			Name:  metaVersion,
			Value: storageVersion,
		}
		_, err := s.client.Put(context.Background() /* TODO: pass ctx from request */, k, meta)
		if err != nil {
			return status.Errorf(codes.Internal, "cannot write datastore metadata: %v", err)
		}
	} else if err != nil {
		return status.Errorf(codes.Internal, "cannot access datastore metadata: %v", err)
	}
	glog.Infof("Datastore service %q version: %s", s.service, meta.Value)
	if meta.Value != storageVersion {
		return status.Errorf(codes.FailedPrecondition, "datastore version not compatible: expected %q, got %q", storageVersion, meta.Value)
	}
	return nil
}

func (s *DatastoreStorage) entityKey(datatype, realm, user, id string, rev int64) string {
	r := storage.LatestRevName
	if rev > 0 {
		r = fmt.Sprintf("%06d", rev)
	}
	if user == storage.DefaultUser {
		user = "~"
	}
	return fmt.Sprintf("%s/%s/%s/%s/%s/%s", s.service, datatype, realm, user, id, r)
}

func (s *DatastoreStorage) metaKey(id string) string {
	return fmt.Sprintf("%s/%s/%s/%s", s.service, "meta", id, "meta")
}

func (s *DatastoreStorage) historyKey(datatype, realm, user, id string, rev int64) string {
	r := storage.LatestRevName
	if rev > 0 {
		r = fmt.Sprintf("%06d", rev)
	}
	if user == storage.DefaultUser {
		user = "~"
	}
	return fmt.Sprintf("%s/%s.%s/%s/%s/%s/%s", s.service, datatype, storage.HistoryRevName, realm, user, id, r)
}

func (s *DatastoreStorage) datastoreEntity(key *datastore.Key, datatype, realm, user, id string, rev int64, content proto.Message) (*DatastoreEntity, error) {
	m := jsonpb.Marshaler{}
	js, err := m.MarshalToString(content)
	if err != nil {
		return nil, err
	}
	return &DatastoreEntity{
		Key:      key,
		Service:  s.service,
		Datatype: datatype,
		Realm:    realm,
		User:     user,
		Id:       id,
		Rev:      rev,
		Version:  storageVersion,
		Modified: time.Now().Unix(),
		Content:  js,
	}, nil
}

func (s *DatastoreStorage) datastoreHistory(key *datastore.Key, datatype, realm, user, id string, rev int64, content proto.Message) (*DatastoreHistory, error) {
	m := jsonpb.Marshaler{}
	js, err := m.MarshalToString(content)
	if err != nil {
		return nil, err
	}
	return &DatastoreHistory{
		Key:      key,
		Service:  s.service,
		Datatype: datatype,
		Realm:    realm,
		User:     user,
		Id:       id,
		Rev:      rev,
		Version:  storageVersion,
		Modified: time.Now().Unix(),
		Content:  js,
	}, nil
}

type DatastoreTx struct {
	writer bool
	Tx     *datastore.Transaction
}

// IsUpdate tells if the transaction is an update or read-only.
func (tx *DatastoreTx) IsUpdate() bool {
	return tx.writer
}

// Finish attempts to commit a transaction.
func (tx *DatastoreTx) Finish() error {
	if tx.Tx == nil {
		return nil
	}
	_, err := tx.Tx.Commit()
	if err != nil {
		glog.Infof("datastore error committing transaction: %v", err)
		return err
	}
	tx.Tx = nil
	return nil
}

// Rollback attempts to rollback a transaction.
func (tx *DatastoreTx) Rollback() error {
	if tx.Tx == nil {
		return nil
	}
	err := tx.Tx.Rollback()
	if err != nil {
		glog.Infof("datastore error during rollback of transaction: %v", err)
		return err
	}
	// Transaction cannot be used after a rollback.
	tx.Tx = nil
	return nil
}
