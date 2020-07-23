// Copyright 2020 Google LLC
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

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: proto/process/v1/process.proto

// Package process provides protocol buffers for background process state.

package v1

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	duration "github.com/golang/protobuf/ptypes/duration"
	timestamp "github.com/golang/protobuf/ptypes/timestamp"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type Process_Status_State int32

const (
	Process_Status_UNSPECIFIED Process_Status_State = 0
	Process_Status_NEW         Process_Status_State = 1
	Process_Status_ACTIVE      Process_Status_State = 2
	Process_Status_ABORTED     Process_Status_State = 3
	Process_Status_INCOMPLETE  Process_Status_State = 4
	Process_Status_COMPLETED   Process_Status_State = 5
)

var Process_Status_State_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "NEW",
	2: "ACTIVE",
	3: "ABORTED",
	4: "INCOMPLETE",
	5: "COMPLETED",
}

var Process_Status_State_value = map[string]int32{
	"UNSPECIFIED": 0,
	"NEW":         1,
	"ACTIVE":      2,
	"ABORTED":     3,
	"INCOMPLETE":  4,
	"COMPLETED":   5,
}

func (x Process_Status_State) String() string {
	return proto.EnumName(Process_Status_State_name, int32(x))
}

func (Process_Status_State) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_b24df3f2bd7a2000, []int{0, 2, 0}
}

// Background process state
type Process struct {
	// Name of the process.
	ProcessName string `protobuf:"bytes,1,opt,name=process_name,json=processName,proto3" json:"process_name,omitempty"`
	// A GUID or other unique identifier for the last process instance that has
	// updated the process. This is a means of tracking state as multiple
	// background processes can attempt to grab and lock process state. It may
	// be used as a means to detect that locks have been lost.
	Instance string `protobuf:"bytes,2,opt,name=instance,proto3" json:"instance,omitempty"`
	// Frequency of how often a process is scheduled to start processing.
	ScheduleFrequency *duration.Duration `protobuf:"bytes,3,opt,name=schedule_frequency,json=scheduleFrequency,proto3" json:"schedule_frequency,omitempty"`
	// A set of active work items being processed. The key is the name of the work
	// item.
	ActiveWork map[string]*Process_Work `protobuf:"bytes,4,rep,name=active_work,json=activeWork,proto3" json:"active_work,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// Work to be dropped during a future active period. Is a map of the work
	// item name to timestamp of request. Some workers may treat this as a no-op
	// while others may have critical cleanup to do before dropping the work.
	// The key is the name of the work item.
	CleanupWork map[string]*timestamp.Timestamp `protobuf:"bytes,5,rep,name=cleanup_work,json=cleanupWork,proto3" json:"cleanup_work,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// Work that are no longer active (i.e. dropped) as a form of tracking
	// previous state. Is a map of work item name to timestamp of when the work
	// item was dropped. The key is the name of the work item.
	DroppedWork map[string]*timestamp.Timestamp `protobuf:"bytes,6,rep,name=dropped_work,json=droppedWork,proto3" json:"dropped_work,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// Input parameters for the worker to use across work items.
	Settings *Process_Params `protobuf:"bytes,7,opt,name=settings,proto3" json:"settings,omitempty"`
	// Time of most recent change to the ProcessStatus.Params settings.
	SettingsTime *timestamp.Timestamp `protobuf:"bytes,8,opt,name=settings_time,json=settingsTime,proto3" json:"settings_time,omitempty"`
	// Status over all work items for the most recent period or active period.
	ProcessStatus *Process_Status `protobuf:"bytes,9,opt,name=process_status,json=processStatus,proto3" json:"process_status,omitempty"`
	// Aggregate stats over all time periods for all work items since last reset.
	AggregateStats       map[string]float64 `protobuf:"bytes,10,rep,name=aggregate_stats,json=aggregateStats,proto3" json:"aggregate_stats,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"fixed64,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}           `json:"-"`
	XXX_unrecognized     []byte             `json:"-"`
	XXX_sizecache        int32              `json:"-"`
}

func (m *Process) Reset()         { *m = Process{} }
func (m *Process) String() string { return proto.CompactTextString(m) }
func (*Process) ProtoMessage()    {}
func (*Process) Descriptor() ([]byte, []int) {
	return fileDescriptor_b24df3f2bd7a2000, []int{0}
}

func (m *Process) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Process.Unmarshal(m, b)
}
func (m *Process) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Process.Marshal(b, m, deterministic)
}
func (m *Process) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Process.Merge(m, src)
}
func (m *Process) XXX_Size() int {
	return xxx_messageInfo_Process.Size(m)
}
func (m *Process) XXX_DiscardUnknown() {
	xxx_messageInfo_Process.DiscardUnknown(m)
}

var xxx_messageInfo_Process proto.InternalMessageInfo

func (m *Process) GetProcessName() string {
	if m != nil {
		return m.ProcessName
	}
	return ""
}

func (m *Process) GetInstance() string {
	if m != nil {
		return m.Instance
	}
	return ""
}

func (m *Process) GetScheduleFrequency() *duration.Duration {
	if m != nil {
		return m.ScheduleFrequency
	}
	return nil
}

func (m *Process) GetActiveWork() map[string]*Process_Work {
	if m != nil {
		return m.ActiveWork
	}
	return nil
}

func (m *Process) GetCleanupWork() map[string]*timestamp.Timestamp {
	if m != nil {
		return m.CleanupWork
	}
	return nil
}

func (m *Process) GetDroppedWork() map[string]*timestamp.Timestamp {
	if m != nil {
		return m.DroppedWork
	}
	return nil
}

func (m *Process) GetSettings() *Process_Params {
	if m != nil {
		return m.Settings
	}
	return nil
}

func (m *Process) GetSettingsTime() *timestamp.Timestamp {
	if m != nil {
		return m.SettingsTime
	}
	return nil
}

func (m *Process) GetProcessStatus() *Process_Status {
	if m != nil {
		return m.ProcessStatus
	}
	return nil
}

func (m *Process) GetAggregateStats() map[string]float64 {
	if m != nil {
		return m.AggregateStats
	}
	return nil
}

// Error message that is kept in context with the background process
// for debugging.
type Process_Error struct {
	// Timestamp of the error.
	Time *timestamp.Timestamp `protobuf:"bytes,1,opt,name=time,proto3" json:"time,omitempty"`
	// Error message.
	Text                 string   `protobuf:"bytes,2,opt,name=text,proto3" json:"text,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Process_Error) Reset()         { *m = Process_Error{} }
func (m *Process_Error) String() string { return proto.CompactTextString(m) }
func (*Process_Error) ProtoMessage()    {}
func (*Process_Error) Descriptor() ([]byte, []int) {
	return fileDescriptor_b24df3f2bd7a2000, []int{0, 0}
}

func (m *Process_Error) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Process_Error.Unmarshal(m, b)
}
func (m *Process_Error) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Process_Error.Marshal(b, m, deterministic)
}
func (m *Process_Error) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Process_Error.Merge(m, src)
}
func (m *Process_Error) XXX_Size() int {
	return xxx_messageInfo_Process_Error.Size(m)
}
func (m *Process_Error) XXX_DiscardUnknown() {
	xxx_messageInfo_Process_Error.DiscardUnknown(m)
}

var xxx_messageInfo_Process_Error proto.InternalMessageInfo

func (m *Process_Error) GetTime() *timestamp.Timestamp {
	if m != nil {
		return m.Time
	}
	return nil
}

func (m *Process_Error) GetText() string {
	if m != nil {
		return m.Text
	}
	return ""
}

// Input parameters configured for the background process that control
// its behavior.
type Process_Params struct {
	// Process-specific map of integer parameter name to parameter value.
	IntParams map[string]int64 `protobuf:"bytes,1,rep,name=int_params,json=intParams,proto3" json:"int_params,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"varint,2,opt,name=value,proto3"`
	// Process-specific map of string parameter name to parameter value.
	StringParams         map[string]string `protobuf:"bytes,2,rep,name=string_params,json=stringParams,proto3" json:"string_params,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Process_Params) Reset()         { *m = Process_Params{} }
func (m *Process_Params) String() string { return proto.CompactTextString(m) }
func (*Process_Params) ProtoMessage()    {}
func (*Process_Params) Descriptor() ([]byte, []int) {
	return fileDescriptor_b24df3f2bd7a2000, []int{0, 1}
}

func (m *Process_Params) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Process_Params.Unmarshal(m, b)
}
func (m *Process_Params) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Process_Params.Marshal(b, m, deterministic)
}
func (m *Process_Params) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Process_Params.Merge(m, src)
}
func (m *Process_Params) XXX_Size() int {
	return xxx_messageInfo_Process_Params.Size(m)
}
func (m *Process_Params) XXX_DiscardUnknown() {
	xxx_messageInfo_Process_Params.DiscardUnknown(m)
}

var xxx_messageInfo_Process_Params proto.InternalMessageInfo

func (m *Process_Params) GetIntParams() map[string]int64 {
	if m != nil {
		return m.IntParams
	}
	return nil
}

func (m *Process_Params) GetStringParams() map[string]string {
	if m != nil {
		return m.StringParams
	}
	return nil
}

// Execution status for a particular run or snapshot of the process.
type Process_Status struct {
	// Time period start.
	StartTime *timestamp.Timestamp `protobuf:"bytes,1,opt,name=start_time,json=startTime,proto3" json:"start_time,omitempty"`
	// Time of last progress status update. This will be equal to the
	// finish_time if the processing has completed.
	ProgressTime *timestamp.Timestamp `protobuf:"bytes,2,opt,name=progress_time,json=progressTime,proto3" json:"progress_time,omitempty"`
	// Time period end.
	FinishTime *timestamp.Timestamp `protobuf:"bytes,3,opt,name=finish_time,json=finishTime,proto3" json:"finish_time,omitempty"`
	// Time of most recent error.
	LastErrorTime *timestamp.Timestamp `protobuf:"bytes,4,opt,name=last_error_time,json=lastErrorTime,proto3" json:"last_error_time,omitempty"`
	// Statistics collected of statistic label to statistic value.
	Stats map[string]float64 `protobuf:"bytes,5,rep,name=stats,proto3" json:"stats,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"fixed64,2,opt,name=value,proto3"`
	// Recent errors, which may have less entries than total errors to reduce
	// space and noise.
	Errors []*Process_Error `protobuf:"bytes,6,rep,name=errors,proto3" json:"errors,omitempty"`
	// Total number of errors before the process completed or aborted.
	TotalErrors          int64                `protobuf:"varint,7,opt,name=total_errors,json=totalErrors,proto3" json:"total_errors,omitempty"`
	State                Process_Status_State `protobuf:"varint,8,opt,name=state,proto3,enum=process.Process_Status_State" json:"state,omitempty"`
	XXX_NoUnkeyedLiteral struct{}             `json:"-"`
	XXX_unrecognized     []byte               `json:"-"`
	XXX_sizecache        int32                `json:"-"`
}

func (m *Process_Status) Reset()         { *m = Process_Status{} }
func (m *Process_Status) String() string { return proto.CompactTextString(m) }
func (*Process_Status) ProtoMessage()    {}
func (*Process_Status) Descriptor() ([]byte, []int) {
	return fileDescriptor_b24df3f2bd7a2000, []int{0, 2}
}

func (m *Process_Status) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Process_Status.Unmarshal(m, b)
}
func (m *Process_Status) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Process_Status.Marshal(b, m, deterministic)
}
func (m *Process_Status) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Process_Status.Merge(m, src)
}
func (m *Process_Status) XXX_Size() int {
	return xxx_messageInfo_Process_Status.Size(m)
}
func (m *Process_Status) XXX_DiscardUnknown() {
	xxx_messageInfo_Process_Status.DiscardUnknown(m)
}

var xxx_messageInfo_Process_Status proto.InternalMessageInfo

func (m *Process_Status) GetStartTime() *timestamp.Timestamp {
	if m != nil {
		return m.StartTime
	}
	return nil
}

func (m *Process_Status) GetProgressTime() *timestamp.Timestamp {
	if m != nil {
		return m.ProgressTime
	}
	return nil
}

func (m *Process_Status) GetFinishTime() *timestamp.Timestamp {
	if m != nil {
		return m.FinishTime
	}
	return nil
}

func (m *Process_Status) GetLastErrorTime() *timestamp.Timestamp {
	if m != nil {
		return m.LastErrorTime
	}
	return nil
}

func (m *Process_Status) GetStats() map[string]float64 {
	if m != nil {
		return m.Stats
	}
	return nil
}

func (m *Process_Status) GetErrors() []*Process_Error {
	if m != nil {
		return m.Errors
	}
	return nil
}

func (m *Process_Status) GetTotalErrors() int64 {
	if m != nil {
		return m.TotalErrors
	}
	return 0
}

func (m *Process_Status) GetState() Process_Status_State {
	if m != nil {
		return m.State
	}
	return Process_Status_UNSPECIFIED
}

// Processes may act on a set of work items, and may have different input
// parameters per item. What work items represent may be different between
// different types of workers. A worker gets called for each item on a work
// list (stored as maps, but can be iterated over as a list).
// A named work item can only appear on one of three maps:
// 1. active_work
// 2. cleanup_work
// 3. dropped_work
type Process_Work struct {
	// Time when the work item's settings was last modified.
	Modified *timestamp.Timestamp `protobuf:"bytes,1,opt,name=modified,proto3" json:"modified,omitempty"`
	// Input parameters for the work item. These will vary depending on the
	// needs of process workers that may need input parameters to complete their
	// work.
	// Example: if there were a rename process that occationally updates the
	// names of objects in the storage layer, then it may have params of:
	//   {
	//     "stringParams": {
	//       "find": "old_name",
	//       "replace": "new_name"
	//     }
	//     "intParams": {
	//       "maxReplacements": 1
	//     }
	//   }
	// Note: this structure allows input parameters to vary between work items.
	Params *Process_Params `protobuf:"bytes,2,opt,name=params,proto3" json:"params,omitempty"`
	// Work status. Changes here do not cause "modified" settings timestamp
	// to change.
	Status               *Process_Status `protobuf:"bytes,3,opt,name=status,proto3" json:"status,omitempty"`
	XXX_NoUnkeyedLiteral struct{}        `json:"-"`
	XXX_unrecognized     []byte          `json:"-"`
	XXX_sizecache        int32           `json:"-"`
}

func (m *Process_Work) Reset()         { *m = Process_Work{} }
func (m *Process_Work) String() string { return proto.CompactTextString(m) }
func (*Process_Work) ProtoMessage()    {}
func (*Process_Work) Descriptor() ([]byte, []int) {
	return fileDescriptor_b24df3f2bd7a2000, []int{0, 3}
}

func (m *Process_Work) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Process_Work.Unmarshal(m, b)
}
func (m *Process_Work) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Process_Work.Marshal(b, m, deterministic)
}
func (m *Process_Work) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Process_Work.Merge(m, src)
}
func (m *Process_Work) XXX_Size() int {
	return xxx_messageInfo_Process_Work.Size(m)
}
func (m *Process_Work) XXX_DiscardUnknown() {
	xxx_messageInfo_Process_Work.DiscardUnknown(m)
}

var xxx_messageInfo_Process_Work proto.InternalMessageInfo

func (m *Process_Work) GetModified() *timestamp.Timestamp {
	if m != nil {
		return m.Modified
	}
	return nil
}

func (m *Process_Work) GetParams() *Process_Params {
	if m != nil {
		return m.Params
	}
	return nil
}

func (m *Process_Work) GetStatus() *Process_Status {
	if m != nil {
		return m.Status
	}
	return nil
}

// WorkResponse returns the state of one work item related to. For use with
// endpoint responses such as LROs.
type WorkResponse struct {
	// Identifier for the work item.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	// The completion state of the work item as one of the following:
	//   "unspecified": Status.State.UNSPECIFIED
	//   "queued":      Status.State.NEW
	//   "active":      Status.State.ACTIVE
	//   "aborted":     Status.State.ABORTED
	//   "incomplete":  Status.State.INCOMPLETE
	//   "completed":   Status.State.COMPLETED
	//   "dropped":     On the DroppedWork list
	//   "cleanup":     On the CleanupWork list
	//   "purged":      Status was removed from the system (or never existed)
	State string `protobuf:"bytes,2,opt,name=state,proto3" json:"state,omitempty"`
	// The work processing/queuing details. Only available when the work item
	// is on the ActiveWork list.
	Details *Process_Work `protobuf:"bytes,3,opt,name=details,proto3" json:"details,omitempty"`
	// The URI of where to fetch the more information about the work item.
	Uri                  string   `protobuf:"bytes,4,opt,name=uri,proto3" json:"uri,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *WorkResponse) Reset()         { *m = WorkResponse{} }
func (m *WorkResponse) String() string { return proto.CompactTextString(m) }
func (*WorkResponse) ProtoMessage()    {}
func (*WorkResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_b24df3f2bd7a2000, []int{1}
}

func (m *WorkResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_WorkResponse.Unmarshal(m, b)
}
func (m *WorkResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_WorkResponse.Marshal(b, m, deterministic)
}
func (m *WorkResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_WorkResponse.Merge(m, src)
}
func (m *WorkResponse) XXX_Size() int {
	return xxx_messageInfo_WorkResponse.Size(m)
}
func (m *WorkResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_WorkResponse.DiscardUnknown(m)
}

var xxx_messageInfo_WorkResponse proto.InternalMessageInfo

func (m *WorkResponse) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *WorkResponse) GetState() string {
	if m != nil {
		return m.State
	}
	return ""
}

func (m *WorkResponse) GetDetails() *Process_Work {
	if m != nil {
		return m.Details
	}
	return nil
}

func (m *WorkResponse) GetUri() string {
	if m != nil {
		return m.Uri
	}
	return ""
}

func init() {
	proto.RegisterEnum("process.Process_Status_State", Process_Status_State_name, Process_Status_State_value)
	proto.RegisterType((*Process)(nil), "process.Process")
	proto.RegisterMapType((map[string]*Process_Work)(nil), "process.Process.ActiveWorkEntry")
	proto.RegisterMapType((map[string]float64)(nil), "process.Process.AggregateStatsEntry")
	proto.RegisterMapType((map[string]*timestamp.Timestamp)(nil), "process.Process.CleanupWorkEntry")
	proto.RegisterMapType((map[string]*timestamp.Timestamp)(nil), "process.Process.DroppedWorkEntry")
	proto.RegisterType((*Process_Error)(nil), "process.Process.Error")
	proto.RegisterType((*Process_Params)(nil), "process.Process.Params")
	proto.RegisterMapType((map[string]int64)(nil), "process.Process.Params.IntParamsEntry")
	proto.RegisterMapType((map[string]string)(nil), "process.Process.Params.StringParamsEntry")
	proto.RegisterType((*Process_Status)(nil), "process.Process.Status")
	proto.RegisterMapType((map[string]float64)(nil), "process.Process.Status.StatsEntry")
	proto.RegisterType((*Process_Work)(nil), "process.Process.Work")
	proto.RegisterType((*WorkResponse)(nil), "process.WorkResponse")
}

func init() { proto.RegisterFile("proto/process/v1/process.proto", fileDescriptor_b24df3f2bd7a2000) }

var fileDescriptor_b24df3f2bd7a2000 = []byte{
	// 926 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xac, 0x56, 0xed, 0x6e, 0xe3, 0x44,
	0x14, 0xc5, 0xf9, 0x6c, 0xae, 0x93, 0xd4, 0x3b, 0x7c, 0x19, 0x4b, 0x2c, 0xdd, 0x0a, 0xa1, 0x22,
	0x54, 0x1b, 0x5a, 0x09, 0x95, 0x0f, 0x51, 0xa5, 0x89, 0x17, 0x22, 0xd8, 0x6c, 0xe4, 0x86, 0x5d,
	0xb1, 0x7f, 0xa2, 0xa9, 0x3d, 0x71, 0x46, 0x75, 0xec, 0x30, 0x33, 0xee, 0xd2, 0x97, 0x41, 0xfc,
	0xe3, 0xa5, 0x78, 0x18, 0xe4, 0x19, 0x3b, 0x4d, 0x93, 0x26, 0x29, 0x12, 0xff, 0xe6, 0x5e, 0x9f,
	0x73, 0xe6, 0xce, 0x9d, 0x73, 0x27, 0x81, 0xa7, 0x73, 0x96, 0x88, 0xc4, 0x99, 0xb3, 0xc4, 0x27,
	0x9c, 0x3b, 0x37, 0x5f, 0x15, 0x4b, 0x5b, 0x7e, 0x40, 0xf5, 0x3c, 0xb4, 0x9e, 0x86, 0x49, 0x12,
	0x46, 0xc4, 0x91, 0xe9, 0xab, 0x74, 0xe2, 0x04, 0x29, 0xc3, 0x82, 0x26, 0xb1, 0x02, 0x5a, 0x9f,
	0xac, 0x7e, 0x17, 0x74, 0x46, 0xb8, 0xc0, 0xb3, 0xb9, 0x02, 0x1c, 0xfe, 0x6d, 0x40, 0x7d, 0xa8,
	0xc4, 0xd0, 0x33, 0x68, 0xe6, 0xba, 0xe3, 0x18, 0xcf, 0x88, 0xa9, 0x1d, 0x68, 0x47, 0x0d, 0x4f,
	0xcf, 0x73, 0x03, 0x3c, 0x23, 0xc8, 0x82, 0x3d, 0x1a, 0x73, 0x81, 0x63, 0x9f, 0x98, 0x25, 0xf9,
	0x79, 0x11, 0xa3, 0x9f, 0x00, 0x71, 0x7f, 0x4a, 0x82, 0x34, 0x22, 0xe3, 0x09, 0x23, 0xbf, 0xa7,
	0x24, 0xf6, 0x6f, 0xcd, 0xf2, 0x81, 0x76, 0xa4, 0x9f, 0x7c, 0x64, 0xab, 0x42, 0xec, 0xa2, 0x10,
	0xbb, 0x97, 0x17, 0xea, 0x3d, 0x29, 0x48, 0xcf, 0x0b, 0x0e, 0xea, 0x80, 0x8e, 0x7d, 0x41, 0x6f,
	0xc8, 0xf8, 0x6d, 0xc2, 0xae, 0xcd, 0xca, 0x41, 0xf9, 0x48, 0x3f, 0x39, 0xb0, 0x8b, 0x1e, 0xe4,
	0xf5, 0xda, 0x1d, 0x89, 0x79, 0x9d, 0xb0, 0x6b, 0x37, 0x16, 0xec, 0xd6, 0x03, 0xbc, 0x48, 0xa0,
	0x1e, 0x34, 0xfd, 0x88, 0xe0, 0x38, 0x9d, 0x2b, 0x8d, 0xaa, 0xd4, 0x78, 0xb6, 0xa6, 0xd1, 0x55,
	0xa0, 0x3b, 0x11, 0xdd, 0xbf, 0xcb, 0x64, 0x2a, 0x01, 0x4b, 0xe6, 0x73, 0x12, 0x28, 0x95, 0xda,
	0x06, 0x95, 0x9e, 0x02, 0x2d, 0xa9, 0x04, 0x77, 0x19, 0x74, 0x0a, 0x7b, 0x9c, 0x08, 0x41, 0xe3,
	0x90, 0x9b, 0x75, 0xd9, 0x8e, 0x0f, 0xd7, 0x14, 0x86, 0x98, 0xe1, 0x19, 0xf7, 0x16, 0x40, 0x74,
	0x0e, 0xad, 0x62, 0x3d, 0xce, 0x2e, 0xcd, 0xdc, 0x93, 0x4c, 0x6b, 0xad, 0x91, 0xa3, 0xe2, 0x46,
	0xbd, 0x66, 0x41, 0xc8, 0x52, 0xe8, 0x07, 0x68, 0x17, 0xb7, 0xc9, 0x05, 0x16, 0x29, 0x37, 0x1b,
	0x1b, 0xf6, 0xbe, 0x94, 0x9f, 0xbd, 0x56, 0x9e, 0x57, 0x21, 0x7a, 0x01, 0xfb, 0x38, 0x0c, 0x19,
	0x09, 0xb1, 0x20, 0x52, 0x81, 0x9b, 0x20, 0x8f, 0xff, 0xe9, 0xfa, 0x45, 0x14, 0xb8, 0x8c, 0xca,
	0x55, 0x07, 0xda, 0xf8, 0x5e, 0xd2, 0xfa, 0x19, 0xaa, 0x2e, 0x63, 0x09, 0x43, 0x36, 0x54, 0xe4,
	0x79, 0xb4, 0x9d, 0xe7, 0x91, 0x38, 0x84, 0xa0, 0x22, 0xc8, 0x1f, 0x22, 0xb7, 0x9b, 0x5c, 0x5b,
	0x7f, 0x96, 0xa0, 0xa6, 0x3a, 0x86, 0x5c, 0x00, 0x1a, 0x8b, 0xf1, 0x5c, 0x46, 0xa6, 0x26, 0x2b,
	0xfc, 0x6c, 0x43, 0x7b, 0xed, 0x7e, 0x2c, 0xd4, 0x4a, 0xd5, 0xd8, 0xa0, 0x45, 0x8c, 0x06, 0xd0,
	0xe2, 0x82, 0xd1, 0x38, 0x2c, 0x94, 0x4a, 0x52, 0xe9, 0xf3, 0x4d, 0x4a, 0x97, 0x12, 0xbc, 0x2c,
	0xd6, 0xe4, 0x4b, 0x29, 0xeb, 0x7b, 0x68, 0xdf, 0xdf, 0x0c, 0x19, 0x50, 0xbe, 0x26, 0xb7, 0xf9,
	0x50, 0x65, 0x4b, 0xf4, 0x1e, 0x54, 0x6f, 0x70, 0x94, 0xaa, 0x49, 0x2a, 0x7b, 0x2a, 0xf8, 0xb6,
	0x74, 0xa6, 0x59, 0xe7, 0xf0, 0x64, 0x6d, 0x83, 0x5d, 0x02, 0x8d, 0x65, 0x81, 0x7f, 0x2a, 0x50,
	0xcb, 0xef, 0xf1, 0x1b, 0x00, 0x2e, 0x30, 0x13, 0xe3, 0x47, 0x76, 0xbd, 0x21, 0xd1, 0xd2, 0x42,
	0xe7, 0x90, 0x79, 0x22, 0x64, 0x99, 0x87, 0x24, 0xbb, 0xb4, 0xdb, 0x83, 0x05, 0x41, 0x0a, 0x7c,
	0x07, 0xfa, 0x84, 0xc6, 0x94, 0x4f, 0x15, 0xbd, 0xbc, 0x93, 0x0e, 0x0a, 0x2e, 0xc9, 0x17, 0xb0,
	0x1f, 0x61, 0x2e, 0xc6, 0x24, 0xb3, 0x8d, 0x12, 0xa8, 0xec, 0x14, 0x68, 0x65, 0x14, 0x69, 0x34,
	0xa9, 0x71, 0x06, 0x55, 0x65, 0x5d, 0x35, 0xff, 0x87, 0x1b, 0xbc, 0x6f, 0x2f, 0x19, 0x57, 0x11,
	0x90, 0x0d, 0x35, 0xb9, 0x31, 0xcf, 0x87, 0xfe, 0x83, 0x35, 0xaa, 0xdc, 0xc5, 0xcb, 0x51, 0xd9,
	0xe3, 0x29, 0x12, 0x81, 0xa3, 0x71, 0xce, 0xaa, 0xcb, 0x3b, 0xd5, 0x65, 0xce, 0x55, 0x90, 0x53,
	0x55, 0x8c, 0x1a, 0xe5, 0xf6, 0xc9, 0xc7, 0xdb, 0x8a, 0x21, 0xaa, 0x0e, 0x62, 0x9d, 0x01, 0xdc,
	0x15, 0xb7, 0xcb, 0x03, 0xda, 0x92, 0x07, 0x0e, 0x7f, 0x83, 0xaa, 0x54, 0x42, 0xfb, 0xa0, 0xff,
	0x3a, 0xb8, 0x1c, 0xba, 0xdd, 0xfe, 0xf3, 0xbe, 0xdb, 0x33, 0xde, 0x41, 0x75, 0x28, 0x0f, 0xdc,
	0xd7, 0x86, 0x86, 0x00, 0x6a, 0x9d, 0xee, 0xa8, 0xff, 0xca, 0x35, 0x4a, 0x48, 0x87, 0x7a, 0xe7,
	0xe2, 0xa5, 0x37, 0x72, 0x7b, 0x46, 0x19, 0xb5, 0x01, 0xfa, 0x83, 0xee, 0xcb, 0x17, 0xc3, 0x5f,
	0xdc, 0x91, 0x6b, 0x54, 0x50, 0x0b, 0x1a, 0x45, 0xd4, 0x33, 0xaa, 0xd6, 0x5f, 0x1a, 0x54, 0xe4,
	0xd3, 0xf6, 0x35, 0xec, 0xcd, 0x92, 0x80, 0x4e, 0x28, 0x09, 0x1e, 0x61, 0xad, 0x05, 0x16, 0x39,
	0x50, 0x5b, 0xcc, 0xd9, 0xd6, 0x07, 0x31, 0x87, 0x65, 0x84, 0xfc, 0x15, 0x2b, 0x6f, 0x7f, 0xc5,
	0x72, 0x98, 0x35, 0x82, 0xfd, 0x95, 0xdf, 0x87, 0x07, 0x9a, 0xf7, 0xc5, 0x72, 0xf3, 0xf4, 0x93,
	0xf7, 0xd7, 0x44, 0x33, 0xf2, 0xf2, 0x5c, 0xbd, 0x01, 0x63, 0xf5, 0x17, 0xe3, 0x01, 0xd9, 0x2f,
	0xef, 0xcb, 0x6e, 0x6b, 0xc9, 0x7d, 0xed, 0xd5, 0xdf, 0x91, 0xff, 0x4d, 0xbb, 0x03, 0xef, 0x3e,
	0xf0, 0x48, 0xff, 0x27, 0x3b, 0xbd, 0x85, 0xa6, 0xec, 0x06, 0xe1, 0xf3, 0x24, 0xe6, 0x04, 0xb5,
	0xa1, 0x44, 0x83, 0x9c, 0x5a, 0xa2, 0x41, 0xc6, 0x54, 0xee, 0xce, 0x1f, 0x23, 0x19, 0x20, 0x07,
	0xea, 0x01, 0x11, 0x98, 0x46, 0xc5, 0xc5, 0x6d, 0xe8, 0x71, 0x81, 0xca, 0x4a, 0x4a, 0x19, 0x95,
	0x93, 0xde, 0xf0, 0xb2, 0xe5, 0xc5, 0xab, 0x37, 0xa3, 0x90, 0x8a, 0x69, 0x7a, 0x65, 0xfb, 0xc9,
	0xcc, 0xf9, 0x51, 0x1e, 0xb7, 0x1b, 0x25, 0x69, 0x30, 0x8c, 0xb0, 0x98, 0x24, 0x6c, 0xe6, 0x4c,
	0x09, 0x8e, 0xc4, 0xd4, 0xc7, 0x8c, 0x1c, 0x4f, 0x48, 0x40, 0x18, 0x16, 0x24, 0x38, 0xc6, 0x7e,
	0xa6, 0x7e, 0xcc, 0x09, 0xbb, 0xa1, 0x3e, 0xe1, 0xce, 0xea, 0x5f, 0xaa, 0xab, 0x9a, 0xcc, 0x9c,
	0xfe, 0x1b, 0x00, 0x00, 0xff, 0xff, 0x32, 0x85, 0xb7, 0xb0, 0x6d, 0x09, 0x00, 0x00,
}
