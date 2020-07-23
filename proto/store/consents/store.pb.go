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
// source: proto/store/consents/store.proto

// Package consents provides Remembered Consents PB for storage

package consents

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
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

// RequestMatchType defines what request is valid to use this consent.
type RememberedConsentPreference_RequestMatchType int32

const (
	// NONE : do not remember.
	RememberedConsentPreference_NONE RememberedConsentPreference_RequestMatchType = 0
	// SUBSET : request resource and scopes are subset of resource and scopes in
	// this item.
	RememberedConsentPreference_SUBSET RememberedConsentPreference_RequestMatchType = 1
	// ANYTHING : request anything.
	RememberedConsentPreference_ANYTHING RememberedConsentPreference_RequestMatchType = 2
)

var RememberedConsentPreference_RequestMatchType_name = map[int32]string{
	0: "NONE",
	1: "SUBSET",
	2: "ANYTHING",
}

var RememberedConsentPreference_RequestMatchType_value = map[string]int32{
	"NONE":     0,
	"SUBSET":   1,
	"ANYTHING": 2,
}

func (x RememberedConsentPreference_RequestMatchType) String() string {
	return proto.EnumName(RememberedConsentPreference_RequestMatchType_name, int32(x))
}

func (RememberedConsentPreference_RequestMatchType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0ffa029a8674e90e, []int{0, 0}
}

// ReleaseType defines what to release.
type RememberedConsentPreference_ReleaseType int32

const (
	RememberedConsentPreference_UNSPECIFIED RememberedConsentPreference_ReleaseType = 0
	// SELECTED : release selected visas of this item.
	RememberedConsentPreference_SELECTED RememberedConsentPreference_ReleaseType = 1
	// ANYTHING_NEEDED: release anything request needed.
	RememberedConsentPreference_ANYTHING_NEEDED RememberedConsentPreference_ReleaseType = 2
)

var RememberedConsentPreference_ReleaseType_name = map[int32]string{
	0: "UNSPECIFIED",
	1: "SELECTED",
	2: "ANYTHING_NEEDED",
}

var RememberedConsentPreference_ReleaseType_value = map[string]int32{
	"UNSPECIFIED":     0,
	"SELECTED":        1,
	"ANYTHING_NEEDED": 2,
}

func (x RememberedConsentPreference_ReleaseType) String() string {
	return proto.EnumName(RememberedConsentPreference_ReleaseType_name, int32(x))
}

func (RememberedConsentPreference_ReleaseType) EnumDescriptor() ([]byte, []int) {
	return fileDescriptor_0ffa029a8674e90e, []int{0, 1}
}

// RememberedConsentPreference contains the consent a user has given for release
// of visas to a specific OAuth client.
type RememberedConsentPreference struct {
	ClientName           string                                       `protobuf:"bytes,1,opt,name=client_name,json=clientName,proto3" json:"client_name,omitempty"`
	CreateTime           *timestamp.Timestamp                         `protobuf:"bytes,2,opt,name=create_time,json=createTime,proto3" json:"create_time,omitempty"`
	ExpireTime           *timestamp.Timestamp                         `protobuf:"bytes,3,opt,name=expire_time,json=expireTime,proto3" json:"expire_time,omitempty"`
	RequestMatchType     RememberedConsentPreference_RequestMatchType `protobuf:"varint,4,opt,name=request_match_type,json=requestMatchType,proto3,enum=consents.RememberedConsentPreference_RequestMatchType" json:"request_match_type,omitempty"`
	RequestedResources   []string                                     `protobuf:"bytes,5,rep,name=requested_resources,json=requestedResources,proto3" json:"requested_resources,omitempty"`
	RequestedScopes      []string                                     `protobuf:"bytes,6,rep,name=requested_scopes,json=requestedScopes,proto3" json:"requested_scopes,omitempty"`
	ReleaseType          RememberedConsentPreference_ReleaseType      `protobuf:"varint,7,opt,name=release_type,json=releaseType,proto3,enum=consents.RememberedConsentPreference_ReleaseType" json:"release_type,omitempty"`
	SelectedVisas        []*RememberedConsentPreference_Visa          `protobuf:"bytes,8,rep,name=selected_visas,json=selectedVisas,proto3" json:"selected_visas,omitempty"`
	ReleaseProfileName   bool                                         `protobuf:"varint,9,opt,name=release_profile_name,json=releaseProfileName,proto3" json:"release_profile_name,omitempty"`
	ReleaseProfileEmail  bool                                         `protobuf:"varint,10,opt,name=release_profile_email,json=releaseProfileEmail,proto3" json:"release_profile_email,omitempty"`
	ReleaseProfileOther  bool                                         `protobuf:"varint,11,opt,name=release_profile_other,json=releaseProfileOther,proto3" json:"release_profile_other,omitempty"`
	ReleaseAccountAdmin  bool                                         `protobuf:"varint,12,opt,name=release_account_admin,json=releaseAccountAdmin,proto3" json:"release_account_admin,omitempty"`
	ReleaseLink          bool                                         `protobuf:"varint,13,opt,name=release_link,json=releaseLink,proto3" json:"release_link,omitempty"`
	ReleaseIdentities    bool                                         `protobuf:"varint,14,opt,name=release_identities,json=releaseIdentities,proto3" json:"release_identities,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                     `json:"-"`
	XXX_unrecognized     []byte                                       `json:"-"`
	XXX_sizecache        int32                                        `json:"-"`
}

func (m *RememberedConsentPreference) Reset()         { *m = RememberedConsentPreference{} }
func (m *RememberedConsentPreference) String() string { return proto.CompactTextString(m) }
func (*RememberedConsentPreference) ProtoMessage()    {}
func (*RememberedConsentPreference) Descriptor() ([]byte, []int) {
	return fileDescriptor_0ffa029a8674e90e, []int{0}
}

func (m *RememberedConsentPreference) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RememberedConsentPreference.Unmarshal(m, b)
}
func (m *RememberedConsentPreference) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RememberedConsentPreference.Marshal(b, m, deterministic)
}
func (m *RememberedConsentPreference) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RememberedConsentPreference.Merge(m, src)
}
func (m *RememberedConsentPreference) XXX_Size() int {
	return xxx_messageInfo_RememberedConsentPreference.Size(m)
}
func (m *RememberedConsentPreference) XXX_DiscardUnknown() {
	xxx_messageInfo_RememberedConsentPreference.DiscardUnknown(m)
}

var xxx_messageInfo_RememberedConsentPreference proto.InternalMessageInfo

func (m *RememberedConsentPreference) GetClientName() string {
	if m != nil {
		return m.ClientName
	}
	return ""
}

func (m *RememberedConsentPreference) GetCreateTime() *timestamp.Timestamp {
	if m != nil {
		return m.CreateTime
	}
	return nil
}

func (m *RememberedConsentPreference) GetExpireTime() *timestamp.Timestamp {
	if m != nil {
		return m.ExpireTime
	}
	return nil
}

func (m *RememberedConsentPreference) GetRequestMatchType() RememberedConsentPreference_RequestMatchType {
	if m != nil {
		return m.RequestMatchType
	}
	return RememberedConsentPreference_NONE
}

func (m *RememberedConsentPreference) GetRequestedResources() []string {
	if m != nil {
		return m.RequestedResources
	}
	return nil
}

func (m *RememberedConsentPreference) GetRequestedScopes() []string {
	if m != nil {
		return m.RequestedScopes
	}
	return nil
}

func (m *RememberedConsentPreference) GetReleaseType() RememberedConsentPreference_ReleaseType {
	if m != nil {
		return m.ReleaseType
	}
	return RememberedConsentPreference_UNSPECIFIED
}

func (m *RememberedConsentPreference) GetSelectedVisas() []*RememberedConsentPreference_Visa {
	if m != nil {
		return m.SelectedVisas
	}
	return nil
}

func (m *RememberedConsentPreference) GetReleaseProfileName() bool {
	if m != nil {
		return m.ReleaseProfileName
	}
	return false
}

func (m *RememberedConsentPreference) GetReleaseProfileEmail() bool {
	if m != nil {
		return m.ReleaseProfileEmail
	}
	return false
}

func (m *RememberedConsentPreference) GetReleaseProfileOther() bool {
	if m != nil {
		return m.ReleaseProfileOther
	}
	return false
}

func (m *RememberedConsentPreference) GetReleaseAccountAdmin() bool {
	if m != nil {
		return m.ReleaseAccountAdmin
	}
	return false
}

func (m *RememberedConsentPreference) GetReleaseLink() bool {
	if m != nil {
		return m.ReleaseLink
	}
	return false
}

func (m *RememberedConsentPreference) GetReleaseIdentities() bool {
	if m != nil {
		return m.ReleaseIdentities
	}
	return false
}

// Visa contains fields to match released visas user have.
type RememberedConsentPreference_Visa struct {
	Type                 string   `protobuf:"bytes,1,opt,name=type,proto3" json:"type,omitempty"`
	Source               string   `protobuf:"bytes,2,opt,name=source,proto3" json:"source,omitempty"`
	By                   string   `protobuf:"bytes,3,opt,name=by,proto3" json:"by,omitempty"`
	Iss                  string   `protobuf:"bytes,4,opt,name=iss,proto3" json:"iss,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *RememberedConsentPreference_Visa) Reset()         { *m = RememberedConsentPreference_Visa{} }
func (m *RememberedConsentPreference_Visa) String() string { return proto.CompactTextString(m) }
func (*RememberedConsentPreference_Visa) ProtoMessage()    {}
func (*RememberedConsentPreference_Visa) Descriptor() ([]byte, []int) {
	return fileDescriptor_0ffa029a8674e90e, []int{0, 0}
}

func (m *RememberedConsentPreference_Visa) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_RememberedConsentPreference_Visa.Unmarshal(m, b)
}
func (m *RememberedConsentPreference_Visa) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_RememberedConsentPreference_Visa.Marshal(b, m, deterministic)
}
func (m *RememberedConsentPreference_Visa) XXX_Merge(src proto.Message) {
	xxx_messageInfo_RememberedConsentPreference_Visa.Merge(m, src)
}
func (m *RememberedConsentPreference_Visa) XXX_Size() int {
	return xxx_messageInfo_RememberedConsentPreference_Visa.Size(m)
}
func (m *RememberedConsentPreference_Visa) XXX_DiscardUnknown() {
	xxx_messageInfo_RememberedConsentPreference_Visa.DiscardUnknown(m)
}

var xxx_messageInfo_RememberedConsentPreference_Visa proto.InternalMessageInfo

func (m *RememberedConsentPreference_Visa) GetType() string {
	if m != nil {
		return m.Type
	}
	return ""
}

func (m *RememberedConsentPreference_Visa) GetSource() string {
	if m != nil {
		return m.Source
	}
	return ""
}

func (m *RememberedConsentPreference_Visa) GetBy() string {
	if m != nil {
		return m.By
	}
	return ""
}

func (m *RememberedConsentPreference_Visa) GetIss() string {
	if m != nil {
		return m.Iss
	}
	return ""
}

func init() {
	proto.RegisterEnum("consents.RememberedConsentPreference_RequestMatchType", RememberedConsentPreference_RequestMatchType_name, RememberedConsentPreference_RequestMatchType_value)
	proto.RegisterEnum("consents.RememberedConsentPreference_ReleaseType", RememberedConsentPreference_ReleaseType_name, RememberedConsentPreference_ReleaseType_value)
	proto.RegisterType((*RememberedConsentPreference)(nil), "consents.RememberedConsentPreference")
	proto.RegisterType((*RememberedConsentPreference_Visa)(nil), "consents.RememberedConsentPreference.Visa")
}

func init() { proto.RegisterFile("proto/store/consents/store.proto", fileDescriptor_0ffa029a8674e90e) }

var fileDescriptor_0ffa029a8674e90e = []byte{
	// 638 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x94, 0x4d, 0x6f, 0xda, 0x4c,
	0x10, 0xc7, 0xc3, 0xcb, 0xc3, 0x03, 0xe3, 0x84, 0xb8, 0x9b, 0xb6, 0xb2, 0xd2, 0x43, 0x68, 0x4e,
	0xb4, 0x12, 0x76, 0x4b, 0xa5, 0x5c, 0x7a, 0x22, 0xe0, 0xa6, 0x48, 0x29, 0xa1, 0x86, 0x54, 0x6d,
	0x2e, 0xd6, 0xb2, 0x1e, 0xc2, 0x2a, 0x7e, 0xa1, 0xbb, 0x4b, 0x54, 0xbe, 0x47, 0x3f, 0x70, 0xe5,
	0x5d, 0x9c, 0x37, 0x45, 0x6d, 0x6e, 0x9e, 0xff, 0x7f, 0x7e, 0x3b, 0xb3, 0xc3, 0x2c, 0xd0, 0x5a,
	0x8a, 0x4c, 0x65, 0x9e, 0x54, 0x99, 0x40, 0x8f, 0x65, 0xa9, 0xc4, 0x54, 0x49, 0x13, 0xba, 0xda,
	0x22, 0xf5, 0x42, 0xdd, 0x3f, 0xb8, 0xcc, 0xb2, 0xcb, 0x18, 0x3d, 0xad, 0xcf, 0x56, 0x73, 0x4f,
	0xf1, 0x04, 0xa5, 0xa2, 0xc9, 0xd2, 0xa4, 0x1e, 0xfe, 0xae, 0xc3, 0xab, 0x00, 0x13, 0x4c, 0x66,
	0x28, 0x30, 0xea, 0x1b, 0x6e, 0x2c, 0x70, 0x8e, 0x02, 0x53, 0x86, 0xe4, 0x00, 0x2c, 0x16, 0x73,
	0x4c, 0x55, 0x98, 0xd2, 0x04, 0x9d, 0x52, 0xab, 0xd4, 0x6e, 0x04, 0x60, 0xa4, 0x11, 0x4d, 0x90,
	0x7c, 0x04, 0x8b, 0x09, 0xa4, 0x0a, 0xc3, 0xfc, 0x68, 0xa7, 0xdc, 0x2a, 0xb5, 0xad, 0xee, 0xbe,
	0x6b, 0xea, 0xba, 0x45, 0x5d, 0x77, 0x5a, 0xd4, 0x0d, 0xc0, 0xa4, 0xe7, 0x42, 0x0e, 0xe3, 0xaf,
	0x25, 0x17, 0x1b, 0xb8, 0xf2, 0x6f, 0xd8, 0xa4, 0x6b, 0x38, 0x02, 0x22, 0xf0, 0xe7, 0x0a, 0xa5,
	0x0a, 0x13, 0xaa, 0xd8, 0x22, 0x54, 0xeb, 0x25, 0x3a, 0xd5, 0x56, 0xa9, 0xdd, 0xec, 0x1e, 0xb9,
	0xc5, 0x08, 0xdc, 0xbf, 0xdc, 0xce, 0x0d, 0x0c, 0xff, 0x25, 0xc7, 0xa7, 0xeb, 0x25, 0x06, 0xb6,
	0x78, 0xa0, 0x10, 0x0f, 0xf6, 0x36, 0x1a, 0x46, 0xa1, 0x40, 0x99, 0xad, 0x04, 0x43, 0xe9, 0xfc,
	0xd7, 0xaa, 0xb4, 0x1b, 0x01, 0xb9, 0xb1, 0x82, 0xc2, 0x21, 0x6f, 0xc0, 0xbe, 0x05, 0x24, 0xcb,
	0x96, 0x28, 0x9d, 0x9a, 0xce, 0xde, 0xbd, 0xd1, 0x27, 0x5a, 0x26, 0x53, 0xd8, 0x16, 0x18, 0x23,
	0x95, 0x68, 0x7a, 0xff, 0x5f, 0xf7, 0xfe, 0xfe, 0xa9, 0xbd, 0x6b, 0x52, 0xb7, 0x6d, 0x89, 0xdb,
	0x80, 0x7c, 0x85, 0xa6, 0xc4, 0x18, 0x59, 0x5e, 0xff, 0x9a, 0x4b, 0x2a, 0x9d, 0x7a, 0xab, 0xd2,
	0xb6, 0xba, 0x6f, 0x9f, 0x76, 0xee, 0x37, 0x2e, 0x69, 0xb0, 0x53, 0x9c, 0x90, 0x47, 0x92, 0xbc,
	0x83, 0xe7, 0x45, 0xa3, 0x4b, 0x91, 0xcd, 0x79, 0x8c, 0x66, 0x1d, 0x1a, 0xad, 0x52, 0xbb, 0x9e,
	0x4f, 0x41, 0x7b, 0x63, 0x63, 0xe9, 0xb5, 0xe8, 0xc2, 0x8b, 0x87, 0x04, 0x26, 0x94, 0xc7, 0x0e,
	0x68, 0x64, 0xef, 0x3e, 0xe2, 0xe7, 0xd6, 0x63, 0x4c, 0xa6, 0x16, 0x28, 0x1c, 0xeb, 0x31, 0xe6,
	0x2c, 0xb7, 0xee, 0x32, 0x94, 0xb1, 0x6c, 0x95, 0xaa, 0x90, 0x46, 0x09, 0x4f, 0x9d, 0xed, 0x7b,
	0x4c, 0xcf, 0x78, 0xbd, 0xdc, 0x22, 0xaf, 0x6f, 0xc7, 0x1e, 0xf3, 0xf4, 0xca, 0xd9, 0xd1, 0xa9,
	0xc5, 0x0c, 0x4f, 0x79, 0x7a, 0x45, 0x3a, 0x50, 0x5c, 0x2a, 0xe4, 0x11, 0xa6, 0x8a, 0x2b, 0x8e,
	0xd2, 0x69, 0xea, 0xc4, 0x67, 0x1b, 0x67, 0x78, 0x63, 0xec, 0x4f, 0xa1, 0x9a, 0x0f, 0x8a, 0x10,
	0xa8, 0xea, 0x1f, 0xd2, 0x3c, 0x13, 0xfd, 0x4d, 0x5e, 0x42, 0xcd, 0xac, 0x86, 0x7e, 0x1b, 0x8d,
	0x60, 0x13, 0x91, 0x26, 0x94, 0x67, 0x6b, 0xbd, 0xf2, 0x8d, 0xa0, 0x3c, 0x5b, 0x13, 0x1b, 0x2a,
	0x5c, 0x4a, 0xbd, 0xbf, 0x8d, 0x20, 0xff, 0x3c, 0x3c, 0x02, 0xfb, 0xe1, 0x82, 0x92, 0x3a, 0x54,
	0x47, 0x67, 0x23, 0xdf, 0xde, 0x22, 0x00, 0xb5, 0xc9, 0xf9, 0xf1, 0xc4, 0x9f, 0xda, 0x25, 0xb2,
	0x0d, 0xf5, 0xde, 0xe8, 0xc7, 0xf4, 0xf3, 0x70, 0x74, 0x62, 0x97, 0x0f, 0x7b, 0x60, 0xdd, 0x59,
	0x0e, 0xb2, 0x0b, 0xd6, 0xf9, 0x68, 0x32, 0xf6, 0xfb, 0xc3, 0x4f, 0x43, 0x7f, 0x60, 0x6f, 0xe5,
	0xd9, 0x13, 0xff, 0xd4, 0xef, 0x4f, 0xfd, 0x81, 0x5d, 0x22, 0x7b, 0xb0, 0x5b, 0xb0, 0xe1, 0xc8,
	0xf7, 0x07, 0xfe, 0xc0, 0x2e, 0x1f, 0x5f, 0x5c, 0x7c, 0xbf, 0xe4, 0x6a, 0xb1, 0x9a, 0xb9, 0x2c,
	0x4b, 0xbc, 0x13, 0xfd, 0x1e, 0xfb, 0x71, 0xb6, 0x8a, 0xc6, 0x31, 0x55, 0xf3, 0x4c, 0x24, 0xde,
	0x02, 0x69, 0xac, 0x16, 0x8c, 0x0a, 0xec, 0xcc, 0x31, 0x42, 0x41, 0x15, 0x46, 0x1d, 0xca, 0x18,
	0x4a, 0xd9, 0x91, 0x28, 0xae, 0x39, 0x43, 0xe9, 0x3d, 0xf6, 0x4f, 0x35, 0xab, 0x69, 0xf5, 0xc3,
	0x9f, 0x00, 0x00, 0x00, 0xff, 0xff, 0x54, 0x93, 0x9e, 0xd8, 0xc8, 0x04, 0x00, 0x00,
}
