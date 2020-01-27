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
// source: proto/common/v1/oauthclient.proto

package v1

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
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

type Client struct {
	ClientId             string            `protobuf:"bytes,1,opt,name=client_id,json=clientId,proto3" json:"client_id,omitempty"`
	Scope                string            `protobuf:"bytes,5,opt,name=scope,proto3" json:"scope,omitempty"`
	RedirectUris         []string          `protobuf:"bytes,2,rep,name=redirect_uris,json=redirectUris,proto3" json:"redirect_uris,omitempty"`
	GrantTypes           []string          `protobuf:"bytes,6,rep,name=grant_types,json=grantTypes,proto3" json:"grant_types,omitempty"`
	ResponseTypes        []string          `protobuf:"bytes,7,rep,name=response_types,json=responseTypes,proto3" json:"response_types,omitempty"`
	Ui                   map[string]string `protobuf:"bytes,3,rep,name=ui,proto3" json:"ui,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Client) Reset()         { *m = Client{} }
func (m *Client) String() string { return proto.CompactTextString(m) }
func (*Client) ProtoMessage()    {}
func (*Client) Descriptor() ([]byte, []int) {
	return fileDescriptor_e55280de4537fe26, []int{0}
}

func (m *Client) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Client.Unmarshal(m, b)
}
func (m *Client) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Client.Marshal(b, m, deterministic)
}
func (m *Client) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Client.Merge(m, src)
}
func (m *Client) XXX_Size() int {
	return xxx_messageInfo_Client.Size(m)
}
func (m *Client) XXX_DiscardUnknown() {
	xxx_messageInfo_Client.DiscardUnknown(m)
}

var xxx_messageInfo_Client proto.InternalMessageInfo

func (m *Client) GetClientId() string {
	if m != nil {
		return m.ClientId
	}
	return ""
}

func (m *Client) GetScope() string {
	if m != nil {
		return m.Scope
	}
	return ""
}

func (m *Client) GetRedirectUris() []string {
	if m != nil {
		return m.RedirectUris
	}
	return nil
}

func (m *Client) GetGrantTypes() []string {
	if m != nil {
		return m.GrantTypes
	}
	return nil
}

func (m *Client) GetResponseTypes() []string {
	if m != nil {
		return m.ResponseTypes
	}
	return nil
}

func (m *Client) GetUi() map[string]string {
	if m != nil {
		return m.Ui
	}
	return nil
}

type ClientResponse struct {
	Client               *Client  `protobuf:"bytes,1,opt,name=client,proto3" json:"client,omitempty"`
	ClientSecret         string   `protobuf:"bytes,2,opt,name=client_secret,proto3" json:"client_secret,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ClientResponse) Reset()         { *m = ClientResponse{} }
func (m *ClientResponse) String() string { return proto.CompactTextString(m) }
func (*ClientResponse) ProtoMessage()    {}
func (*ClientResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_e55280de4537fe26, []int{1}
}

func (m *ClientResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ClientResponse.Unmarshal(m, b)
}
func (m *ClientResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ClientResponse.Marshal(b, m, deterministic)
}
func (m *ClientResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ClientResponse.Merge(m, src)
}
func (m *ClientResponse) XXX_Size() int {
	return xxx_messageInfo_ClientResponse.Size(m)
}
func (m *ClientResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ClientResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ClientResponse proto.InternalMessageInfo

func (m *ClientResponse) GetClient() *Client {
	if m != nil {
		return m.Client
	}
	return nil
}

func (m *ClientResponse) GetClientSecret() string {
	if m != nil {
		return m.ClientSecret
	}
	return ""
}

type ConfigModification struct {
	Revision             int64                                              `protobuf:"varint,1,opt,name=revision,proto3" json:"revision,omitempty"`
	TestPersonas         map[string]*ConfigModification_PersonaModification `protobuf:"bytes,2,rep,name=test_personas,json=testPersonas,proto3" json:"test_personas,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	DryRun               bool                                               `protobuf:"varint,3,opt,name=dry_run,json=dryRun,proto3" json:"dry_run,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                                           `json:"-"`
	XXX_unrecognized     []byte                                             `json:"-"`
	XXX_sizecache        int32                                              `json:"-"`
}

func (m *ConfigModification) Reset()         { *m = ConfigModification{} }
func (m *ConfigModification) String() string { return proto.CompactTextString(m) }
func (*ConfigModification) ProtoMessage()    {}
func (*ConfigModification) Descriptor() ([]byte, []int) {
	return fileDescriptor_e55280de4537fe26, []int{2}
}

func (m *ConfigModification) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ConfigModification.Unmarshal(m, b)
}
func (m *ConfigModification) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ConfigModification.Marshal(b, m, deterministic)
}
func (m *ConfigModification) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConfigModification.Merge(m, src)
}
func (m *ConfigModification) XXX_Size() int {
	return xxx_messageInfo_ConfigModification.Size(m)
}
func (m *ConfigModification) XXX_DiscardUnknown() {
	xxx_messageInfo_ConfigModification.DiscardUnknown(m)
}

var xxx_messageInfo_ConfigModification proto.InternalMessageInfo

func (m *ConfigModification) GetRevision() int64 {
	if m != nil {
		return m.Revision
	}
	return 0
}

func (m *ConfigModification) GetTestPersonas() map[string]*ConfigModification_PersonaModification {
	if m != nil {
		return m.TestPersonas
	}
	return nil
}

func (m *ConfigModification) GetDryRun() bool {
	if m != nil {
		return m.DryRun
	}
	return false
}

type ConfigModification_PersonaModification struct {
	Access               []string `protobuf:"bytes,1,rep,name=access,proto3" json:"access,omitempty"`
	AddAccess            []string `protobuf:"bytes,2,rep,name=add_access,json=addAccess,proto3" json:"add_access,omitempty"`
	RemoveAccess         []string `protobuf:"bytes,3,rep,name=remove_access,json=removeAccess,proto3" json:"remove_access,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ConfigModification_PersonaModification) Reset() {
	*m = ConfigModification_PersonaModification{}
}
func (m *ConfigModification_PersonaModification) String() string { return proto.CompactTextString(m) }
func (*ConfigModification_PersonaModification) ProtoMessage()    {}
func (*ConfigModification_PersonaModification) Descriptor() ([]byte, []int) {
	return fileDescriptor_e55280de4537fe26, []int{2, 0}
}

func (m *ConfigModification_PersonaModification) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ConfigModification_PersonaModification.Unmarshal(m, b)
}
func (m *ConfigModification_PersonaModification) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ConfigModification_PersonaModification.Marshal(b, m, deterministic)
}
func (m *ConfigModification_PersonaModification) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConfigModification_PersonaModification.Merge(m, src)
}
func (m *ConfigModification_PersonaModification) XXX_Size() int {
	return xxx_messageInfo_ConfigModification_PersonaModification.Size(m)
}
func (m *ConfigModification_PersonaModification) XXX_DiscardUnknown() {
	xxx_messageInfo_ConfigModification_PersonaModification.DiscardUnknown(m)
}

var xxx_messageInfo_ConfigModification_PersonaModification proto.InternalMessageInfo

func (m *ConfigModification_PersonaModification) GetAccess() []string {
	if m != nil {
		return m.Access
	}
	return nil
}

func (m *ConfigModification_PersonaModification) GetAddAccess() []string {
	if m != nil {
		return m.AddAccess
	}
	return nil
}

func (m *ConfigModification_PersonaModification) GetRemoveAccess() []string {
	if m != nil {
		return m.RemoveAccess
	}
	return nil
}

type ConfigClientRequest struct {
	Item                 *Client             `protobuf:"bytes,1,opt,name=item,proto3" json:"item,omitempty"`
	Modification         *ConfigModification `protobuf:"bytes,2,opt,name=modification,proto3" json:"modification,omitempty"`
	XXX_NoUnkeyedLiteral struct{}            `json:"-"`
	XXX_unrecognized     []byte              `json:"-"`
	XXX_sizecache        int32               `json:"-"`
}

func (m *ConfigClientRequest) Reset()         { *m = ConfigClientRequest{} }
func (m *ConfigClientRequest) String() string { return proto.CompactTextString(m) }
func (*ConfigClientRequest) ProtoMessage()    {}
func (*ConfigClientRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_e55280de4537fe26, []int{3}
}

func (m *ConfigClientRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ConfigClientRequest.Unmarshal(m, b)
}
func (m *ConfigClientRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ConfigClientRequest.Marshal(b, m, deterministic)
}
func (m *ConfigClientRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConfigClientRequest.Merge(m, src)
}
func (m *ConfigClientRequest) XXX_Size() int {
	return xxx_messageInfo_ConfigClientRequest.Size(m)
}
func (m *ConfigClientRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ConfigClientRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ConfigClientRequest proto.InternalMessageInfo

func (m *ConfigClientRequest) GetItem() *Client {
	if m != nil {
		return m.Item
	}
	return nil
}

func (m *ConfigClientRequest) GetModification() *ConfigModification {
	if m != nil {
		return m.Modification
	}
	return nil
}

type ConfigClientResponse struct {
	Client               *Client  `protobuf:"bytes,1,opt,name=client,proto3" json:"client,omitempty"`
	ClientSecret         string   `protobuf:"bytes,2,opt,name=client_secret,proto3" json:"client_secret,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ConfigClientResponse) Reset()         { *m = ConfigClientResponse{} }
func (m *ConfigClientResponse) String() string { return proto.CompactTextString(m) }
func (*ConfigClientResponse) ProtoMessage()    {}
func (*ConfigClientResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_e55280de4537fe26, []int{4}
}

func (m *ConfigClientResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ConfigClientResponse.Unmarshal(m, b)
}
func (m *ConfigClientResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ConfigClientResponse.Marshal(b, m, deterministic)
}
func (m *ConfigClientResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ConfigClientResponse.Merge(m, src)
}
func (m *ConfigClientResponse) XXX_Size() int {
	return xxx_messageInfo_ConfigClientResponse.Size(m)
}
func (m *ConfigClientResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ConfigClientResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ConfigClientResponse proto.InternalMessageInfo

func (m *ConfigClientResponse) GetClient() *Client {
	if m != nil {
		return m.Client
	}
	return nil
}

func (m *ConfigClientResponse) GetClientSecret() string {
	if m != nil {
		return m.ClientSecret
	}
	return ""
}

func init() {
	proto.RegisterType((*Client)(nil), "common.Client")
	proto.RegisterMapType((map[string]string)(nil), "common.Client.UiEntry")
	proto.RegisterType((*ClientResponse)(nil), "common.ClientResponse")
	proto.RegisterType((*ConfigModification)(nil), "common.ConfigModification")
	proto.RegisterMapType((map[string]*ConfigModification_PersonaModification)(nil), "common.ConfigModification.TestPersonasEntry")
	proto.RegisterType((*ConfigModification_PersonaModification)(nil), "common.ConfigModification.PersonaModification")
	proto.RegisterType((*ConfigClientRequest)(nil), "common.ConfigClientRequest")
	proto.RegisterType((*ConfigClientResponse)(nil), "common.ConfigClientResponse")
}

func init() { proto.RegisterFile("proto/common/v1/oauthclient.proto", fileDescriptor_e55280de4537fe26) }

var fileDescriptor_e55280de4537fe26 = []byte{
	// 539 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xb4, 0x54, 0x4d, 0x6f, 0xd3, 0x40,
	0x10, 0x55, 0x6c, 0xea, 0x26, 0x93, 0x0f, 0xc1, 0xb6, 0x2a, 0x56, 0x10, 0x22, 0x04, 0xa8, 0x72,
	0x20, 0xb6, 0x08, 0x42, 0x42, 0x1c, 0x90, 0x20, 0x20, 0xc4, 0x01, 0xa9, 0x98, 0xe6, 0xc2, 0x01,
	0x6b, 0xeb, 0x9d, 0x24, 0x2b, 0x6c, 0x6f, 0xba, 0xbb, 0x8e, 0xe4, 0x1b, 0x37, 0xfe, 0x36, 0xca,
	0xee, 0xa6, 0x4a, 0x68, 0xcb, 0x8d, 0x5b, 0xe6, 0xbd, 0x97, 0x99, 0x37, 0xfb, 0x46, 0x86, 0xc7,
	0x2b, 0x29, 0xb4, 0x88, 0x33, 0x51, 0x14, 0xa2, 0x8c, 0xd7, 0x2f, 0x62, 0x41, 0x2b, 0xbd, 0xcc,
	0x72, 0x8e, 0xa5, 0x8e, 0x0c, 0x47, 0x02, 0x4b, 0x0e, 0x7f, 0x7b, 0x10, 0x4c, 0x0d, 0x41, 0x1e,
	0x40, 0xcb, 0x4a, 0x52, 0xce, 0xc2, 0xc6, 0xa0, 0x31, 0x6a, 0x25, 0x4d, 0x0b, 0x7c, 0x66, 0xe4,
	0x18, 0x0e, 0x54, 0x26, 0x56, 0x18, 0x1e, 0x18, 0xc2, 0x16, 0xe4, 0x09, 0x74, 0x25, 0x32, 0x2e,
	0x31, 0xd3, 0x69, 0x25, 0xb9, 0x0a, 0xbd, 0x81, 0x3f, 0x6a, 0x25, 0x9d, 0x2d, 0x38, 0x93, 0x5c,
	0x91, 0x47, 0xd0, 0x5e, 0x48, 0x5a, 0xea, 0x54, 0xd7, 0x2b, 0x54, 0x61, 0x60, 0x24, 0x60, 0xa0,
	0xf3, 0x0d, 0x42, 0x9e, 0x41, 0x4f, 0xa2, 0x5a, 0x89, 0x52, 0xa1, 0xd3, 0x1c, 0x1a, 0x4d, 0x77,
	0x8b, 0x5a, 0xd9, 0x29, 0x78, 0x15, 0x0f, 0xfd, 0x81, 0x3f, 0x6a, 0x4f, 0x4e, 0x22, 0xeb, 0x3f,
	0xb2, 0xde, 0xa3, 0x19, 0xff, 0x58, 0x6a, 0x59, 0x27, 0x5e, 0xc5, 0xfb, 0xaf, 0xe0, 0xd0, 0x95,
	0xe4, 0x2e, 0xf8, 0x3f, 0xb1, 0x76, 0xcb, 0x6c, 0x7e, 0x6e, 0xf6, 0x58, 0xd3, 0xbc, 0xc2, 0xd0,
	0xb3, 0x7b, 0x98, 0xe2, 0x8d, 0xf7, 0xba, 0x31, 0xfc, 0x01, 0x3d, 0xdb, 0x2c, 0x71, 0x53, 0xc9,
	0x29, 0x04, 0x76, 0x7f, 0xd3, 0xa0, 0x3d, 0xe9, 0xed, 0x0f, 0x4d, 0x1c, 0x4b, 0x9e, 0x42, 0xd7,
	0x3d, 0x9c, 0xc2, 0x4c, 0xa2, 0x76, 0xbd, 0xf7, 0xc1, 0xe1, 0x2f, 0x1f, 0xc8, 0x54, 0x94, 0x73,
	0xbe, 0xf8, 0x22, 0x18, 0x9f, 0xf3, 0x8c, 0x6a, 0x2e, 0x4a, 0xd2, 0x87, 0xa6, 0xc4, 0x35, 0x57,
	0x5c, 0x94, 0x66, 0x8c, 0x9f, 0x5c, 0xd5, 0xe4, 0x2b, 0x74, 0x35, 0x2a, 0x9d, 0xae, 0x50, 0x2a,
	0x51, 0x52, 0xfb, 0xbc, 0xed, 0xc9, 0xf3, 0x2b, 0x1f, 0xd7, 0xda, 0x45, 0xe7, 0xa8, 0xf4, 0x99,
	0x93, 0xdb, 0x27, 0xe9, 0xe8, 0x1d, 0x88, 0xdc, 0x87, 0x43, 0x26, 0xeb, 0x54, 0x56, 0x65, 0xe8,
	0x0f, 0x1a, 0xa3, 0x66, 0x12, 0x30, 0x59, 0x27, 0x55, 0xd9, 0xbf, 0x84, 0x23, 0x27, 0xda, 0xb3,
	0x77, 0x02, 0x01, 0xcd, 0x32, 0x54, 0x2a, 0x6c, 0x98, 0x4c, 0x5c, 0x45, 0x1e, 0x02, 0x50, 0xc6,
	0x52, 0xc7, 0xd9, 0xd8, 0x5b, 0x94, 0xb1, 0x77, 0x96, 0x36, 0x87, 0x51, 0x88, 0x35, 0x6e, 0x15,
	0xfe, 0xf6, 0x30, 0x36, 0xa0, 0x15, 0xf5, 0x05, 0xdc, 0xbb, 0x66, 0xf7, 0x86, 0xc8, 0x3e, 0xec,
	0x46, 0xd6, 0x9e, 0x44, 0xff, 0xd8, 0xfe, 0x86, 0x0d, 0x76, 0x23, 0xae, 0xe1, 0xc8, 0xfe, 0x69,
	0x1b, 0xf4, 0x65, 0x85, 0x4a, 0x93, 0x21, 0xdc, 0xe1, 0x1a, 0x8b, 0x5b, 0x52, 0x36, 0x1c, 0x79,
	0x0b, 0x9d, 0x62, 0xa7, 0xab, 0xf3, 0xd2, 0xbf, 0xdd, 0x4b, 0xb2, 0xa7, 0x1f, 0x32, 0x38, 0xde,
	0x1f, 0xfd, 0x3f, 0x6e, 0xec, 0xfd, 0xec, 0xfb, 0xb7, 0x05, 0xd7, 0xcb, 0xea, 0x62, 0xd3, 0x25,
	0xfe, 0x24, 0xc4, 0x22, 0xc7, 0x69, 0x2e, 0x2a, 0x76, 0x96, 0x53, 0x3d, 0x17, 0xb2, 0x88, 0x97,
	0x48, 0x73, 0xbd, 0xcc, 0xa8, 0xc4, 0xf1, 0x1c, 0x19, 0x4a, 0xaa, 0x91, 0x8d, 0x6d, 0x46, 0x63,
	0x85, 0x72, 0xcd, 0x33, 0x54, 0xf1, 0x5f, 0x9f, 0x8f, 0x8b, 0xc0, 0x00, 0x2f, 0xff, 0x04, 0x00,
	0x00, 0xff, 0xff, 0x8d, 0xf3, 0xcf, 0x1b, 0x58, 0x04, 0x00, 0x00,
}
