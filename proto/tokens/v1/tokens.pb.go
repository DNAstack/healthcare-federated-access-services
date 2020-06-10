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
// source: proto/tokens/v1/tokens.proto

// Package v1 tokens provides protocol buffer versions of tokens API.
package v1

import (
	context "context"
	fmt "fmt"
	math "math"

	proto "github.com/golang/protobuf/proto"
	empty "github.com/golang/protobuf/ptypes/empty"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
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

type Token struct {
	// Name of the token.
	// Format: `users/{user_id}/tokens/{token_id}`.
	Name      string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	Issuer    string `protobuf:"bytes,2,opt,name=issuer,json=iss,proto3" json:"issuer,omitempty"`
	Subject   string `protobuf:"bytes,3,opt,name=subject,json=sub,proto3" json:"subject,omitempty"`
	Audience  string `protobuf:"bytes,4,opt,name=audience,json=aud,proto3" json:"audience,omitempty"`
	ExpiresAt int64  `protobuf:"varint,5,opt,name=expires_at,json=exp,proto3" json:"expires_at,omitempty"`
	// int64 not_before = 6 [json_name = "nbf"];
	IssuedAt int64   `protobuf:"varint,7,opt,name=issued_at,json=iat,proto3" json:"issued_at,omitempty"`
	Scope    string  `protobuf:"bytes,9,opt,name=scope,proto3" json:"scope,omitempty"`
	Client   *Client `protobuf:"bytes,10,opt,name=client,proto3" json:"client,omitempty"`
	// Target of the token.
	// For DAM, it is URL containing the resource & role & view.
	// For IC, it is URL of the client requesting.
	Target string `protobuf:"bytes,11,opt,name=target,proto3" json:"target,omitempty"`
	// Metadata contains additional metadata.
	// For DAM:
	//   resource: description of the resource.
	//   role: description of the role.
	//   view: description of the view.
	// For IC:
	//   client_id:
	//   client_desc: description of the client.
	Metadata map[string]string `protobuf:"bytes,12,rep,name=metadata,proto3" json:"metadata,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// Type of the token, used to distinguish tokens from different platforms.
	Type string `protobuf:"bytes,13,opt,name=type,proto3" json:"type,omitempty"`
	// Resources of this token used to access.
	Resources            []string `protobuf:"bytes,14,rep,name=resources,proto3" json:"resources,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Token) Reset()         { *m = Token{} }
func (m *Token) String() string { return proto.CompactTextString(m) }
func (*Token) ProtoMessage()    {}
func (*Token) Descriptor() ([]byte, []int) {
	return fileDescriptor_522bedb22d9068f2, []int{0}
}

func (m *Token) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Token.Unmarshal(m, b)
}
func (m *Token) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Token.Marshal(b, m, deterministic)
}
func (m *Token) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Token.Merge(m, src)
}
func (m *Token) XXX_Size() int {
	return xxx_messageInfo_Token.Size(m)
}
func (m *Token) XXX_DiscardUnknown() {
	xxx_messageInfo_Token.DiscardUnknown(m)
}

var xxx_messageInfo_Token proto.InternalMessageInfo

func (m *Token) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Token) GetIssuer() string {
	if m != nil {
		return m.Issuer
	}
	return ""
}

func (m *Token) GetSubject() string {
	if m != nil {
		return m.Subject
	}
	return ""
}

func (m *Token) GetAudience() string {
	if m != nil {
		return m.Audience
	}
	return ""
}

func (m *Token) GetExpiresAt() int64 {
	if m != nil {
		return m.ExpiresAt
	}
	return 0
}

func (m *Token) GetIssuedAt() int64 {
	if m != nil {
		return m.IssuedAt
	}
	return 0
}

func (m *Token) GetScope() string {
	if m != nil {
		return m.Scope
	}
	return ""
}

func (m *Token) GetClient() *Client {
	if m != nil {
		return m.Client
	}
	return nil
}

func (m *Token) GetTarget() string {
	if m != nil {
		return m.Target
	}
	return ""
}

func (m *Token) GetMetadata() map[string]string {
	if m != nil {
		return m.Metadata
	}
	return nil
}

func (m *Token) GetType() string {
	if m != nil {
		return m.Type
	}
	return ""
}

func (m *Token) GetResources() []string {
	if m != nil {
		return m.Resources
	}
	return nil
}

type Client struct {
	Id          string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name        string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	Description string `protobuf:"bytes,3,opt,name=description,proto3" json:"description,omitempty"`
	// flexible struct for ui display.
	Ui                   map[string]string `protobuf:"bytes,4,rep,name=ui,proto3" json:"ui,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Client) Reset()         { *m = Client{} }
func (m *Client) String() string { return proto.CompactTextString(m) }
func (*Client) ProtoMessage()    {}
func (*Client) Descriptor() ([]byte, []int) {
	return fileDescriptor_522bedb22d9068f2, []int{1}
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

func (m *Client) GetId() string {
	if m != nil {
		return m.Id
	}
	return ""
}

func (m *Client) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

func (m *Client) GetDescription() string {
	if m != nil {
		return m.Description
	}
	return ""
}

func (m *Client) GetUi() map[string]string {
	if m != nil {
		return m.Ui
	}
	return nil
}

type GetTokenRequest struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetTokenRequest) Reset()         { *m = GetTokenRequest{} }
func (m *GetTokenRequest) String() string { return proto.CompactTextString(m) }
func (*GetTokenRequest) ProtoMessage()    {}
func (*GetTokenRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_522bedb22d9068f2, []int{2}
}

func (m *GetTokenRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetTokenRequest.Unmarshal(m, b)
}
func (m *GetTokenRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetTokenRequest.Marshal(b, m, deterministic)
}
func (m *GetTokenRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetTokenRequest.Merge(m, src)
}
func (m *GetTokenRequest) XXX_Size() int {
	return xxx_messageInfo_GetTokenRequest.Size(m)
}
func (m *GetTokenRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetTokenRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetTokenRequest proto.InternalMessageInfo

func (m *GetTokenRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type DeleteTokenRequest struct {
	Name                 string   `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DeleteTokenRequest) Reset()         { *m = DeleteTokenRequest{} }
func (m *DeleteTokenRequest) String() string { return proto.CompactTextString(m) }
func (*DeleteTokenRequest) ProtoMessage()    {}
func (*DeleteTokenRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_522bedb22d9068f2, []int{3}
}

func (m *DeleteTokenRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DeleteTokenRequest.Unmarshal(m, b)
}
func (m *DeleteTokenRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DeleteTokenRequest.Marshal(b, m, deterministic)
}
func (m *DeleteTokenRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DeleteTokenRequest.Merge(m, src)
}
func (m *DeleteTokenRequest) XXX_Size() int {
	return xxx_messageInfo_DeleteTokenRequest.Size(m)
}
func (m *DeleteTokenRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_DeleteTokenRequest.DiscardUnknown(m)
}

var xxx_messageInfo_DeleteTokenRequest proto.InternalMessageInfo

func (m *DeleteTokenRequest) GetName() string {
	if m != nil {
		return m.Name
	}
	return ""
}

type ListTokensRequest struct {
	Parent               string   `protobuf:"bytes,1,opt,name=parent,proto3" json:"parent,omitempty"`
	PageSize             int32    `protobuf:"varint,2,opt,name=page_size,json=pageSize,proto3" json:"page_size,omitempty"`
	PageToken            string   `protobuf:"bytes,3,opt,name=page_token,json=pageToken,proto3" json:"page_token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ListTokensRequest) Reset()         { *m = ListTokensRequest{} }
func (m *ListTokensRequest) String() string { return proto.CompactTextString(m) }
func (*ListTokensRequest) ProtoMessage()    {}
func (*ListTokensRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_522bedb22d9068f2, []int{4}
}

func (m *ListTokensRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListTokensRequest.Unmarshal(m, b)
}
func (m *ListTokensRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListTokensRequest.Marshal(b, m, deterministic)
}
func (m *ListTokensRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListTokensRequest.Merge(m, src)
}
func (m *ListTokensRequest) XXX_Size() int {
	return xxx_messageInfo_ListTokensRequest.Size(m)
}
func (m *ListTokensRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_ListTokensRequest.DiscardUnknown(m)
}

var xxx_messageInfo_ListTokensRequest proto.InternalMessageInfo

func (m *ListTokensRequest) GetParent() string {
	if m != nil {
		return m.Parent
	}
	return ""
}

func (m *ListTokensRequest) GetPageSize() int32 {
	if m != nil {
		return m.PageSize
	}
	return 0
}

func (m *ListTokensRequest) GetPageToken() string {
	if m != nil {
		return m.PageToken
	}
	return ""
}

type ListTokensResponse struct {
	Tokens               []*Token `protobuf:"bytes,1,rep,name=tokens,proto3" json:"tokens,omitempty"`
	NextPageToken        string   `protobuf:"bytes,2,opt,name=next_page_token,json=nextPageToken,proto3" json:"next_page_token,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *ListTokensResponse) Reset()         { *m = ListTokensResponse{} }
func (m *ListTokensResponse) String() string { return proto.CompactTextString(m) }
func (*ListTokensResponse) ProtoMessage()    {}
func (*ListTokensResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_522bedb22d9068f2, []int{5}
}

func (m *ListTokensResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_ListTokensResponse.Unmarshal(m, b)
}
func (m *ListTokensResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_ListTokensResponse.Marshal(b, m, deterministic)
}
func (m *ListTokensResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_ListTokensResponse.Merge(m, src)
}
func (m *ListTokensResponse) XXX_Size() int {
	return xxx_messageInfo_ListTokensResponse.Size(m)
}
func (m *ListTokensResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_ListTokensResponse.DiscardUnknown(m)
}

var xxx_messageInfo_ListTokensResponse proto.InternalMessageInfo

func (m *ListTokensResponse) GetTokens() []*Token {
	if m != nil {
		return m.Tokens
	}
	return nil
}

func (m *ListTokensResponse) GetNextPageToken() string {
	if m != nil {
		return m.NextPageToken
	}
	return ""
}

func init() {
	proto.RegisterType((*Token)(nil), "tokens.v1.Token")
	proto.RegisterMapType((map[string]string)(nil), "tokens.v1.Token.MetadataEntry")
	proto.RegisterType((*Client)(nil), "tokens.v1.Client")
	proto.RegisterMapType((map[string]string)(nil), "tokens.v1.Client.UiEntry")
	proto.RegisterType((*GetTokenRequest)(nil), "tokens.v1.GetTokenRequest")
	proto.RegisterType((*DeleteTokenRequest)(nil), "tokens.v1.DeleteTokenRequest")
	proto.RegisterType((*ListTokensRequest)(nil), "tokens.v1.ListTokensRequest")
	proto.RegisterType((*ListTokensResponse)(nil), "tokens.v1.ListTokensResponse")
}

func init() {
	proto.RegisterFile("proto/tokens/v1/tokens.proto", fileDescriptor_522bedb22d9068f2)
}

var fileDescriptor_522bedb22d9068f2 = []byte{
	// 641 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x94, 0xcf, 0x4e, 0xdb, 0x4a,
	0x14, 0xc6, 0x71, 0x4c, 0x0c, 0x3e, 0xb9, 0xfc, 0x3b, 0x97, 0x9b, 0xeb, 0x6b, 0xe0, 0x2a, 0xb2,
	0xd4, 0xca, 0x2c, 0xb0, 0x05, 0x55, 0xa5, 0x8a, 0xee, 0x4a, 0x29, 0x8b, 0xb6, 0x12, 0x32, 0x65,
	0xd3, 0x0d, 0x9a, 0xd8, 0x27, 0x61, 0x8a, 0x63, 0xbb, 0x9e, 0x71, 0x44, 0x78, 0x8c, 0x3e, 0x49,
	0x5f, 0xa7, 0x6f, 0x53, 0x79, 0xc6, 0x01, 0x97, 0xb4, 0xaa, 0xba, 0x9b, 0xf3, 0xcd, 0x97, 0xef,
	0xf8, 0xfc, 0x66, 0x26, 0xb0, 0x5b, 0x94, 0xb9, 0xcc, 0x43, 0x99, 0xdf, 0x50, 0x26, 0xc2, 0xe9,
	0x61, 0xb3, 0x0a, 0x94, 0x8c, 0x76, 0x53, 0x4d, 0x0f, 0xdd, 0x9d, 0x71, 0x9e, 0x8f, 0x53, 0x0a,
	0xd5, 0xc6, 0xb0, 0x1a, 0x85, 0x34, 0x29, 0xe4, 0x4c, 0xfb, 0xbc, 0x2f, 0x26, 0x74, 0x3f, 0xd4,
	0x56, 0x44, 0x58, 0xce, 0xd8, 0x84, 0x1c, 0x63, 0x60, 0xf8, 0x76, 0xa4, 0xd6, 0xf8, 0x37, 0x58,
	0x5c, 0x88, 0x8a, 0x4a, 0xa7, 0xa3, 0x54, 0x93, 0x0b, 0x81, 0xdb, 0xb0, 0x22, 0xaa, 0xe1, 0x27,
	0x8a, 0xa5, 0x63, 0x6a, 0x55, 0x54, 0x43, 0xfc, 0x07, 0x56, 0x59, 0x95, 0x70, 0xca, 0x62, 0x72,
	0x96, 0xb5, 0xcc, 0xaa, 0x04, 0xff, 0x05, 0xa0, 0xdb, 0x82, 0x97, 0x24, 0xae, 0x98, 0x74, 0xba,
	0x03, 0xc3, 0x37, 0x23, 0x93, 0x6e, 0x0b, 0xec, 0x83, 0xad, 0xa2, 0x93, 0x5a, 0x5f, 0xd1, 0x3a,
	0x67, 0x12, 0xb7, 0xa1, 0x2b, 0xe2, 0xbc, 0x20, 0xc7, 0x56, 0x21, 0xba, 0xc0, 0x7d, 0xb0, 0xe2,
	0x94, 0x53, 0x26, 0x1d, 0x18, 0x18, 0x7e, 0xef, 0x68, 0x2b, 0xb8, 0x9f, 0x2f, 0x38, 0x51, 0x1b,
	0x51, 0x63, 0xc0, 0x3e, 0x58, 0x92, 0x95, 0x63, 0x92, 0x4e, 0x4f, 0x25, 0x34, 0x15, 0x1e, 0xc3,
	0xea, 0x84, 0x24, 0x4b, 0x98, 0x64, 0xce, 0x5f, 0x03, 0xd3, 0xef, 0x1d, 0xfd, 0xdf, 0x0a, 0x51,
	0x0c, 0x82, 0xf7, 0x8d, 0xe1, 0x34, 0x93, 0xe5, 0x2c, 0xba, 0xf7, 0xd7, 0x6c, 0xe4, 0xac, 0x20,
	0x67, 0x4d, 0xb3, 0xa9, 0xd7, 0xb8, 0x0b, 0x76, 0x49, 0x22, 0xaf, 0xca, 0x98, 0x84, 0xb3, 0x3e,
	0x30, 0x7d, 0x3b, 0x7a, 0x10, 0xdc, 0x97, 0xb0, 0xf6, 0x43, 0x18, 0x6e, 0x82, 0x79, 0x43, 0xb3,
	0x86, 0x6e, 0xbd, 0xac, 0x27, 0x9d, 0xb2, 0xb4, 0xa2, 0x86, 0xad, 0x2e, 0x8e, 0x3b, 0x2f, 0x0c,
	0xef, 0xab, 0x01, 0x96, 0x9e, 0x0a, 0xd7, 0xa1, 0xc3, 0x93, 0xe6, 0x57, 0x1d, 0x9e, 0xdc, 0x9f,
	0x52, 0xa7, 0x75, 0x4a, 0x03, 0xe8, 0x25, 0x24, 0xe2, 0x92, 0x17, 0x92, 0xe7, 0x59, 0x73, 0x28,
	0x6d, 0x09, 0xf7, 0xa1, 0x53, 0x71, 0x67, 0x59, 0x4d, 0xfd, 0xdf, 0x02, 0xba, 0xe0, 0x92, 0xeb,
	0x81, 0x3b, 0x15, 0x77, 0x9f, 0xc3, 0x4a, 0x53, 0xfe, 0xd1, 0x27, 0x3f, 0x81, 0x8d, 0x33, 0x92,
	0x8a, 0x62, 0x44, 0x9f, 0x2b, 0x12, 0xf2, 0x67, 0x17, 0xca, 0xf3, 0x01, 0x5f, 0x53, 0x4a, 0x92,
	0x7e, 0xeb, 0x1c, 0xc3, 0xd6, 0x3b, 0x2e, 0x74, 0xa2, 0x98, 0x1b, 0xfb, 0x60, 0x15, 0xac, 0xac,
	0xaf, 0x81, 0xb6, 0x36, 0x15, 0xee, 0x80, 0x5d, 0xb0, 0x31, 0x5d, 0x09, 0x7e, 0xa7, 0xbf, 0xad,
	0x1b, 0xad, 0xd6, 0xc2, 0x05, 0xbf, 0x23, 0xdc, 0x03, 0x50, 0x9b, 0x6a, 0xec, 0x86, 0x8e, 0xb2,
	0xab, 0x6c, 0x6f, 0x04, 0xd8, 0x6e, 0x24, 0x8a, 0x3c, 0x13, 0x84, 0x3e, 0x58, 0x1a, 0x93, 0x63,
	0x28, 0x6a, 0x9b, 0x8f, 0xef, 0x4a, 0xd4, 0xec, 0xe3, 0x53, 0xd8, 0xc8, 0xe8, 0x56, 0x5e, 0xb5,
	0x7a, 0x68, 0x3a, 0x6b, 0xb5, 0x7c, 0x3e, 0xef, 0x73, 0xf4, 0xcd, 0x00, 0x4b, 0x37, 0xa9, 0xaf,
	0xe2, 0x1c, 0x16, 0xba, 0xad, 0xe0, 0x47, 0x04, 0xdd, 0x85, 0xa6, 0xde, 0x12, 0xbe, 0x81, 0x5e,
	0x8b, 0x20, 0xee, 0xb5, 0x2c, 0x8b, 0x64, 0xdd, 0x7e, 0xa0, 0x1f, 0x7f, 0x30, 0x7f, 0xfc, 0xc1,
	0x69, 0xfd, 0xf8, 0xbd, 0x25, 0x7c, 0x0b, 0xf0, 0x30, 0x36, 0xee, 0xb6, 0x62, 0x16, 0xb0, 0xbb,
	0x7b, 0xbf, 0xd8, 0xd5, 0xac, 0xbc, 0xa5, 0x57, 0x97, 0x1f, 0x2f, 0xc6, 0x5c, 0x5e, 0x57, 0xc3,
	0x20, 0xce, 0x27, 0xe1, 0x99, 0x6a, 0x79, 0x92, 0xe6, 0x55, 0x72, 0x9e, 0x32, 0x39, 0xca, 0xcb,
	0x49, 0x78, 0x4d, 0x2c, 0x95, 0xd7, 0x31, 0x2b, 0xe9, 0x60, 0x44, 0x09, 0x95, 0x4c, 0x52, 0x72,
	0xc0, 0xe2, 0x98, 0x84, 0x38, 0x10, 0x54, 0x4e, 0x79, 0x4c, 0x22, 0x7c, 0xf4, 0x8f, 0x36, 0xb4,
	0x94, 0xf0, 0xec, 0x7b, 0x00, 0x00, 0x00, 0xff, 0xff, 0xdc, 0x56, 0x28, 0x27, 0xeb, 0x04, 0x00,
	0x00,
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// TokensClient is the client API for Tokens service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type TokensClient interface {
	// Gets the information for the specified token.
	GetToken(ctx context.Context, in *GetTokenRequest, opts ...grpc.CallOption) (*Token, error)
	// Deletes the specified token.
	DeleteToken(ctx context.Context, in *DeleteTokenRequest, opts ...grpc.CallOption) (*empty.Empty, error)
	// Lists the tokens.
	ListTokens(ctx context.Context, in *ListTokensRequest, opts ...grpc.CallOption) (*ListTokensResponse, error)
}

type tokensClient struct {
	cc grpc.ClientConnInterface
}

func NewTokensClient(cc grpc.ClientConnInterface) TokensClient {
	return &tokensClient{cc}
}

func (c *tokensClient) GetToken(ctx context.Context, in *GetTokenRequest, opts ...grpc.CallOption) (*Token, error) {
	out := new(Token)
	err := c.cc.Invoke(ctx, "/tokens.v1.Tokens/GetToken", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tokensClient) DeleteToken(ctx context.Context, in *DeleteTokenRequest, opts ...grpc.CallOption) (*empty.Empty, error) {
	out := new(empty.Empty)
	err := c.cc.Invoke(ctx, "/tokens.v1.Tokens/DeleteToken", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *tokensClient) ListTokens(ctx context.Context, in *ListTokensRequest, opts ...grpc.CallOption) (*ListTokensResponse, error) {
	out := new(ListTokensResponse)
	err := c.cc.Invoke(ctx, "/tokens.v1.Tokens/ListTokens", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// TokensServer is the server API for Tokens service.
type TokensServer interface {
	// Gets the information for the specified token.
	GetToken(context.Context, *GetTokenRequest) (*Token, error)
	// Deletes the specified token.
	DeleteToken(context.Context, *DeleteTokenRequest) (*empty.Empty, error)
	// Lists the tokens.
	ListTokens(context.Context, *ListTokensRequest) (*ListTokensResponse, error)
}

// UnimplementedTokensServer can be embedded to have forward compatible implementations.
type UnimplementedTokensServer struct {
}

func (*UnimplementedTokensServer) GetToken(ctx context.Context, req *GetTokenRequest) (*Token, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetToken not implemented")
}
func (*UnimplementedTokensServer) DeleteToken(ctx context.Context, req *DeleteTokenRequest) (*empty.Empty, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteToken not implemented")
}
func (*UnimplementedTokensServer) ListTokens(ctx context.Context, req *ListTokensRequest) (*ListTokensResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListTokens not implemented")
}

func RegisterTokensServer(s *grpc.Server, srv TokensServer) {
	s.RegisterService(&_Tokens_serviceDesc, srv)
}

func _Tokens_GetToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServer).GetToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/tokens.v1.Tokens/GetToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServer).GetToken(ctx, req.(*GetTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Tokens_DeleteToken_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteTokenRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServer).DeleteToken(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/tokens.v1.Tokens/DeleteToken",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServer).DeleteToken(ctx, req.(*DeleteTokenRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _Tokens_ListTokens_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListTokensRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(TokensServer).ListTokens(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/tokens.v1.Tokens/ListTokens",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(TokensServer).ListTokens(ctx, req.(*ListTokensRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Tokens_serviceDesc = grpc.ServiceDesc{
	ServiceName: "tokens.v1.Tokens",
	HandlerType: (*TokensServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetToken",
			Handler:    _Tokens_GetToken_Handler,
		},
		{
			MethodName: "DeleteToken",
			Handler:    _Tokens_DeleteToken_Handler,
		},
		{
			MethodName: "ListTokens",
			Handler:    _Tokens_ListTokens_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "proto/tokens/v1/tokens.proto",
}
