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

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: builder/builder.proto

// Package builder provides protocol buffer versions of some of the top-level
// types from the ga4gh package, allowing builder.Build the ability to build
// 'real' versions of these messages from their protocol buffer counterparts.

package builder

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

type Validator struct {
	// Types that are valid to be assigned to Validator:
	//	*Validator_And_
	//	*Validator_Or_
	//	*Validator_Simple_
	//	*Validator_Constant_
	Validator            isValidator_Validator `protobuf_oneof:"validator"`
	XXX_NoUnkeyedLiteral struct{}              `json:"-"`
	XXX_unrecognized     []byte                `json:"-"`
	XXX_sizecache        int32                 `json:"-"`
}

func (m *Validator) Reset()         { *m = Validator{} }
func (m *Validator) String() string { return proto.CompactTextString(m) }
func (*Validator) ProtoMessage()    {}
func (*Validator) Descriptor() ([]byte, []int) {
	return fileDescriptor_3ba3046719757e1e, []int{0}
}

func (m *Validator) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Validator.Unmarshal(m, b)
}
func (m *Validator) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Validator.Marshal(b, m, deterministic)
}
func (m *Validator) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Validator.Merge(m, src)
}
func (m *Validator) XXX_Size() int {
	return xxx_messageInfo_Validator.Size(m)
}
func (m *Validator) XXX_DiscardUnknown() {
	xxx_messageInfo_Validator.DiscardUnknown(m)
}

var xxx_messageInfo_Validator proto.InternalMessageInfo

type isValidator_Validator interface {
	isValidator_Validator()
}

type Validator_And_ struct {
	And *Validator_And `protobuf:"bytes,1,opt,name=and,proto3,oneof"`
}

type Validator_Or_ struct {
	Or *Validator_Or `protobuf:"bytes,2,opt,name=or,proto3,oneof"`
}

type Validator_Simple_ struct {
	Simple *Validator_Simple `protobuf:"bytes,3,opt,name=simple,proto3,oneof"`
}

type Validator_Constant_ struct {
	Constant *Validator_Constant `protobuf:"bytes,4,opt,name=constant,proto3,oneof"`
}

func (*Validator_And_) isValidator_Validator() {}

func (*Validator_Or_) isValidator_Validator() {}

func (*Validator_Simple_) isValidator_Validator() {}

func (*Validator_Constant_) isValidator_Validator() {}

func (m *Validator) GetValidator() isValidator_Validator {
	if m != nil {
		return m.Validator
	}
	return nil
}

func (m *Validator) GetAnd() *Validator_And {
	if x, ok := m.GetValidator().(*Validator_And_); ok {
		return x.And
	}
	return nil
}

func (m *Validator) GetOr() *Validator_Or {
	if x, ok := m.GetValidator().(*Validator_Or_); ok {
		return x.Or
	}
	return nil
}

func (m *Validator) GetSimple() *Validator_Simple {
	if x, ok := m.GetValidator().(*Validator_Simple_); ok {
		return x.Simple
	}
	return nil
}

func (m *Validator) GetConstant() *Validator_Constant {
	if x, ok := m.GetValidator().(*Validator_Constant_); ok {
		return x.Constant
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*Validator) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*Validator_And_)(nil),
		(*Validator_Or_)(nil),
		(*Validator_Simple_)(nil),
		(*Validator_Constant_)(nil),
	}
}

type Validator_And struct {
	Validators           []*Validator `protobuf:"bytes,1,rep,name=validators,proto3" json:"validators,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *Validator_And) Reset()         { *m = Validator_And{} }
func (m *Validator_And) String() string { return proto.CompactTextString(m) }
func (*Validator_And) ProtoMessage()    {}
func (*Validator_And) Descriptor() ([]byte, []int) {
	return fileDescriptor_3ba3046719757e1e, []int{0, 0}
}

func (m *Validator_And) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Validator_And.Unmarshal(m, b)
}
func (m *Validator_And) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Validator_And.Marshal(b, m, deterministic)
}
func (m *Validator_And) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Validator_And.Merge(m, src)
}
func (m *Validator_And) XXX_Size() int {
	return xxx_messageInfo_Validator_And.Size(m)
}
func (m *Validator_And) XXX_DiscardUnknown() {
	xxx_messageInfo_Validator_And.DiscardUnknown(m)
}

var xxx_messageInfo_Validator_And proto.InternalMessageInfo

func (m *Validator_And) GetValidators() []*Validator {
	if m != nil {
		return m.Validators
	}
	return nil
}

type Validator_Or struct {
	Validators           []*Validator `protobuf:"bytes,2,rep,name=validators,proto3" json:"validators,omitempty"`
	XXX_NoUnkeyedLiteral struct{}     `json:"-"`
	XXX_unrecognized     []byte       `json:"-"`
	XXX_sizecache        int32        `json:"-"`
}

func (m *Validator_Or) Reset()         { *m = Validator_Or{} }
func (m *Validator_Or) String() string { return proto.CompactTextString(m) }
func (*Validator_Or) ProtoMessage()    {}
func (*Validator_Or) Descriptor() ([]byte, []int) {
	return fileDescriptor_3ba3046719757e1e, []int{0, 1}
}

func (m *Validator_Or) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Validator_Or.Unmarshal(m, b)
}
func (m *Validator_Or) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Validator_Or.Marshal(b, m, deterministic)
}
func (m *Validator_Or) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Validator_Or.Merge(m, src)
}
func (m *Validator_Or) XXX_Size() int {
	return xxx_messageInfo_Validator_Or.Size(m)
}
func (m *Validator_Or) XXX_DiscardUnknown() {
	xxx_messageInfo_Validator_Or.DiscardUnknown(m)
}

var xxx_messageInfo_Validator_Or proto.InternalMessageInfo

func (m *Validator_Or) GetValidators() []*Validator {
	if m != nil {
		return m.Validators
	}
	return nil
}

type Validator_Simple struct {
	Claims               map[string]string `protobuf:"bytes,1,rep,name=claims,proto3" json:"claims,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	XXX_NoUnkeyedLiteral struct{}          `json:"-"`
	XXX_unrecognized     []byte            `json:"-"`
	XXX_sizecache        int32             `json:"-"`
}

func (m *Validator_Simple) Reset()         { *m = Validator_Simple{} }
func (m *Validator_Simple) String() string { return proto.CompactTextString(m) }
func (*Validator_Simple) ProtoMessage()    {}
func (*Validator_Simple) Descriptor() ([]byte, []int) {
	return fileDescriptor_3ba3046719757e1e, []int{0, 2}
}

func (m *Validator_Simple) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Validator_Simple.Unmarshal(m, b)
}
func (m *Validator_Simple) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Validator_Simple.Marshal(b, m, deterministic)
}
func (m *Validator_Simple) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Validator_Simple.Merge(m, src)
}
func (m *Validator_Simple) XXX_Size() int {
	return xxx_messageInfo_Validator_Simple.Size(m)
}
func (m *Validator_Simple) XXX_DiscardUnknown() {
	xxx_messageInfo_Validator_Simple.DiscardUnknown(m)
}

var xxx_messageInfo_Validator_Simple proto.InternalMessageInfo

func (m *Validator_Simple) GetClaims() map[string]string {
	if m != nil {
		return m.Claims
	}
	return nil
}

type Validator_Constant struct {
	Value                bool     `protobuf:"varint,1,opt,name=value,proto3" json:"value,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *Validator_Constant) Reset()         { *m = Validator_Constant{} }
func (m *Validator_Constant) String() string { return proto.CompactTextString(m) }
func (*Validator_Constant) ProtoMessage()    {}
func (*Validator_Constant) Descriptor() ([]byte, []int) {
	return fileDescriptor_3ba3046719757e1e, []int{0, 3}
}

func (m *Validator_Constant) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_Validator_Constant.Unmarshal(m, b)
}
func (m *Validator_Constant) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_Validator_Constant.Marshal(b, m, deterministic)
}
func (m *Validator_Constant) XXX_Merge(src proto.Message) {
	xxx_messageInfo_Validator_Constant.Merge(m, src)
}
func (m *Validator_Constant) XXX_Size() int {
	return xxx_messageInfo_Validator_Constant.Size(m)
}
func (m *Validator_Constant) XXX_DiscardUnknown() {
	xxx_messageInfo_Validator_Constant.DiscardUnknown(m)
}

var xxx_messageInfo_Validator_Constant proto.InternalMessageInfo

func (m *Validator_Constant) GetValue() bool {
	if m != nil {
		return m.Value
	}
	return false
}

func init() {
	proto.RegisterType((*Validator)(nil), "builder.Validator")
	proto.RegisterType((*Validator_And)(nil), "builder.Validator.And")
	proto.RegisterType((*Validator_Or)(nil), "builder.Validator.Or")
	proto.RegisterType((*Validator_Simple)(nil), "builder.Validator.Simple")
	proto.RegisterMapType((map[string]string)(nil), "builder.Validator.Simple.ClaimsEntry")
	proto.RegisterType((*Validator_Constant)(nil), "builder.Validator.Constant")
}

func init() { proto.RegisterFile("builder/builder.proto", fileDescriptor_3ba3046719757e1e) }

var fileDescriptor_3ba3046719757e1e = []byte{
	// 354 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0xd2, 0xcf, 0x6b, 0xe2, 0x40,
	0x14, 0x07, 0xf0, 0xfc, 0xd8, 0xcd, 0x9a, 0x97, 0xcb, 0x32, 0xac, 0x4b, 0x9a, 0x5e, 0xa4, 0x50,
	0x2a, 0x05, 0x23, 0xe8, 0x45, 0x0b, 0x3d, 0xa8, 0x94, 0x06, 0x4a, 0xb1, 0x4c, 0xa1, 0x87, 0xde,
	0xc6, 0xcc, 0xa8, 0xa1, 0x93, 0x8c, 0xcc, 0x4c, 0x04, 0xaf, 0xfd, 0xaf, 0x7b, 0x2b, 0x8e, 0x89,
	0x95, 0xd6, 0x42, 0x4f, 0xc9, 0x0b, 0x9f, 0x6f, 0x92, 0xf7, 0xe6, 0x41, 0x73, 0x56, 0x66, 0x9c,
	0x32, 0xd9, 0xad, 0xae, 0xf1, 0x4a, 0x0a, 0x2d, 0xd0, 0x9f, 0xaa, 0x3c, 0x7b, 0x73, 0xc1, 0x7f,
	0x22, 0x3c, 0xa3, 0x44, 0x0b, 0x89, 0x2e, 0xc1, 0x25, 0x05, 0x0d, 0xed, 0x96, 0xdd, 0x0e, 0x7a,
	0xff, 0xe3, 0x3a, 0xb3, 0x07, 0xf1, 0xa8, 0xa0, 0x89, 0x85, 0xb7, 0x08, 0x5d, 0x80, 0x23, 0x64,
	0xe8, 0x18, 0xda, 0x3c, 0x42, 0xa7, 0x32, 0xb1, 0xb0, 0x23, 0x24, 0xea, 0x83, 0xa7, 0xb2, 0x7c,
	0xc5, 0x59, 0xe8, 0x1a, 0x7c, 0x72, 0x04, 0x3f, 0x1a, 0x90, 0x58, 0xb8, 0xa2, 0x68, 0x08, 0x8d,
	0x54, 0x14, 0x4a, 0x93, 0x42, 0x87, 0xbf, 0x4c, 0xec, 0xf4, 0x48, 0x6c, 0x52, 0x91, 0xc4, 0xc2,
	0x7b, 0x1e, 0x0d, 0xc1, 0x1d, 0x15, 0x14, 0xf5, 0x00, 0xd6, 0x35, 0x54, 0xa1, 0xdd, 0x72, 0xdb,
	0x41, 0x0f, 0x7d, 0x7d, 0x07, 0x3e, 0x50, 0xd1, 0x00, 0x9c, 0xa9, 0xfc, 0x94, 0x74, 0x7e, 0x94,
	0x7c, 0xb5, 0xc1, 0xdb, 0x35, 0x81, 0xae, 0xc1, 0x4b, 0x39, 0xc9, 0xf2, 0xfa, 0xa3, 0xe7, 0xdf,
	0xf6, 0x1b, 0x4f, 0x8c, 0xbb, 0x29, 0xb4, 0xdc, 0xe0, 0x2a, 0x14, 0x0d, 0x21, 0x38, 0x78, 0x8c,
	0xfe, 0x82, 0xfb, 0xc2, 0x36, 0xe6, 0x48, 0x7c, 0xbc, 0xbd, 0x45, 0xff, 0xe0, 0xf7, 0x9a, 0xf0,
	0x92, 0x99, 0xd9, 0xfb, 0x78, 0x57, 0x5c, 0x39, 0x03, 0x3b, 0x6a, 0x41, 0xa3, 0x9e, 0xc8, 0x87,
	0xda, 0x26, 0x1b, 0x95, 0x1a, 0x07, 0xe0, 0xef, 0x7f, 0x7a, 0x7c, 0xff, 0x7c, 0xb7, 0xc8, 0xf4,
	0xb2, 0x9c, 0xc5, 0xa9, 0xc8, 0xbb, 0xb7, 0x42, 0x2c, 0x38, 0x9b, 0x70, 0x51, 0xd2, 0x07, 0x4e,
	0xf4, 0x5c, 0xc8, 0xbc, 0xbb, 0x64, 0x84, 0xeb, 0x65, 0x4a, 0x24, 0xeb, 0xcc, 0x19, 0x65, 0x92,
	0x68, 0x46, 0x3b, 0x24, 0x4d, 0x99, 0x52, 0x1d, 0xc5, 0xe4, 0x3a, 0x4b, 0x99, 0xaa, 0x37, 0x6b,
	0xe6, 0x99, 0xd5, 0xea, 0xbf, 0x07, 0x00, 0x00, 0xff, 0xff, 0x23, 0x96, 0x2d, 0xa3, 0x73, 0x02,
	0x00, 0x00,
}