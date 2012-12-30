# Generated by the protocol buffer compiler.  DO NOT EDIT!

from google.protobuf import descriptor
from google.protobuf import message
from google.protobuf import reflection
from google.protobuf import descriptor_pb2
# @@protoc_insertion_point(imports)



DESCRIPTOR = descriptor.FileDescriptor(
  name='cert.proto',
  package='bitcoincert',
  serialized_pb='\n\ncert.proto\x12\x0b\x62itcoincert\"X\n\x11\x42itcoinSimpleCert\x12\x15\n\recdsa_pubkeys\x18\x01 \x03(\x0c\x12\x10\n\x08SSL_cert\x18\x02 \x01(\x0c\x12\r\n\x05\x65mail\x18\x03 \x01(\t\x12\x0b\n\x03url\x18\x04 \x01(\t')




_BITCOINSIMPLECERT = descriptor.Descriptor(
  name='BitcoinSimpleCert',
  full_name='bitcoincert.BitcoinSimpleCert',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    descriptor.FieldDescriptor(
      name='ecdsa_pubkeys', full_name='bitcoincert.BitcoinSimpleCert.ecdsa_pubkeys', index=0,
      number=1, type=12, cpp_type=9, label=3,
      has_default_value=False, default_value=[],
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='SSL_cert', full_name='bitcoincert.BitcoinSimpleCert.SSL_cert', index=1,
      number=2, type=12, cpp_type=9, label=1,
      has_default_value=False, default_value="",
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='email', full_name='bitcoincert.BitcoinSimpleCert.email', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
    descriptor.FieldDescriptor(
      name='url', full_name='bitcoincert.BitcoinSimpleCert.url', index=3,
      number=4, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=unicode("", "utf-8"),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      options=None),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  options=None,
  is_extendable=False,
  extension_ranges=[],
  serialized_start=27,
  serialized_end=115,
)

DESCRIPTOR.message_types_by_name['BitcoinSimpleCert'] = _BITCOINSIMPLECERT

class BitcoinSimpleCert(message.Message):
  __metaclass__ = reflection.GeneratedProtocolMessageType
  DESCRIPTOR = _BITCOINSIMPLECERT
  
  # @@protoc_insertion_point(class_scope:bitcoincert.BitcoinSimpleCert)

# @@protoc_insertion_point(module_scope)
