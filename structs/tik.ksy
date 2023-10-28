meta:
  id: tik
  file-extension: tik
  endian: le
  bit-endian: le
seq:
  - id: sig_type
    type: u4
    enum: signature_type
  - id: signature
    size: '((sig_type == signature_type::rsa4096_sha1 or sig_type == signature_type::rsa4096_sha256) ? 0x200 : ((sig_type == signature_type::rsa2048_sha1 or sig_type == signature_type::rsa2048_sha256) ? 0x100 : ((sig_type == signature_type::ecc480_sha1 or sig_type == signature_type::ecc480_sha256) ? 0x3C : (sig_type == signature_type::hmac160_sha1 ? 0x14 : 0))))'
  - id: padding
    size: '((sig_type == signature_type::rsa4096_sha1 or sig_type == signature_type::rsa4096_sha256 or sig_type == signature_type::rsa2048_sha1 or sig_type == signature_type::rsa2048_sha256) ? 0x3C : ((sig_type == signature_type::ecc480_sha1 or sig_type == signature_type::ecc480_sha256) ? 0x40 : (sig_type == signature_type::hmac160_sha1 ? 0x28 : 0)))'
  - id: sig_issuer
    type: strz
    size: 0x40
    encoding: UTF-8
  - id: titlekey_block
    size: 0x100
  - id: format_version
    type: u1
  - id: titlekey_type
    type: u1
    enum: titlekey_type
  - id: ticket_version
    type: u2
  - id: license_type
    type: u1
    enum: license_type
  - id: key_generation
    type: u1
  - id: property_mask
    type: property_mask
  - id: reserved
    size: 8
  - id: ticket_id
    type: u8
  - id: device_id
    type: u8
  - id: rights_id
    type: rights_id
  - id: account_id
    type: u4
  - id: sect_total_size
    type: u4
  - id: sect_hdr_offset
    type: u4
  - id: sect_hdr_count
    type: u2
  - id: sect_hdr_entry_size
    type: u2
  - id: section_records_block
    size: sect_total_size
    if: '(sect_total_size > 0) and (sect_hdr_count > 0) and (sect_hdr_entry_size > 0)'
    type: 'section_records_block(sect_hdr_count)'
enums:
  signature_type:
    0x10000: rsa4096_sha1
    0x10001: rsa2048_sha1
    0x10002: ecc480_sha1
    0x10003: rsa4096_sha256
    0x10004: rsa2048_sha256
    0x10005: ecc480_sha256
    0x10006: hmac160_sha1
  titlekey_type:
    0x0: common
    0x1: personalized
  license_type:
    0x0: permanent
    0x1: demo
    0x2: trial
    0x3: rental
    0x4: subscription
    0x5: service
  section_type:
    0x1: permanent
    0x2: subscription
    0x3: content
    0x4: content_consumption
    0x5: access_title
    0x6: limited_resource
types:
  property_mask:
    seq:
      - id: pre_installation
        type: b1
      - id: shared_title
        type: b1
      - id: all_contents
        type: b1
      - id: device_link_independent
        type: b1
      - id: volatile
        type: b1
      - id: elicense_required
        type: b1
      - id: reserved
        type: b10
  rights_id:
    seq:
      - id: title_id
        type: u8be
      - id: reserved
        size: 7
      - id: key_generation
        type: u1
  esv2_section_record:
    seq:
      - id: sect_offset
        type: u4
      - id: record_size
        type: u4
      - id: section_size
        type: u4
      - id: record_count
        type: u2
      - id: section_type
        type: u2
        enum: section_type
  esv1_permanent_record:
    seq:
      - id: ref_id
        size: 0x10
      - id: ref_id_attr
        type: u4
  esv1_subscription_record:
    seq:
      - id: limit
        type: u4
      - id: ref_id
        size: 0x10
      - id: ref_id_attr
        type: u4
  esv1_content_record:
    seq:
      - id: offset
        type: u4
      - id: access_mask
        size: 0x80
  esv1_content_consumption_record:
    seq:
      - id: index
        type: u2
      - id: code
        type: u2
      - id: limit
        type: u4
  esv1_access_title_record:
    seq:
      - id: access_title_id
        type: u8
      - id: access_title_mask
        type: u8
  esv1_limited_resource_record:
    seq:
      - id: limit
        type: u4
      - id: ref_id
        size: 0x10
      - id: ref_id_attr
        type: u4
  section_record:
    seq:
      - id: esv2_record
        type: esv2_section_record
      - id: esv1_records
        size: esv2_record.record_size
        type:
          switch-on: esv2_record.section_type
          cases:
            'section_type::permanent': esv1_permanent_record
            'section_type::subscription': esv1_subscription_record
            'section_type::content': esv1_content_record
            'section_type::content_consumption': esv1_content_consumption_record
            'section_type::access_title': esv1_access_title_record
            'section_type::limited_resource': esv1_limited_resource_record
        repeat: expr
        repeat-expr: esv2_record.record_count
  section_records_block:
    params:
      - id: sect_hdr_count
        type: u2
    seq:
      - id: section_records
        type: section_record
        repeat: expr
        repeat-expr: sect_hdr_count
