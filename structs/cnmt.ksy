meta:
  id: cnmt
  file-extension: cnmt
  endian: le
  bit-endian: le
seq:
  - id: header
    type: packaged_content_meta_header
  - id: extended_header
    if: _root.header.extended_header_size > 0
    size: _root.header.extended_header_size
    type:
      switch-on: |
        _root.header.content_meta_type == content_meta_type::system_update ? dummy_meta_type::system_update
        : _root.header.content_meta_type == content_meta_type::application ? dummy_meta_type::application
        : _root.header.content_meta_type == content_meta_type::patch ? dummy_meta_type::patch
        : _root.header.content_meta_type == content_meta_type::add_on_content ? (_root.header.extended_header_size == 0x18 ? dummy_meta_type::add_on_content : dummy_meta_type::add_on_content_legacy)
        : _root.header.content_meta_type == content_meta_type::delta ? dummy_meta_type::delta
        : _root.header.content_meta_type == content_meta_type::data_patch ? dummy_meta_type::data_patch
        : dummy_meta_type::invalid
      cases:
        'dummy_meta_type::system_update': system_update_extended_header
        'dummy_meta_type::application': application_extended_header
        'dummy_meta_type::patch': patch_extended_header
        'dummy_meta_type::add_on_content': aoc_extended_header
        'dummy_meta_type::add_on_content_legacy': aoc_legacy_extended_header
        'dummy_meta_type::delta': delta_extended_header
        'dummy_meta_type::data_patch': data_patch_extended_header
        _: dummy
  - id: packaged_content_infos
    type: packaged_content_info
    repeat: expr
    repeat-expr: _root.header.content_count
  - id: content_meta_infos
    type: content_meta_info
    repeat: expr
    repeat-expr: _root.header.content_meta_count
  - id: extended_data
    if: extended_data_size > 0
    size: extended_data_size
    type:
      switch-on: _root.header.content_meta_type
      cases:
        'content_meta_type::system_update': system_update_extended_data
        'content_meta_type::patch': patch_extended_data
        'content_meta_type::delta': delta_extended_data
        'content_meta_type::data_patch': patch_extended_data # TODO: check if this is right
        _: dummy
  - id: digest
    size: 0x20
instances:
  extended_data_size:
    value: '(_root.header.extended_header_size <= 0 ? 0 : (_root.header.content_meta_type == content_meta_type::system_update ? extended_header.as<system_update_extended_header>.extended_data_size : (_root.header.content_meta_type == content_meta_type::patch ? extended_header.as<patch_extended_header>.extended_data_size : (_root.header.content_meta_type == content_meta_type::delta ? extended_header.as<delta_extended_header>.extended_data_size : (_root.header.content_meta_type == content_meta_type::data_patch ? extended_header.as<data_patch_extended_header>.extended_data_size : 0)))))'
enums:
  dummy_meta_type:
    0x0:  system_update
    0x1:  application
    0x2:  patch
    0x3:  add_on_content
    0x4:  add_on_content_legacy
    0x5:  delta
    0x6:  data_patch
    0xff: invalid
  content_meta_type:
    0x0:  unknown
    0x1:  system_program
    0x2:  system_data
    0x3:  system_update
    0x4:  boot_image_package
    0x5:  boot_image_package_safe
    0x80: application
    0x81: patch
    0x82: add_on_content
    0x83: delta
    0x84: data_patch
  storage_type:
    0x0: none
    0x1: host
    0x2: gamecard
    0x3: built_in_system
    0x4: built_in_user
    0x5: sd_card
    0x6: any
  install_type:
    0x0: full
    0x1: fragment_only
    0x7: unknown
  content_type:
    0x0: meta
    0x1: program
    0x2: data
    0x3: control
    0x4: html_document
    0x5: legal_information
    0x6: delta_fragment
  firmware_variation_version:
    0x1: v1
    0x2: v2
  update_type:
    0x0: apply_as_delta
    0x1: overwrite
    0x2: create
types:
  dummy: {}
  system_version:
    seq:
      - id: minor_relstep
        type: b8
      - id: major_relstep
        type: b8
      - id: micro
        type: b4
      - id: minor
        type: b6
      - id: major
        type: b6
    instances:
      raw_version:
        value: '(major.as<u4> << 26) | (minor.as<u4> << 20) | (micro.as<u4> << 16) | (major_relstep.as<u4> << 8) | minor_relstep.as<u4>'
  application_version:
    seq:
      - id: private_ver
        type: b16
      - id: release_ver
        type: b16
    instances:
      raw_version:
        value: '(release_ver.as<u4> << 16) | private_ver'
  content_meta_attribute:
    seq:
      - id: includes_exfat_driver
        type: b1
      - id: rebootless
        type: b1
      - id: compacted
        type: b1
      - id: reserved
        type: b5
  content_meta_install_state:
    seq:
      - id: install_state_committed
        type: b1
      - id: reserved
        type: b7
  packaged_content_meta_header:
    seq:
      - id: title_id
        type: u8
      - id: version
        type: application_version
      - id: content_meta_type
        type: u1
        enum: content_meta_type
      - id: reserved_1
        size: 1
      - id: extended_header_size
        type: u2
      - id: content_count
        type: u2
      - id: content_meta_count
        type: u2
      - id: content_meta_attribute
        type: content_meta_attribute
      - id: storage_id
        type: u1
        enum: storage_type
      - id: content_install_type
        type: u1
        enum: install_type
      - id: content_meta_install_state
        type: content_meta_install_state
      - id: required_download_system_version
        type: system_version
      - id: reserved_2
        size: 4
  system_update_extended_header:
    seq:
      - id: extended_data_size
        type: u4
  application_extended_header:
    seq:
      - id: patch_id
        type: u8
      - id: required_system_version
        type: system_version
      - id: required_application_version
        type: application_version
  patch_extended_header:
    seq:
      - id: application_id
        type: u8
      - id: required_system_version
        type: system_version
      - id: extended_data_size
        type: u4
      - id: reserved
        size: 8
  aoc_extended_header:
    seq:
      - id: application_id
        type: u8
      - id: required_application_version
        type: application_version
      - id: content_accessibilities
        type: u1
      - id: reserved
        size: 3
      - id: data_patch_id
        type: u8
  aoc_legacy_extended_header:
    seq:
      - id: application_id
        type: u8
      - id: required_application_version
        type: application_version
      - id: reserved
        size: 4
  delta_extended_header:
    seq:
      - id: application_id
        type: u8
      - id: extended_data_size
        type: u4
      - id: reserved
        size: 4
  data_patch_extended_header:
    seq:
      - id: data_id
        type: u8
      - id: application_id
        type: u8
      - id: required_application_version
        type: application_version
      - id: extended_data_size
        type: u4
      - id: reserved
        size: 8
  content_info:
    seq:
      - id: id
        size: 0x10
      - id: size_low
        type: u4
      - id: size_high
        type: u1
      - id: attr
        type: u1
      - id: type
        type: u1
        enum: content_type
      - id: id_offset
        type: u1
    instances:
      raw_size:
        value: '(size_high.as<u8> << 32) | size_low'
  packaged_content_info:
    seq:
      - id: hash
        size: 0x20
      - id: info
        type: content_info
  content_meta_info:
    seq:
      - id: id
        type: u8
      - id: version
        type: system_version
      - id: type
        type: u1
        enum: content_meta_type
      - id: attr
        type: content_meta_attribute
      - id: padding
        size: 2
  firmware_variation_info_v1:
    seq:
      - id: id
        type: u4
      - id: reserved
        size: 0x1C
  firmware_variation_info_v2:
    seq:
      - id: refer_to_base
        type: u1
      - id: reserved_1
        size: 3
      - id: meta_count
        type: u4
      - id: reserved_2
        size: 0x18
  sum_reduce:
    params:
      - id: step_item
        type: s8
      - id: accumulator
        type: s8
    instances:
      result:
        value: step_item + accumulator
  system_update_extended_data:
    seq:
      - id: version
        type: u4
        enum: firmware_variation_version
      - id: variation_count
        type: u4
      - id: firmware_variation_infos_v1
        type: firmware_variation_info_v1
        repeat: expr
        repeat-expr: variation_count
        if: version == firmware_variation_version::v1
      - id: firmware_variation_ids
        type: u4
        repeat: expr
        repeat-expr: variation_count
        if: version == firmware_variation_version::v2
      - id: firmware_variation_infos_v2
        type: firmware_variation_info_v2
        repeat: expr
        repeat-expr: variation_count
        if: version == firmware_variation_version::v2
      - id: content_meta_infos
        if: '(version == firmware_variation_version::v2) and (variation_count > 0)'
        type: content_meta_info
        repeat: expr
        repeat-expr: meta_count_sum.last.result
    instances:
      meta_count_sum:
        if: version == firmware_variation_version::v2
        type: 'sum_reduce((firmware_variation_infos_v2[_index].refer_to_base != 0) ? 0 : firmware_variation_infos_v2[_index].meta_count, (_index == 0) ? 0 : meta_count_sum[_index - 1].result)'
        repeat: expr
        repeat-expr: variation_count
  content_meta_key:
    seq:
      - id: id
        type: u8
      - id: version
        type: application_version
      - id: type
        type: u1
        enum: content_meta_type
      - id: install_type
        type: u1
        enum: install_type
      - id: padding
        size: 2
  patch_history_header:
    seq:
      - id: content_meta_key
        type: content_meta_key
      - id: digest
        size: 0x20
      - id: content_info_count
        type: u2
      - id: reserved
        size: 6
  patch_delta_history:
    seq:
      - id: src_patch_id
        type: u8
      - id: dst_patch_id
        type: u8
      - id: src_version
        type: application_version
      - id: dst_version
        type: application_version
      - id: download_size
        type: u8
      - id: reserved
        size: 8
  patch_delta_header:
    seq:
      - id: src_patch_id
        type: u8
      - id: dst_patch_id
        type: u8
      - id: src_version
        type: application_version
      - id: dst_version
        type: application_version
      - id: fragment_set_count
        type: u2
      - id: reserved_1
        size: 6
      - id: content_info_count
        type: u2
      - id: reserved_2
        size: 6
  patch_fragment_set:
    seq:
      - id: src_content_id
        size: 0x10
      - id: dst_content_id
        size: 0x10
      - id: src_size_low
        type: u4
      - id: src_size_high
        type: u2
      - id: dst_size_high
        type: u2
      - id: dst_size_low
        type: u4
      - id: fragment_count
        type: u2
      - id: fragment_target_content_type
        type: u1
        enum: content_type
      - id: update_type
        type: u1
        enum: update_type
      - id: reserved
        size: 4
    instances:
      src_size:
        value: '(src_size_high.as<u8> << 32) | src_size_low'
      dst_size:
        value: '(dst_size_high.as<u8> << 32) | dst_size_low'
  patch_fragment_indicator:
    seq:
      - id: content_info_index
        type: u2
      - id: fragment_index
        type: u2
  patch_extended_data:
    seq:
      - id: history_count
        type: u4
      - id: delta_history_count
        type: u4
      - id: delta_count
        type: u4
      - id: fragment_set_count
        type: u4
      - id: history_content_count
        type: u4
      - id: delta_content_count
        type: u4
      - id: reserved
        size: 4
      - id: history_headers
        type: patch_history_header
        repeat: expr
        repeat-expr: history_count
      - id: delta_histories
        type: patch_delta_history
        repeat: expr
        repeat-expr: delta_history_count
      - id: delta_headers
        type: patch_delta_header
        repeat: expr
        repeat-expr: delta_count
      - id: fragment_sets
        type: patch_fragment_set
        repeat: expr
        repeat-expr: fragment_set_count
      - id: history_contents
        type: content_info
        repeat: expr
        repeat-expr: history_content_count
      - id: delta_contents
        type: packaged_content_info
        repeat: expr
        repeat-expr: delta_content_count
      - id: fragment_indicators
        if: fragment_set_count > 0
        type: patch_fragment_indicator
        repeat: expr
        repeat-expr: fragment_count_sum.last.result
    instances:
      fragment_count_sum:
        type: 'sum_reduce(fragment_sets[_index].fragment_count, (_index == 0) ? 0 : fragment_count_sum[_index - 1].result)'
        repeat: expr
        repeat-expr: fragment_set_count
  delta_extended_data:
    seq:
      - id: src_patch_id
        type: u8
      - id: dst_patch_id
        type: u8
      - id: src_version
        type: application_version
      - id: dst_version
        type: application_version
      - id: fragment_set_count
        type: u2
      - id: reserved
        size: 6
      - id: fragment_sets
        type: patch_fragment_set
        repeat: expr
        repeat-expr: fragment_set_count
      - id: fragment_indicators
        if: fragment_set_count > 0
        type: patch_fragment_indicator
        repeat: expr
        repeat-expr: fragment_count_sum.last.result
    instances:
      fragment_count_sum:
        type: 'sum_reduce(fragment_sets[_index].fragment_count, (_index == 0) ? 0 : fragment_count_sum[_index - 1].result)'
        repeat: expr
        repeat-expr: fragment_set_count
