meta:
  id: nacp
  file-extension: nacp
  endian: le
  bit-endian: le
seq:
  - id: title
    type: title
    repeat: expr
    repeat-expr: 0x10
  - id: isbn
    type: strz
    size: 0x25
    encoding: UTF-8
  - id: startup_user_account
    type: u1
    enum: startup_user_account
  - id: user_account_switch_lock
    type: u1
    enum: user_account_switch_lock
  - id: add_on_content_registration_type
    type: u1
    enum: add_on_content_registration_type
  - id: attribute
    type: attribute
  - id: supported_language
    type: supported_language
  - id: parental_control
    type: parental_control
  - id: screenshot
    type: u1
    enum: screenshot
  - id: video_capture
    type: u1
    enum: video_capture
  - id: data_loss_confirmation
    type: u1
    enum: data_loss_confirmation
  - id: play_log_policy
    type: u1
    enum: play_log_policy
  - id: presence_group_id
    type: u8
  - id: rating_age
    type: rating_age
  - id: display_version
    type: strz
    size: 0x10
    encoding: UTF-8
  - id: add_on_content_base_id
    type: u8
  - id: save_data_owner_id
    type: u8
  - id: user_account_save_data_size
    type: s8
  - id: user_account_save_data_journal_size
    type: s8
  - id: device_save_data_size
    type: s8
  - id: device_save_data_journal_size
    type: s8
  - id: bcat_delivery_cache_storage_size
    type: s8
  - id: application_error_code_category
    type: strz
    size: 8
    encoding: UTF-8
  - id: local_communication_id
    type: u8
    repeat: expr
    repeat-expr: 8
  - id: logo_type
    type: u1
    enum: logo_type
  - id: logo_handling
    type: u1
    enum: logo_handling
  - id: runtime_add_on_content_install
    type: u1
    enum: runtime_add_on_content_install
  - id: runtime_parameter_delivery
    type: u1
    enum: runtime_parameter_delivery
  - id: appropriate_age_for_china
    type: u1
    enum: appropriate_age_for_china
  - id: undecided_parameter_75b8b
    type: u1
    enum: undecided_parameter_75b8b
  - id: crash_report
    type: u1
    enum: crash_report
  - id: hdcp
    type: u1
    enum: hdcp
  - id: seed_for_pseudo_device_id
    type: u8
  - id: bcat_passphrase
    type: strz
    size: 0x41
    encoding: UTF-8
  - id: startup_user_account_option
    type: startup_user_account_option
  - id: reserved_for_user_account_save_data_operation
    size: 6
  - id: user_account_save_data_size_max
    type: s8
  - id: user_account_save_data_journal_size_max
    type: s8
  - id: device_save_data_size_max
    type: s8
  - id: device_save_data_journal_size_max
    type: s8
  - id: temporary_storage_size
    type: s8
  - id: cache_storage_size
    type: s8
  - id: cache_storage_journal_size
    type: s8
  - id: cache_storage_data_and_journal_size_max
    type: s8
  - id: cache_storage_index_max
    type: u2
  - id: reserved_1
    size: 1
  - id: runtime_upgrade
    type: u1
    enum: runtime_upgrade
  - id: supporting_limited_licenses
    type: supporting_limited_licenses
  - id: play_log_queryable_application_id
    type: u8
    repeat: expr
    repeat-expr: 0x10
  - id: play_log_query_capability
    type: u1
    enum: play_log_query_capability
  - id: repair
    type: repair
  - id: program_index
    type: u1
  - id: required_network_service_license_on_launch
    type: required_network_service_license_on_launch
  - id: reserved_2
    size: 4
  - id: neighbor_detection_client_configuration
    type: neighbor_detection_client_configuration
  - id: jit_configuration
    type: jit_configuration
  - id: required_add_on_contents_set_binary_descriptor
    type: required_add_on_contents_set_binary_descriptor
  - id: play_report_permission
    type: play_report_permission
  - id: crash_screenshot_for_prod
    type: u1
    enum: crash_screenshot_for_prod
  - id: crash_screenshot_for_dev
    type: u1
    enum: crash_screenshot_for_dev
  - id: contents_availability_transition_policy
    type: u1
    enum: contents_availability_transition_policy
  - id: reserved_3
    size: 4
  - id: accessible_launch_required_version
    type: accessible_launch_required_version
  - id: reserved_4
    size: 0xBB8
enums:
  startup_user_account:
    0: none
    1: required
    2: required_with_network_service_account_available
  user_account_switch_lock:
    0: disable
    1: enable
  add_on_content_registration_type:
    0: all_on_launch
    1: on_demand
  language:
    0:  american_english
    1:  british_english
    2:  japanese
    3:  french
    4:  german
    5:  latin_american_spanish
    6:  spanish
    7:  italian
    8:  dutch
    9:  canadian_french
    10: portuguese
    11: russian
    12: korean
    13: traditional_chinese
    14: simplified_chinese
    15: brazilian_portuguese
    16: count
  screenshot:
    0: allow
    1: deny
  video_capture:
    0: disable
    1: manual
    2: enable
  data_loss_confirmation:
    0: none
    1: required
  play_log_policy:
    0: open
    1: log_only
    2: none
    3: closed
  rating_age_organization:
    0:  cero
    1:  grac_gcrb
    2:  gsrmr
    3:  esrb
    4:  class_ind
    5:  usk
    6:  pegi
    7:  pegi_portugal
    8:  pegi_bbfc
    9:  russian
    10: acb
    11: oflc
    12: iarc_generic
    13: count
  logo_type:
    0: licensed_by_nintendo
    1: distributed_by_nintendo
    2: nintendo
  logo_handling:
    0: auto
    1: manual
  runtime_add_on_content_install:
    0: deny
    1: allow_append
    2: allow_append_but_dont_download_when_using_network
  runtime_parameter_delivery:
    0: always
    1: always_if_user_state_matched
    2: on_restart
  appropriate_age_for_china:
    0: none
    1: age_8
    2: age_12
    3: age_16
  undecided_parameter_75b8b:
    0: a
    1: b
  crash_report:
    0: deny
    1: allow
  hdcp:
    0: none
    1: required
  runtime_upgrade:
    0: deny
    1: allow
  play_log_query_capability:
    0: none
    1: white_list
    2: all
  required_add_on_contents_set_descriptor_flag:
    0: none
    1: continue_
  crash_screenshot_for_prod:
    0: deny
    1: allow
  crash_screenshot_for_dev:
    0: deny
    1: allow
  contents_availability_transition_policy:
    0: no_policy
    1: stable
    2: changeable
types:
  title:
    seq:
      - id: name
        type: strz
        size: 0x200
        encoding: UTF-8
      - id: publisher
        type: strz
        size: 0x100
        encoding: UTF-8
  attribute:
    seq:
      - id: demo
        type: b1
      - id: retail_interactive_display
        type: b1
      - id: download_play
        type: b1
      - id: reserved
        type: b29
  supported_language:
    seq:
      - id: languages
        type: b1
        repeat: expr
        repeat-expr: 'language::count.to_i'
      - id: reserved
        type: b16
  parental_control:
    seq:
      - id: free_communication
        type: b1
      - id: reserved
        type: b31
  rating_age:
    seq:
      - id: organizations
        type: s1
        repeat: expr
        repeat-expr: 'rating_age_organization::count.to_i'
      - id: reserved
        size: 0x13
  startup_user_account_option:
    seq:
      - id: is_optional
        type: b1
      - id: reserved
        type: b7
  supporting_limited_licenses:
    seq:
      - id: demo
        type: b1
      - id: reserved
        type: b31
  repair:
    seq:
      - id: supress_gamecard_access
        type: b1
      - id: reserved
        type: b7
  required_network_service_license_on_launch:
    seq:
      - id: common
        type: b1
      - id: reserved
        type: b7
  neighbor_detection_group_configuration:
    seq:
      - id: group_id
        type: u8
      - id: key
        size: 0x10
  neighbor_detection_client_configuration:
    seq:
      - id: send_group_configuration
        type: neighbor_detection_group_configuration
      - id: receivable_group_configurations
        type: neighbor_detection_group_configuration
        repeat: expr
        repeat-expr: 0x10
  jit_configuration_flags:
    seq:
      - id: enabled
        type: b1
      - id: reserved_1
        type: b31
      - id: reserved_2
        size: 4
  jit_configuration:
    seq:
      - id: flags
        type: jit_configuration_flags
      - id: memory_size
        type: u8
  required_add_on_contents_set_descriptor:
    seq:
      - id: index
        type: b15
      - id: flag
        type: b1
        enum: required_add_on_contents_set_descriptor_flag
  required_add_on_contents_set_binary_descriptor:
    seq:
      - id: descriptors
        type: required_add_on_contents_set_descriptor
        repeat: expr
        repeat-expr: 0x20
  play_report_permission:
    seq:
      - id: target_marketing
        type: b1
      - id: reserved
        type: b7
  accessible_launch_required_version:
    seq:
      - id: application_id
        type: u8
        repeat: expr
        repeat-expr: 8
