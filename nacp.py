# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

from pkg_resources import parse_version
import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if parse_version(kaitaistruct.__version__) < parse_version('0.9'):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class Nacp(KaitaiStruct):

    class RuntimeAddOnContentInstall(Enum):
        deny = 0
        allow_append = 1
        allow_append_but_dont_download_when_using_network = 2

    class RatingAgeOrganization(Enum):
        cero = 0
        grac_gcrb = 1
        gsrmr = 2
        esrb = 3
        class_ind = 4
        usk = 5
        pegi = 6
        pegi_portugal = 7
        pegi_bbfc = 8
        russian = 9
        acb = 10
        oflc = 11
        iarc_generic = 12
        count = 13

    class PlayLogQueryCapability(Enum):
        none = 0
        white_list = 1
        all = 2

    class UserAccountSwitchLock(Enum):
        disable = 0
        enable = 1

    class ContentsAvailabilityTransitionPolicy(Enum):
        no_policy = 0
        stable = 1
        changeable = 2

    class PlayLogPolicy(Enum):
        open = 0
        log_only = 1
        none = 2
        closed = 3

    class AddOnContentRegistrationType(Enum):
        all_on_launch = 0
        on_demand = 1

    class CrashScreenshotForProd(Enum):
        deny = 0
        allow = 1

    class RequiredAddOnContentsSetDescriptorFlag(Enum):
        none = 0
        continue_ = 1

    class CrashReport(Enum):
        deny = 0
        allow = 1

    class LogoHandling(Enum):
        auto = 0
        manual = 1

    class Language(Enum):
        american_english = 0
        british_english = 1
        japanese = 2
        french = 3
        german = 4
        latin_american_spanish = 5
        spanish = 6
        italian = 7
        dutch = 8
        canadian_french = 9
        portuguese = 10
        russian = 11
        korean = 12
        traditional_chinese = 13
        simplified_chinese = 14
        brazilian_portuguese = 15
        count = 16

    class RuntimeUpgrade(Enum):
        deny = 0
        allow = 1

    class DataLossConfirmation(Enum):
        none = 0
        required = 1

    class UndecidedParameter75b8b(Enum):
        a = 0
        b = 1

    class Screenshot(Enum):
        allow = 0
        deny = 1

    class VideoCapture(Enum):
        disable = 0
        manual = 1
        enable = 2

    class StartupUserAccount(Enum):
        none = 0
        required = 1
        required_with_network_service_account_available = 2

    class RuntimeParameterDelivery(Enum):
        always = 0
        always_if_user_state_matched = 1
        on_restart = 2

    class LogoType(Enum):
        licensed_by_nintendo = 0
        distributed_by_nintendo = 1
        nintendo = 2

    class Hdcp(Enum):
        none = 0
        required = 1

    class CrashScreenshotForDev(Enum):
        deny = 0
        allow = 1

    class AppropriateAgeForChina(Enum):
        none = 0
        age_8 = 1
        age_12 = 2
        age_16 = 3
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.title = [None] * (16)
        for i in range(16):
            self.title[i] = Nacp.Title(self._io, self, self._root)

        self.isbn = (KaitaiStream.bytes_terminate(self._io.read_bytes(37), 0, False)).decode(u"UTF-8")
        self.startup_user_account = KaitaiStream.resolve_enum(Nacp.StartupUserAccount, self._io.read_u1())
        self.user_account_switch_lock = KaitaiStream.resolve_enum(Nacp.UserAccountSwitchLock, self._io.read_u1())
        self.add_on_content_registration_type = KaitaiStream.resolve_enum(Nacp.AddOnContentRegistrationType, self._io.read_u1())
        self.attribute = Nacp.Attribute(self._io, self, self._root)
        self.supported_language = Nacp.SupportedLanguage(self._io, self, self._root)
        self.parental_control = Nacp.ParentalControl(self._io, self, self._root)
        self.screenshot = KaitaiStream.resolve_enum(Nacp.Screenshot, self._io.read_u1())
        self.video_capture = KaitaiStream.resolve_enum(Nacp.VideoCapture, self._io.read_u1())
        self.data_loss_confirmation = KaitaiStream.resolve_enum(Nacp.DataLossConfirmation, self._io.read_u1())
        self.play_log_policy = KaitaiStream.resolve_enum(Nacp.PlayLogPolicy, self._io.read_u1())
        self.presence_group_id = self._io.read_u8le()
        self.rating_age = Nacp.RatingAge(self._io, self, self._root)
        self.display_version = (KaitaiStream.bytes_terminate(self._io.read_bytes(16), 0, False)).decode(u"UTF-8")
        self.add_on_content_base_id = self._io.read_u8le()
        self.save_data_owner_id = self._io.read_u8le()
        self.user_account_save_data_size = self._io.read_s8le()
        self.user_account_save_data_journal_size = self._io.read_s8le()
        self.device_save_data_size = self._io.read_s8le()
        self.device_save_data_journal_size = self._io.read_s8le()
        self.bcat_delivery_cache_storage_size = self._io.read_s8le()
        self.application_error_code_category = (KaitaiStream.bytes_terminate(self._io.read_bytes(8), 0, False)).decode(u"UTF-8")
        self.local_communication_id = [None] * (8)
        for i in range(8):
            self.local_communication_id[i] = self._io.read_u8le()

        self.logo_type = KaitaiStream.resolve_enum(Nacp.LogoType, self._io.read_u1())
        self.logo_handling = KaitaiStream.resolve_enum(Nacp.LogoHandling, self._io.read_u1())
        self.runtime_add_on_content_install = KaitaiStream.resolve_enum(Nacp.RuntimeAddOnContentInstall, self._io.read_u1())
        self.runtime_parameter_delivery = KaitaiStream.resolve_enum(Nacp.RuntimeParameterDelivery, self._io.read_u1())
        self.appropriate_age_for_china = KaitaiStream.resolve_enum(Nacp.AppropriateAgeForChina, self._io.read_u1())
        self.undecided_parameter_75b8b = KaitaiStream.resolve_enum(Nacp.UndecidedParameter75b8b, self._io.read_u1())
        self.crash_report = KaitaiStream.resolve_enum(Nacp.CrashReport, self._io.read_u1())
        self.hdcp = KaitaiStream.resolve_enum(Nacp.Hdcp, self._io.read_u1())
        self.seed_for_pseudo_device_id = self._io.read_u8le()
        self.bcat_passphrase = (KaitaiStream.bytes_terminate(self._io.read_bytes(65), 0, False)).decode(u"UTF-8")
        self.startup_user_account_option = Nacp.StartupUserAccountOption(self._io, self, self._root)
        self.reserved_for_user_account_save_data_operation = self._io.read_bytes(6)
        self.user_account_save_data_size_max = self._io.read_s8le()
        self.user_account_save_data_journal_size_max = self._io.read_s8le()
        self.device_save_data_size_max = self._io.read_s8le()
        self.device_save_data_journal_size_max = self._io.read_s8le()
        self.temporary_storage_size = self._io.read_s8le()
        self.cache_storage_size = self._io.read_s8le()
        self.cache_storage_journal_size = self._io.read_s8le()
        self.cache_storage_data_and_journal_size_max = self._io.read_s8le()
        self.cache_storage_index_max = self._io.read_u2le()
        self.reserved_1 = self._io.read_bytes(1)
        self.runtime_upgrade = KaitaiStream.resolve_enum(Nacp.RuntimeUpgrade, self._io.read_u1())
        self.supporting_limited_licenses = Nacp.SupportingLimitedLicenses(self._io, self, self._root)
        self.play_log_queryable_application_id = [None] * (16)
        for i in range(16):
            self.play_log_queryable_application_id[i] = self._io.read_u8le()

        self.play_log_query_capability = KaitaiStream.resolve_enum(Nacp.PlayLogQueryCapability, self._io.read_u1())
        self.repair = Nacp.Repair(self._io, self, self._root)
        self.program_index = self._io.read_u1()
        self.required_network_service_license_on_launch = Nacp.RequiredNetworkServiceLicenseOnLaunch(self._io, self, self._root)
        self.reserved_2 = self._io.read_bytes(4)
        self.neighbor_detection_client_configuration = Nacp.NeighborDetectionClientConfiguration(self._io, self, self._root)
        self.jit_configuration = Nacp.JitConfiguration(self._io, self, self._root)
        self.required_add_on_contents_set_binary_descriptor = Nacp.RequiredAddOnContentsSetBinaryDescriptor(self._io, self, self._root)
        self.play_report_permission = Nacp.PlayReportPermission(self._io, self, self._root)
        self.crash_screenshot_for_prod = KaitaiStream.resolve_enum(Nacp.CrashScreenshotForProd, self._io.read_u1())
        self.crash_screenshot_for_dev = KaitaiStream.resolve_enum(Nacp.CrashScreenshotForDev, self._io.read_u1())
        self.contents_availability_transition_policy = KaitaiStream.resolve_enum(Nacp.ContentsAvailabilityTransitionPolicy, self._io.read_u1())
        self.reserved_3 = self._io.read_bytes(4)
        self.accessible_launch_required_version = Nacp.AccessibleLaunchRequiredVersion(self._io, self, self._root)
        self.reserved_4 = self._io.read_bytes(3000)

    class StartupUserAccountOption(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.is_optional = self._io.read_bits_int_le(1) != 0
            self.reserved = self._io.read_bits_int_le(7)


    class RequiredAddOnContentsSetBinaryDescriptor(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.descriptors = [None] * (32)
            for i in range(32):
                self.descriptors[i] = Nacp.RequiredAddOnContentsSetDescriptor(self._io, self, self._root)



    class SupportedLanguage(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.languages = [None] * (Nacp.Language.count.value)
            for i in range(Nacp.Language.count.value):
                self.languages[i] = self._io.read_bits_int_le(1) != 0

            self.reserved = self._io.read_bits_int_le(16)


    class NeighborDetectionClientConfiguration(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.send_group_configuration = Nacp.NeighborDetectionGroupConfiguration(self._io, self, self._root)
            self.receivable_group_configurations = [None] * (16)
            for i in range(16):
                self.receivable_group_configurations[i] = Nacp.NeighborDetectionGroupConfiguration(self._io, self, self._root)



    class Repair(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.supress_gamecard_access = self._io.read_bits_int_le(1) != 0
            self.reserved = self._io.read_bits_int_le(7)


    class PlayReportPermission(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.target_marketing = self._io.read_bits_int_le(1) != 0
            self.reserved = self._io.read_bits_int_le(7)


    class RequiredNetworkServiceLicenseOnLaunch(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.common = self._io.read_bits_int_le(1) != 0
            self.reserved = self._io.read_bits_int_le(7)


    class JitConfiguration(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.flags = Nacp.JitConfigurationFlags(self._io, self, self._root)
            self.memory_size = self._io.read_u8le()


    class RatingAge(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.organizations = [None] * (Nacp.RatingAgeOrganization.count.value)
            for i in range(Nacp.RatingAgeOrganization.count.value):
                self.organizations[i] = self._io.read_s1()

            self.reserved = self._io.read_bytes(19)


    class NeighborDetectionGroupConfiguration(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.group_id = self._io.read_u8le()
            self.key = self._io.read_bytes(16)


    class Attribute(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.demo = self._io.read_bits_int_le(1) != 0
            self.retail_interactive_display = self._io.read_bits_int_le(1) != 0
            self.download_play = self._io.read_bits_int_le(1) != 0
            self.reserved = self._io.read_bits_int_le(29)


    class JitConfigurationFlags(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.enabled = self._io.read_bits_int_le(1) != 0
            self.reserved_1 = self._io.read_bits_int_le(31)
            self._io.align_to_byte()
            self.reserved_2 = self._io.read_bytes(4)


    class Title(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.name = (KaitaiStream.bytes_terminate(self._io.read_bytes(512), 0, False)).decode(u"UTF-8")
            self.publisher = (KaitaiStream.bytes_terminate(self._io.read_bytes(256), 0, False)).decode(u"UTF-8")


    class SupportingLimitedLicenses(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.demo = self._io.read_bits_int_le(1) != 0
            self.reserved = self._io.read_bits_int_le(31)


    class AccessibleLaunchRequiredVersion(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.application_id = [None] * (8)
            for i in range(8):
                self.application_id[i] = self._io.read_u8le()



    class RequiredAddOnContentsSetDescriptor(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.index = self._io.read_bits_int_le(15)
            self.flag = KaitaiStream.resolve_enum(Nacp.RequiredAddOnContentsSetDescriptorFlag, self._io.read_bits_int_le(1))


    class ParentalControl(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.free_communication = self._io.read_bits_int_le(1) != 0
            self.reserved = self._io.read_bits_int_le(31)



