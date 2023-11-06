# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class Cnmt(KaitaiStruct):

    class FirmwareVariationVersion(Enum):
        v1 = 1
        v2 = 2

    class ContentType(Enum):
        meta = 0
        program = 1
        data = 2
        control = 3
        html_document = 4
        legal_information = 5
        delta_fragment = 6

    class ContentMetaType(Enum):
        unknown = 0
        system_program = 1
        system_data = 2
        system_update = 3
        boot_image_package = 4
        boot_image_package_safe = 5
        application = 128
        patch = 129
        add_on_content = 130
        delta = 131
        data_patch = 132

    class DummyMetaType(Enum):
        system_update = 0
        application = 1
        patch = 2
        add_on_content = 3
        add_on_content_legacy = 4
        delta = 5
        data_patch = 6
        invalid = 255

    class StorageType(Enum):
        none = 0
        host = 1
        gamecard = 2
        built_in_system = 3
        built_in_user = 4
        sd_card = 5
        any = 6

    class UpdateType(Enum):
        apply_as_delta = 0
        overwrite = 1
        create = 2

    class InstallType(Enum):
        full = 0
        fragment_only = 1
        unknown = 7
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.header = Cnmt.PackagedContentMetaHeader(self._io, self, self._root)
        if self._root.header.extended_header_size > 0:
            _on = (Cnmt.DummyMetaType.system_update if self._root.header.content_meta_type == Cnmt.ContentMetaType.system_update else (Cnmt.DummyMetaType.application if self._root.header.content_meta_type == Cnmt.ContentMetaType.application else (Cnmt.DummyMetaType.patch if self._root.header.content_meta_type == Cnmt.ContentMetaType.patch else ((Cnmt.DummyMetaType.add_on_content if self._root.header.extended_header_size == 24 else Cnmt.DummyMetaType.add_on_content_legacy) if self._root.header.content_meta_type == Cnmt.ContentMetaType.add_on_content else (Cnmt.DummyMetaType.delta if self._root.header.content_meta_type == Cnmt.ContentMetaType.delta else (Cnmt.DummyMetaType.data_patch if self._root.header.content_meta_type == Cnmt.ContentMetaType.data_patch else Cnmt.DummyMetaType.invalid))))))
            if _on == Cnmt.DummyMetaType.system_update:
                self._raw_extended_header = self._io.read_bytes(self._root.header.extended_header_size)
                _io__raw_extended_header = KaitaiStream(BytesIO(self._raw_extended_header))
                self.extended_header = Cnmt.SystemUpdateExtendedHeader(_io__raw_extended_header, self, self._root)
            elif _on == Cnmt.DummyMetaType.patch:
                self._raw_extended_header = self._io.read_bytes(self._root.header.extended_header_size)
                _io__raw_extended_header = KaitaiStream(BytesIO(self._raw_extended_header))
                self.extended_header = Cnmt.PatchExtendedHeader(_io__raw_extended_header, self, self._root)
            elif _on == Cnmt.DummyMetaType.application:
                self._raw_extended_header = self._io.read_bytes(self._root.header.extended_header_size)
                _io__raw_extended_header = KaitaiStream(BytesIO(self._raw_extended_header))
                self.extended_header = Cnmt.ApplicationExtendedHeader(_io__raw_extended_header, self, self._root)
            elif _on == Cnmt.DummyMetaType.data_patch:
                self._raw_extended_header = self._io.read_bytes(self._root.header.extended_header_size)
                _io__raw_extended_header = KaitaiStream(BytesIO(self._raw_extended_header))
                self.extended_header = Cnmt.DataPatchExtendedHeader(_io__raw_extended_header, self, self._root)
            elif _on == Cnmt.DummyMetaType.add_on_content:
                self._raw_extended_header = self._io.read_bytes(self._root.header.extended_header_size)
                _io__raw_extended_header = KaitaiStream(BytesIO(self._raw_extended_header))
                self.extended_header = Cnmt.AocExtendedHeader(_io__raw_extended_header, self, self._root)
            elif _on == Cnmt.DummyMetaType.delta:
                self._raw_extended_header = self._io.read_bytes(self._root.header.extended_header_size)
                _io__raw_extended_header = KaitaiStream(BytesIO(self._raw_extended_header))
                self.extended_header = Cnmt.DeltaExtendedHeader(_io__raw_extended_header, self, self._root)
            elif _on == Cnmt.DummyMetaType.add_on_content_legacy:
                self._raw_extended_header = self._io.read_bytes(self._root.header.extended_header_size)
                _io__raw_extended_header = KaitaiStream(BytesIO(self._raw_extended_header))
                self.extended_header = Cnmt.AocLegacyExtendedHeader(_io__raw_extended_header, self, self._root)
            else:
                self._raw_extended_header = self._io.read_bytes(self._root.header.extended_header_size)
                _io__raw_extended_header = KaitaiStream(BytesIO(self._raw_extended_header))
                self.extended_header = Cnmt.Dummy(_io__raw_extended_header, self, self._root)

        self.packaged_content_infos = []
        for i in range(self._root.header.content_count):
            self.packaged_content_infos.append(Cnmt.PackagedContentInfo(self._io, self, self._root))

        self.content_meta_infos = []
        for i in range(self._root.header.content_meta_count):
            self.content_meta_infos.append(Cnmt.ContentMetaInfo(self._io, self, self._root))

        if self.extended_data_size > 0:
            _on = self._root.header.content_meta_type
            if _on == Cnmt.ContentMetaType.delta:
                self._raw_extended_data = self._io.read_bytes(self.extended_data_size)
                _io__raw_extended_data = KaitaiStream(BytesIO(self._raw_extended_data))
                self.extended_data = Cnmt.DeltaExtendedData(_io__raw_extended_data, self, self._root)
            elif _on == Cnmt.ContentMetaType.system_update:
                self._raw_extended_data = self._io.read_bytes(self.extended_data_size)
                _io__raw_extended_data = KaitaiStream(BytesIO(self._raw_extended_data))
                self.extended_data = Cnmt.SystemUpdateExtendedData(_io__raw_extended_data, self, self._root)
            elif _on == Cnmt.ContentMetaType.patch:
                self._raw_extended_data = self._io.read_bytes(self.extended_data_size)
                _io__raw_extended_data = KaitaiStream(BytesIO(self._raw_extended_data))
                self.extended_data = Cnmt.PatchExtendedData(_io__raw_extended_data, self, self._root)
            elif _on == Cnmt.ContentMetaType.data_patch:
                self._raw_extended_data = self._io.read_bytes(self.extended_data_size)
                _io__raw_extended_data = KaitaiStream(BytesIO(self._raw_extended_data))
                self.extended_data = Cnmt.PatchExtendedData(_io__raw_extended_data, self, self._root)
            else:
                self._raw_extended_data = self._io.read_bytes(self.extended_data_size)
                _io__raw_extended_data = KaitaiStream(BytesIO(self._raw_extended_data))
                self.extended_data = Cnmt.Dummy(_io__raw_extended_data, self, self._root)

        self.digest = self._io.read_bytes(32)

    class PatchHistoryHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.content_meta_key = Cnmt.ContentMetaKey(self._io, self, self._root)
            self.digest = self._io.read_bytes(32)
            self.content_info_count = self._io.read_u2le()
            self.reserved = self._io.read_bytes(6)


    class FirmwareVariationInfoV1(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.id = self._io.read_u4le()
            self.reserved = self._io.read_bytes(28)


    class ContentMetaKey(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.id = self._io.read_u8le()
            self.version = Cnmt.ApplicationVersion(self._io, self, self._root)
            self.type = KaitaiStream.resolve_enum(Cnmt.ContentMetaType, self._io.read_u1())
            self.install_type = KaitaiStream.resolve_enum(Cnmt.InstallType, self._io.read_u1())
            self.padding = self._io.read_bytes(2)


    class DeltaExtendedData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.src_patch_id = self._io.read_u8le()
            self.dst_patch_id = self._io.read_u8le()
            self.src_version = Cnmt.ApplicationVersion(self._io, self, self._root)
            self.dst_version = Cnmt.ApplicationVersion(self._io, self, self._root)
            self.fragment_set_count = self._io.read_u2le()
            self.reserved = self._io.read_bytes(6)
            self.fragment_sets = []
            for i in range(self.fragment_set_count):
                self.fragment_sets.append(Cnmt.PatchFragmentSet(self._io, self, self._root))

            if self.fragment_set_count > 0:
                self.fragment_indicators = []
                for i in range(self.fragment_count_sum[-1].result):
                    self.fragment_indicators.append(Cnmt.PatchFragmentIndicator(self._io, self, self._root))



        @property
        def fragment_count_sum(self):
            if hasattr(self, '_m_fragment_count_sum'):
                return self._m_fragment_count_sum

            self._m_fragment_count_sum = []
            for i in range(self.fragment_set_count):
                self._m_fragment_count_sum.append(Cnmt.SumReduce(self.fragment_sets[i].fragment_count, (0 if i == 0 else self.fragment_count_sum[(i - 1)].result), self._io, self, self._root))

            return getattr(self, '_m_fragment_count_sum', None)


    class PatchExtendedData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.history_count = self._io.read_u4le()
            self.delta_history_count = self._io.read_u4le()
            self.delta_count = self._io.read_u4le()
            self.fragment_set_count = self._io.read_u4le()
            self.history_content_count = self._io.read_u4le()
            self.delta_content_count = self._io.read_u4le()
            self.reserved = self._io.read_bytes(4)
            self.history_headers = []
            for i in range(self.history_count):
                self.history_headers.append(Cnmt.PatchHistoryHeader(self._io, self, self._root))

            self.delta_histories = []
            for i in range(self.delta_history_count):
                self.delta_histories.append(Cnmt.PatchDeltaHistory(self._io, self, self._root))

            self.delta_headers = []
            for i in range(self.delta_count):
                self.delta_headers.append(Cnmt.PatchDeltaHeader(self._io, self, self._root))

            self.fragment_sets = []
            for i in range(self.fragment_set_count):
                self.fragment_sets.append(Cnmt.PatchFragmentSet(self._io, self, self._root))

            self.history_contents = []
            for i in range(self.history_content_count):
                self.history_contents.append(Cnmt.ContentInfo(self._io, self, self._root))

            self.delta_contents = []
            for i in range(self.delta_content_count):
                self.delta_contents.append(Cnmt.PackagedContentInfo(self._io, self, self._root))

            if self.fragment_set_count > 0:
                self.fragment_indicators = []
                for i in range(self.fragment_count_sum[-1].result):
                    self.fragment_indicators.append(Cnmt.PatchFragmentIndicator(self._io, self, self._root))



        @property
        def fragment_count_sum(self):
            if hasattr(self, '_m_fragment_count_sum'):
                return self._m_fragment_count_sum

            self._m_fragment_count_sum = []
            for i in range(self.fragment_set_count):
                self._m_fragment_count_sum.append(Cnmt.SumReduce(self.fragment_sets[i].fragment_count, (0 if i == 0 else self.fragment_count_sum[(i - 1)].result), self._io, self, self._root))

            return getattr(self, '_m_fragment_count_sum', None)


    class ContentMetaInfo(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.id = self._io.read_u8le()
            self.version = Cnmt.SystemVersion(self._io, self, self._root)
            self.type = KaitaiStream.resolve_enum(Cnmt.ContentMetaType, self._io.read_u1())
            self.attr = Cnmt.ContentMetaAttribute(self._io, self, self._root)
            self.padding = self._io.read_bytes(2)


    class SystemUpdateExtendedHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.extended_data_size = self._io.read_u4le()


    class SumReduce(KaitaiStruct):
        def __init__(self, step_item, accumulator, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.step_item = step_item
            self.accumulator = accumulator
            self._read()

        def _read(self):
            pass

        @property
        def result(self):
            if hasattr(self, '_m_result'):
                return self._m_result

            self._m_result = (self.step_item + self.accumulator)
            return getattr(self, '_m_result', None)


    class AocExtendedHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.application_id = self._io.read_u8le()
            self.required_application_version = Cnmt.ApplicationVersion(self._io, self, self._root)
            self.content_accessibilities = self._io.read_u1()
            self.reserved = self._io.read_bytes(3)
            self.data_patch_id = self._io.read_u8le()


    class PatchFragmentIndicator(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.content_info_index = self._io.read_u2le()
            self.fragment_index = self._io.read_u2le()


    class ContentMetaInstallState(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.install_state_committed = self._io.read_bits_int_le(1) != 0
            self.reserved = self._io.read_bits_int_le(7)


    class SystemUpdateExtendedData(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.version = KaitaiStream.resolve_enum(Cnmt.FirmwareVariationVersion, self._io.read_u4le())
            self.variation_count = self._io.read_u4le()
            if self.version == Cnmt.FirmwareVariationVersion.v1:
                self.firmware_variation_infos_v1 = []
                for i in range(self.variation_count):
                    self.firmware_variation_infos_v1.append(Cnmt.FirmwareVariationInfoV1(self._io, self, self._root))


            if self.version == Cnmt.FirmwareVariationVersion.v2:
                self.firmware_variation_ids = []
                for i in range(self.variation_count):
                    self.firmware_variation_ids.append(self._io.read_u4le())


            if self.version == Cnmt.FirmwareVariationVersion.v2:
                self.firmware_variation_infos_v2 = []
                for i in range(self.variation_count):
                    self.firmware_variation_infos_v2.append(Cnmt.FirmwareVariationInfoV2(self._io, self, self._root))


            if  ((self.version == Cnmt.FirmwareVariationVersion.v2) and (self.variation_count > 0)) :
                self.content_meta_infos = []
                for i in range(self.meta_count_sum[-1].result):
                    self.content_meta_infos.append(Cnmt.ContentMetaInfo(self._io, self, self._root))



        @property
        def meta_count_sum(self):
            if hasattr(self, '_m_meta_count_sum'):
                return self._m_meta_count_sum

            if self.version == Cnmt.FirmwareVariationVersion.v2:
                self._m_meta_count_sum = []
                for i in range(self.variation_count):
                    self._m_meta_count_sum.append(Cnmt.SumReduce((0 if self.firmware_variation_infos_v2[i].refer_to_base != 0 else self.firmware_variation_infos_v2[i].meta_count), (0 if i == 0 else self.meta_count_sum[(i - 1)].result), self._io, self, self._root))


            return getattr(self, '_m_meta_count_sum', None)


    class Dummy(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            pass


    class PackagedContentInfo(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.hash = self._io.read_bytes(32)
            self.info = Cnmt.ContentInfo(self._io, self, self._root)


    class PatchDeltaHistory(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.src_patch_id = self._io.read_u8le()
            self.dst_patch_id = self._io.read_u8le()
            self.src_version = Cnmt.ApplicationVersion(self._io, self, self._root)
            self.dst_version = Cnmt.ApplicationVersion(self._io, self, self._root)
            self.download_size = self._io.read_u8le()
            self.reserved = self._io.read_bytes(8)


    class PackagedContentMetaHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.title_id = self._io.read_u8le()
            self.version = Cnmt.ApplicationVersion(self._io, self, self._root)
            self.content_meta_type = KaitaiStream.resolve_enum(Cnmt.ContentMetaType, self._io.read_u1())
            self.reserved_1 = self._io.read_bytes(1)
            self.extended_header_size = self._io.read_u2le()
            self.content_count = self._io.read_u2le()
            self.content_meta_count = self._io.read_u2le()
            self.content_meta_attribute = Cnmt.ContentMetaAttribute(self._io, self, self._root)
            self.storage_id = KaitaiStream.resolve_enum(Cnmt.StorageType, self._io.read_u1())
            self.content_install_type = KaitaiStream.resolve_enum(Cnmt.InstallType, self._io.read_u1())
            self.content_meta_install_state = Cnmt.ContentMetaInstallState(self._io, self, self._root)
            self.required_download_system_version = Cnmt.SystemVersion(self._io, self, self._root)
            self.reserved_2 = self._io.read_bytes(4)


    class SystemVersion(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.minor_relstep = self._io.read_bits_int_le(8)
            self.major_relstep = self._io.read_bits_int_le(8)
            self.micro = self._io.read_bits_int_le(4)
            self.minor = self._io.read_bits_int_le(6)
            self.major = self._io.read_bits_int_le(6)

        @property
        def raw_version(self):
            if hasattr(self, '_m_raw_version'):
                return self._m_raw_version

            self._m_raw_version = (((((self.major << 26) | (self.minor << 20)) | (self.micro << 16)) | (self.major_relstep << 8)) | self.minor_relstep)
            return getattr(self, '_m_raw_version', None)


    class ApplicationVersion(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.private_ver = self._io.read_bits_int_le(16)
            self.release_ver = self._io.read_bits_int_le(16)

        @property
        def raw_version(self):
            if hasattr(self, '_m_raw_version'):
                return self._m_raw_version

            self._m_raw_version = ((self.release_ver << 16) | self.private_ver)
            return getattr(self, '_m_raw_version', None)


    class ApplicationExtendedHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.patch_id = self._io.read_u8le()
            self.required_system_version = Cnmt.SystemVersion(self._io, self, self._root)
            self.required_application_version = Cnmt.ApplicationVersion(self._io, self, self._root)


    class PatchExtendedHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.application_id = self._io.read_u8le()
            self.required_system_version = Cnmt.SystemVersion(self._io, self, self._root)
            self.extended_data_size = self._io.read_u4le()
            self.reserved = self._io.read_bytes(8)


    class DataPatchExtendedHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.data_id = self._io.read_u8le()
            self.application_id = self._io.read_u8le()
            self.required_application_version = Cnmt.ApplicationVersion(self._io, self, self._root)
            self.extended_data_size = self._io.read_u4le()
            self.reserved = self._io.read_bytes(8)


    class FirmwareVariationInfoV2(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.refer_to_base = self._io.read_u1()
            self.reserved_1 = self._io.read_bytes(3)
            self.meta_count = self._io.read_u4le()
            self.reserved_2 = self._io.read_bytes(24)


    class ContentMetaAttribute(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.includes_exfat_driver = self._io.read_bits_int_le(1) != 0
            self.rebootless = self._io.read_bits_int_le(1) != 0
            self.compacted = self._io.read_bits_int_le(1) != 0
            self.reserved = self._io.read_bits_int_le(5)


    class AocLegacyExtendedHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.application_id = self._io.read_u8le()
            self.required_application_version = Cnmt.ApplicationVersion(self._io, self, self._root)
            self.reserved = self._io.read_bytes(4)


    class PatchFragmentSet(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.src_content_id = self._io.read_bytes(16)
            self.dst_content_id = self._io.read_bytes(16)
            self.src_size_low = self._io.read_u4le()
            self.src_size_high = self._io.read_u2le()
            self.dst_size_high = self._io.read_u2le()
            self.dst_size_low = self._io.read_u4le()
            self.fragment_count = self._io.read_u2le()
            self.fragment_target_content_type = KaitaiStream.resolve_enum(Cnmt.ContentType, self._io.read_u1())
            self.update_type = KaitaiStream.resolve_enum(Cnmt.UpdateType, self._io.read_u1())
            self.reserved = self._io.read_bytes(4)

        @property
        def src_size(self):
            if hasattr(self, '_m_src_size'):
                return self._m_src_size

            self._m_src_size = ((self.src_size_high << 32) | self.src_size_low)
            return getattr(self, '_m_src_size', None)

        @property
        def dst_size(self):
            if hasattr(self, '_m_dst_size'):
                return self._m_dst_size

            self._m_dst_size = ((self.dst_size_high << 32) | self.dst_size_low)
            return getattr(self, '_m_dst_size', None)


    class ContentInfo(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.id = self._io.read_bytes(16)
            self.size_low = self._io.read_u4le()
            self.size_high = self._io.read_u1()
            self.attr = self._io.read_u1()
            self.type = KaitaiStream.resolve_enum(Cnmt.ContentType, self._io.read_u1())
            self.id_offset = self._io.read_u1()

        @property
        def raw_size(self):
            if hasattr(self, '_m_raw_size'):
                return self._m_raw_size

            self._m_raw_size = ((self.size_high << 32) | self.size_low)
            return getattr(self, '_m_raw_size', None)


    class DeltaExtendedHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.application_id = self._io.read_u8le()
            self.extended_data_size = self._io.read_u4le()
            self.reserved = self._io.read_bytes(4)


    class PatchDeltaHeader(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.src_patch_id = self._io.read_u8le()
            self.dst_patch_id = self._io.read_u8le()
            self.src_version = Cnmt.ApplicationVersion(self._io, self, self._root)
            self.dst_version = Cnmt.ApplicationVersion(self._io, self, self._root)
            self.fragment_set_count = self._io.read_u2le()
            self.reserved_1 = self._io.read_bytes(6)
            self.content_info_count = self._io.read_u2le()
            self.reserved_2 = self._io.read_bytes(6)


    @property
    def extended_data_size(self):
        if hasattr(self, '_m_extended_data_size'):
            return self._m_extended_data_size

        self._m_extended_data_size = (self.extended_header.extended_data_size if self._root.header.content_meta_type == Cnmt.ContentMetaType.system_update else (self.extended_header.extended_data_size if self._root.header.content_meta_type == Cnmt.ContentMetaType.patch else (self.extended_header.extended_data_size if self._root.header.content_meta_type == Cnmt.ContentMetaType.delta else (self.extended_header.extended_data_size if self._root.header.content_meta_type == Cnmt.ContentMetaType.data_patch else 0))))
        return getattr(self, '_m_extended_data_size', None)


