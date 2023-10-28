# This is a generated file! Please edit source .ksy file and use kaitai-struct-compiler to rebuild

import kaitaistruct
from kaitaistruct import KaitaiStruct, KaitaiStream, BytesIO
from enum import Enum


if getattr(kaitaistruct, 'API_VERSION', (0, 9)) < (0, 9):
    raise Exception("Incompatible Kaitai Struct Python API: 0.9 or later is required, but you have %s" % (kaitaistruct.__version__))

class Tik(KaitaiStruct):

    class SignatureType(Enum):
        rsa4096_sha1 = 65536
        rsa2048_sha1 = 65537
        ecc480_sha1 = 65538
        rsa4096_sha256 = 65539
        rsa2048_sha256 = 65540
        ecc480_sha256 = 65541
        hmac160_sha1 = 65542

    class TitlekeyType(Enum):
        common = 0
        personalized = 1

    class LicenseType(Enum):
        permanent = 0
        demo = 1
        trial = 2
        rental = 3
        subscription = 4
        service = 5

    class SectionType(Enum):
        permanent = 1
        subscription = 2
        content = 3
        content_consumption = 4
        access_title = 5
        limited_resource = 6
    def __init__(self, _io, _parent=None, _root=None):
        self._io = _io
        self._parent = _parent
        self._root = _root if _root else self
        self._read()

    def _read(self):
        self.sig_type = KaitaiStream.resolve_enum(Tik.SignatureType, self._io.read_u4le())
        self.signature = self._io.read_bytes((512 if  ((self.sig_type == Tik.SignatureType.rsa4096_sha1) or (self.sig_type == Tik.SignatureType.rsa4096_sha256))  else (256 if  ((self.sig_type == Tik.SignatureType.rsa2048_sha1) or (self.sig_type == Tik.SignatureType.rsa2048_sha256))  else (60 if  ((self.sig_type == Tik.SignatureType.ecc480_sha1) or (self.sig_type == Tik.SignatureType.ecc480_sha256))  else (20 if self.sig_type == Tik.SignatureType.hmac160_sha1 else 0)))))
        self.padding = self._io.read_bytes((60 if  ((self.sig_type == Tik.SignatureType.rsa4096_sha1) or (self.sig_type == Tik.SignatureType.rsa4096_sha256) or (self.sig_type == Tik.SignatureType.rsa2048_sha1) or (self.sig_type == Tik.SignatureType.rsa2048_sha256))  else (64 if  ((self.sig_type == Tik.SignatureType.ecc480_sha1) or (self.sig_type == Tik.SignatureType.ecc480_sha256))  else (40 if self.sig_type == Tik.SignatureType.hmac160_sha1 else 0))))
        self.sig_issuer = (KaitaiStream.bytes_terminate(self._io.read_bytes(64), 0, False)).decode(u"UTF-8")
        self.titlekey_block = self._io.read_bytes(256)
        self.format_version = self._io.read_u1()
        self.titlekey_type = KaitaiStream.resolve_enum(Tik.TitlekeyType, self._io.read_u1())
        self.ticket_version = self._io.read_u2le()
        self.license_type = KaitaiStream.resolve_enum(Tik.LicenseType, self._io.read_u1())
        self.key_generation = self._io.read_u1()
        self.property_mask = Tik.PropertyMask(self._io, self, self._root)
        self.reserved = self._io.read_bytes(8)
        self.ticket_id = self._io.read_u8le()
        self.device_id = self._io.read_u8le()
        self.rights_id = Tik.RightsId(self._io, self, self._root)
        self.account_id = self._io.read_u4le()
        self.sect_total_size = self._io.read_u4le()
        self.sect_hdr_offset = self._io.read_u4le()
        self.sect_hdr_count = self._io.read_u2le()
        self.sect_hdr_entry_size = self._io.read_u2le()
        if  ((self.sect_total_size > 0) and (self.sect_hdr_count > 0) and (self.sect_hdr_entry_size > 0)) :
            self._raw_section_records_block = self._io.read_bytes(self.sect_total_size)
            _io__raw_section_records_block = KaitaiStream(BytesIO(self._raw_section_records_block))
            self.section_records_block = Tik.SectionRecordsBlock(self.sect_hdr_count, _io__raw_section_records_block, self, self._root)


    class Esv1PermanentRecord(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.ref_id = self._io.read_bytes(16)
            self.ref_id_attr = self._io.read_u4le()


    class Esv1AccessTitleRecord(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.access_title_id = self._io.read_u8le()
            self.access_title_mask = self._io.read_u8le()


    class PropertyMask(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.pre_installation = self._io.read_bits_int_le(1) != 0
            self.shared_title = self._io.read_bits_int_le(1) != 0
            self.all_contents = self._io.read_bits_int_le(1) != 0
            self.device_link_independent = self._io.read_bits_int_le(1) != 0
            self.volatile = self._io.read_bits_int_le(1) != 0
            self.elicense_required = self._io.read_bits_int_le(1) != 0
            self.reserved = self._io.read_bits_int_le(10)


    class RightsId(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.title_id = self._io.read_u8be()
            self.reserved = self._io.read_bytes(7)
            self.key_generation = self._io.read_u1()


    class SectionRecord(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.esv2_record = Tik.Esv2SectionRecord(self._io, self, self._root)
            self._raw_esv1_records = []
            self.esv1_records = []
            for i in range(self.esv2_record.record_count):
                _on = self.esv2_record.section_type
                if _on == Tik.SectionType.access_title:
                    self._raw_esv1_records.append(self._io.read_bytes(self.esv2_record.record_size))
                    _io__raw_esv1_records = KaitaiStream(BytesIO(self._raw_esv1_records[i]))
                    self.esv1_records.append(Tik.Esv1AccessTitleRecord(_io__raw_esv1_records, self, self._root))
                elif _on == Tik.SectionType.content_consumption:
                    self._raw_esv1_records.append(self._io.read_bytes(self.esv2_record.record_size))
                    _io__raw_esv1_records = KaitaiStream(BytesIO(self._raw_esv1_records[i]))
                    self.esv1_records.append(Tik.Esv1ContentConsumptionRecord(_io__raw_esv1_records, self, self._root))
                elif _on == Tik.SectionType.limited_resource:
                    self._raw_esv1_records.append(self._io.read_bytes(self.esv2_record.record_size))
                    _io__raw_esv1_records = KaitaiStream(BytesIO(self._raw_esv1_records[i]))
                    self.esv1_records.append(Tik.Esv1LimitedResourceRecord(_io__raw_esv1_records, self, self._root))
                elif _on == Tik.SectionType.permanent:
                    self._raw_esv1_records.append(self._io.read_bytes(self.esv2_record.record_size))
                    _io__raw_esv1_records = KaitaiStream(BytesIO(self._raw_esv1_records[i]))
                    self.esv1_records.append(Tik.Esv1PermanentRecord(_io__raw_esv1_records, self, self._root))
                elif _on == Tik.SectionType.content:
                    self._raw_esv1_records.append(self._io.read_bytes(self.esv2_record.record_size))
                    _io__raw_esv1_records = KaitaiStream(BytesIO(self._raw_esv1_records[i]))
                    self.esv1_records.append(Tik.Esv1ContentRecord(_io__raw_esv1_records, self, self._root))
                elif _on == Tik.SectionType.subscription:
                    self._raw_esv1_records.append(self._io.read_bytes(self.esv2_record.record_size))
                    _io__raw_esv1_records = KaitaiStream(BytesIO(self._raw_esv1_records[i]))
                    self.esv1_records.append(Tik.Esv1SubscriptionRecord(_io__raw_esv1_records, self, self._root))
                else:
                    self.esv1_records.append(self._io.read_bytes(self.esv2_record.record_size))



    class Esv1SubscriptionRecord(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.limit = self._io.read_u4le()
            self.ref_id = self._io.read_bytes(16)
            self.ref_id_attr = self._io.read_u4le()


    class Esv1ContentRecord(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.offset = self._io.read_u4le()
            self.access_mask = self._io.read_bytes(128)


    class Esv2SectionRecord(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.sect_offset = self._io.read_u4le()
            self.record_size = self._io.read_u4le()
            self.section_size = self._io.read_u4le()
            self.record_count = self._io.read_u2le()
            self.section_type = KaitaiStream.resolve_enum(Tik.SectionType, self._io.read_u2le())


    class Esv1ContentConsumptionRecord(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.index = self._io.read_u2le()
            self.code = self._io.read_u2le()
            self.limit = self._io.read_u4le()


    class SectionRecordsBlock(KaitaiStruct):
        def __init__(self, sect_hdr_count, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self.sect_hdr_count = sect_hdr_count
            self._read()

        def _read(self):
            self.section_records = []
            for i in range(self.sect_hdr_count):
                self.section_records.append(Tik.SectionRecord(self._io, self, self._root))



    class Esv1LimitedResourceRecord(KaitaiStruct):
        def __init__(self, _io, _parent=None, _root=None):
            self._io = _io
            self._parent = _parent
            self._root = _root if _root else self
            self._read()

        def _read(self):
            self.limit = self._io.read_u4le()
            self.ref_id = self._io.read_bytes(16)
            self.ref_id_attr = self._io.read_u4le()



