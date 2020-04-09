import struct

from scapy.fields import ShortEnumField, FieldLenField, XByteField, BitField, IntField, ShortField, IP6Field, IPField, StrFixedLenField
from scapy.packet import Packet
from scapy.compat import orb
from scapy.utils import strxor

_ATTRIB_TYPE_XOR_MAPPED_ADDRESS = 0x0020
_ATTRIB_TYPE_MAPPED_ADDRESS = 0x0001
AttributeTypes = {
     _ATTRIB_TYPE_MAPPED_ADDRESS: 'MAPPED-ADDRESS',
     0x0002: 'RESPONSE-ADDRESS',
     0x0003: 'CHANGE-ADDRESS',
     0x0004: 'SOURCE-ADDRESS',
     0x0005: 'CHANGED-ADDRESS',
     0x0006: 'USERNAME',
     0x0007: 'PASSWORD',
     0x0008: 'MESSAGE-INTEGRITY',
     0x0009: 'ERROR-CODE',
     0x000A: 'UNKNOWN-ATTRIBUTES',
     0x000B: 'REFLECTED-FROM',
     0x0014: 'REALM',
     0x0015: 'NONCE',
     _ATTRIB_TYPE_XOR_MAPPED_ADDRESS: 'XOR-MAPPED-ADDRESS',
     0x8022: 'SOFTWARE',
     0x8023: 'ALTERNATE-SERVER',
     0x8028: 'FINGERPRINT'
}

STUN_COOKIE_VALUE = 0x2112a442
_SHORT_MASK = 0x2112 # Most significant bytes in host order
_IP_MASK = '\x21\x12\xa4\x42'
_IP6_MASK = _IP_MASK * 4
# See https://tools.ietf.org/html/rfc5389#section-15.1
_FAMILY_IP4 = 0x01
_FAMILY_IP6 = 0x02


def _xor_short(x):
    return x ^ _SHORT_MASK


class _XorShortField(ShortField):
    '''
    X-Port is computed by taking the mapped port in host byte order,
    XOR'ing it with the most significant 16 bits of the magic cookie, and
    then the converting the result to network byte order.
    '''
    def i2m(self, pkt, x):
        x = _xor_short(x)
        return super(_XorShortField, self).i2m(pkt, x)

    def m2i(self, pkt, x):
        x = _xor_short(x)
        return super(_XorShortField, self).m2i(pkt, x)


class _XorIP6Field(IP6Field):
    '''
    Field that XORs the IPv6 value with the magic cookie
    '''
    def i2m(self, pkt, x):
        if x is not None:
            x = strxor(x, _IP6_MASK)
        return super(_XorIP6Field, self).i2m(pkt, x)

    def m2i(self, pkt, x):
        x = strxor(x, _IP6_MASK)
        return super(_XorIP6Field, self).m2i(pkt, x)


class _XorIPField(IPField):
    '''
    Field that XORs the IPv4 value with the magic cookie
    '''
    def i2m(self, pkt, x):
        if x is not None:
            x = strxor(x, _IP_MASK)
        return super(_XorIPField, self).i2m(pkt, x)

    def m2i(self, pkt, x):
        x = strxor(x, _IP_MASK)
        return super(_XorIPField, self).m2i(pkt, x)
        


class StunAttribute(Packet):
    name = "STUN attribute"
    fields_desc = [ 
        ShortEnumField("type", 0, AttributeTypes),
        FieldLenField("length", 0, fmt="H")
    ]

    registered_options = {}

    @property
    def must_understand_type(self):
        return (self.type & 0x8000) > 0 

    @classmethod
    def register_variant(cls):
        cls.registered_options[cls.type.default] = cls

    def extract_padding(self, p):
        '''
        From the spec:

        The value in the length field MUST contain the length of the Value
        part of the attribute, prior to padding, measured in bytes.  Since
        STUN aligns attributes on 32-bit boundaries, attributes whose content
        is not a multiple of 4 bytes are padded with 1, 2, or 3 bytes of
        padding so that its value contains a multiple of 4 bytes.  The
        padding bits are ignored, and may be any value.
        '''
        return p[:self.length], p[self.length:]
    
    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        if _pkt:
            o = struct.unpack("!H", _pkt[0:2])[0]
            cls = cls.registered_options.get(o, cls)
            if cls == XorMappedAddress:
                XorMappedAddress.dispatch_hook(_pkt, *args, **kwargs)
        return cls

class XorMappedAddress(StunAttribute):
    __slots__ = ['ip_address']
    fields_desc = [ 
        ShortEnumField("type", _ATTRIB_TYPE_XOR_MAPPED_ADDRESS, AttributeTypes),
        FieldLenField("length", 0, fmt="H"),
        XByteField("x", 0),
        XByteField("family", 0),
        _XorShortField("port", 0),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        if _pkt:
            if _pkt[0] == _FAMILY_IP4:
                cls = XorMappedIpAddress
            elif _pkt[0] == _FAMILY_IP6:
                cls = XorMappedIp6Address
        return cls

class XorMappedIpAddress(XorMappedAddress):
    fields_desc = [ 
        ShortEnumField("type", _ATTRIB_TYPE_XOR_MAPPED_ADDRESS, AttributeTypes),
        FieldLenField("length", 0, fmt="H"),
        XByteField("x", 0),
        XByteField("family", 0),
        _XorShortField("port", 0),
        _XorIPField("address", '0.0.0.0')
    ]

    def post_dissection(self, pkt):
        self.ip_address = strxor(self.x_address, _IP6_MASK)

class XorMappedIp6Address(XorMappedAddress):
    fields_desc = [ 
        ShortEnumField("type", _ATTRIB_TYPE_XOR_MAPPED_ADDRESS, AttributeTypes),
        FieldLenField("length", 0, fmt="H"),
        XByteField("x", 0),
        XByteField("family", 0),
        _XorShortField("port", 0),
        _XorIP6Field("address", '::')
    ]

class MappedAddress(StunAttribute):
    fields_desc = [
        ShortEnumField("type", _ATTRIB_TYPE_MAPPED_ADDRESS, AttributeTypes),
        FieldLenField("length", 0, fmt="H"),
        XByteField("x", 0),
        XByteField("family", 0),
        ShortField("port", 0),
    ]

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        if _pkt:
            if _pkt[0] == _FAMILY_IP4:
                cls = MappedIpAddress
            elif _pkt[0] == _FAMILY_IP6:
                cls = MappedIp6Address
        return cls

class MappedIpAddress(MappedAddress):
    fields_desc = [
        ShortEnumField("type", _ATTRIB_TYPE_MAPPED_ADDRESS, AttributeTypes),
        FieldLenField("length", 0, fmt="H"),
        XByteField("x", 0),
        XByteField("family", 0),
        ShortField("port", 0),
        IPField("address", None)
    ]

class MappedIp6Address(MappedAddress):
    fields_desc = [
        ShortEnumField("type", _ATTRIB_TYPE_MAPPED_ADDRESS, AttributeTypes),
        FieldLenField("length", 0, fmt="H"),
        XByteField("x", 0),
        XByteField("family", 0),
        ShortField("port", 0),
        IP6Field("address", None)
    ]

class STUN(Packet):
    '''
    According to RFC5389

    https://tools.ietf.org/html/rfc5389#section-6
    '''
    name = "STUN packet"
    fields_desc = [ 
        BitField('reserved', 0, 2),
        BitField('type', 1, 6+8),
        FieldLenField("message_length", 0, fmt="H", length_of="attributes"),
        IntField("cookie", STUN_COOKIE_VALUE), # MUST contain the fixed value 
        StrFixedLenField("transaction_id",None, 12)]

    def extract_padding(self, p):
        return p[:self.message_length], p[self.message_length:]

    def do_dissect_payload(self, s):
        # TODO: how to parse multiple attributes?
        attribute = StunAttribute(s, _internal=1, _underlayer=self)
        self.add_payload(attribute)
