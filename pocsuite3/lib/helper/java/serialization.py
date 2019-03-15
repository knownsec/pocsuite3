import struct


class Constants:
    STREAM_MAGIC = 0xaced
    STREAM_VERSION = 5
    TC_NULL = 0x70
    TC_REFERENCE = 0x71
    TC_CLASSDESC = 0x72
    TC_OBJECT = 0x73
    TC_STRING = 0x74
    TC_ARRAY = 0x75
    TC_CLASS = 0x76
    TC_BLOCKDATA = 0x77
    TC_ENDBLOCKDATA = 0x78
    TC_RESET = 0x79
    TC_BLOCKDATALONG = 0x7A
    TC_EXCEPTION = 0x7B
    TC_LONGSTRING = 0x7C
    TC_PROXYCLASSDESC = 0x7D
    TC_ENUM = 0x7E
    BASE_WIRE_HANDLE = 0x7E0000
    PRIMITIVE_TYPE_CODES = {
        'B': 'byte',
        'C': 'char',
        'D': 'double',
        'F': 'float',
        'I': 'int',
        'J': 'long',
        'S': 'short',
        'Z': 'boolean'
    }
    OBJECT_TYPE_CODES = {
        '[': 'array',
        'L': 'object'
    }
    TYPE_CODES = {}
    TYPE_CODES.update(PRIMITIVE_TYPE_CODES)
    TYPE_CODES.update(OBJECT_TYPE_CODES)

    SC_WRITE_METHOD = 0x01  # if SC_SERIALIZABLE
    SC_BLOCK_DATA = 0x08  # if SC_EXTERNALIZABLE
    SC_SERIALIZABLE = 0x02
    SC_EXTERNALIZABLE = 0x04
    SC_ENUM = 0x10


class Element:
    def __init__(self, stream=""):
        self.stream = stream

    def decode(self, io):
        return self

    def encode(self):
        return ''

    def __str__(self):
        return self.__class__.__name__


class Annotation(Element):
    def __init__(self, stream=None):
        Element.__init__(self, stream)
        self.contents = []

    def decode(self, io):
        while True:
            content = decode_content(io, self.stream)
            self.contents.append(content)
            if content.__class__ is EndBlockData:
                return self
        return self

    def encode(self):
        if not self.contents:
            raise Exception('Failed to serialize Annotation with empty contents')
        encoded = ''
        for content in self.contents:
            encoded += encode_content(content)
        return encoded

    def __str__(self):
        str = '['
        data = [content.__str__() for content in self.contents]
        str += ', '.join(data)
        str += ']'
        return str


class BlockData(Element):
    def __init__(self, stream=None, contents=''):
        Element.__init__(self, stream)
        self.contents = contents
        self.length = len(contents)

    def decode(self, io):
        raw_length = io.read(1)
        if not raw_length:
            raise Exception('Failed to unserialize BlockData')
        self.length = struct.unpack('>B', raw_length)[0]
        if self.length == 0:
            self.contents = ''
        else:
            self.contents = io.read(self.length)
            if not self.contents or len(self.contents) != self.length:
                raise Exception('Failed to unserialize BlockData')
        return self

    def encode(self):
        encoded = struct.pack(">B", self.length)
        encoded += self.contents
        return encoded

    def __str__(self):
        ret = '['
        ret += ', '.join("0x%s" % byte.encode('hex') for byte in self.contents)
        ret += ']'
        return ret


class BlockDataLong(Element):
    def __init__(self, stream=None, contents=''):
        Element.__init__(self, stream)
        self.contents = contents
        self.length = len(contents)

    def decode(self, io):
        raw_length = io.read(4)
        if not raw_length or len(raw_length) != 4:
            raise Exception('Failed to unserialize BlockDataLong')
        self.length = struct.unpack('>i', raw_length)[0]
        if self.length == 0:
            self.contents = ''
        else:
            self.contents = io.read(self.length)
            if not self.contents or len(self.contents) != self.length:
                raise Exception('Failed to unserialize BlockDataLong')
        return self

    def encode(self):
        encoded = struct.pack(">I", [self.length])
        encoded += self.contents
        return encoded

    def __str__(self):
        return self.contents.__str__()


class ClassDesc(Element):
    def __init__(self, stream=None):
        Element.__init__(self, stream)
        self.description = None

    def decode(self, io):
        content = decode_content(io, self.stream)
        allowed_content = [NullReference, NewClassDesc, Reference, ProxyClassDesc]
        if content.__class__ not in allowed_content:
            raise Exception('ClassDesc unserialize failed')
        self.description = content
        return self

    def encode(self):
        encoded = ''
        allowed_contents = [NullReference, NewClassDesc, Reference, ProxyClassDesc]
        if self.description.__class__ not in allowed_contents:
            raise Exception('ClassDesc unserialize failed')
        encoded += encode_content(self.description)
        return encoded

    def __str__(self):
        return print_content(self.description)


class EndBlockData(Element):
    pass


class Field(Element):
    def __init__(self, stream=''):
        Element.__init__(self, stream)
        self.type = ''
        self.name = None
        self.field_type = None

    def decode(self, io):
        code = io.read(1)
        if not code or not self.is_valid(code):
            raise Exception('Failed to unserialize Field')
        self.type = Constants.TYPE_CODES[code]
        utf = Utf(self.stream)
        self.name = utf.decode(io)
        if self.is_object():
            self.field_type = self.decode_field_type(io)
        return self

    def encode(self):
        if self.name.__class__ is not Utf:
            raise Exception('Failed to serialize Field')
        if not self.is_type_valid():
            raise Exception('Failed to serialize Field')
        encoded = ''
        encoded += get_key_by_value(Constants.TYPE_CODES, self.type)
        encoded += self.name.encode()

        if self.is_object():
            encoded += self.encode_field_type()
        return encoded

    def is_type_valid(self):
        if self.type in Constants.TYPE_CODES.values():
            return True
        return False

    def is_primitive(self):
        if self.type in Constants.PRIMITIVE_TYPE_CODES.values():
            return True
        return False

    def is_object(self):
        if self.type in Constants.OBJECT_TYPE_CODES.values():
            return True
        return False

    def is_valid(self, code):
        if code in Constants.TYPE_CODES.keys():
            return True
        return False

    def encode_field_type(self):
        allowed_contents = [Utf, Reference]
        if self.field_type.__class__ not in allowed_contents:
            raise Exception('Failed to serialize Field')
        encoded = encode_content(self.field_type)
        return encoded

    def decode_field_type(self, io):
        allowed_contents = [Utf, Reference]
        type = decode_content(io, self.stream)
        if type.__class__ not in allowed_contents:
            raise Exception('Failed to serialize Field')
        return type

    def __str__(self):
        ret = self.name.__str__()
        if self.is_primitive():
            ret += " (%s)" % self.type
        else:
            ret += " (%s)" % self.field_type
        return ret


class NewArray(Element):
    def __init__(self, stream=''):
        Element.__init__(self, stream)
        self.array_description = None
        self.type = ''
        self.values = []

    def decode(self, io):
        class_desc = ClassDesc(self.stream)
        self.array_description = class_desc.decode(io)
        if self.stream:
            self.stream.add_reference(self)
        self.type = self.array_type()
        values_length = self.decode_values_length(io)
        for i in range(values_length):
            value = self.decode_value(io)
            self.values.append(value)
        return self

    def encode(self):
        if self.array_description.__class__ is not ClassDesc:
            raise Exception('Failed to serialize NewArray')
        encoded = ''
        encoded += self.array_description.encode()
        encoded += struct.pack(">I", len(self.values))
        for value in self.values:
            encoded += self.encode_value(value)
        return encoded

    def decode_values_length(self, io):
        values_length = io.read(4)
        if not values_length or len(values_length) != 4:
            raise Exception('Failed to unserialize NewArray')
        return struct.unpack('>I', values_length)[0]

    def array_type(self):
        if not self.array_description:
            raise Exception('Empty NewArray description')
        if self.array_description.__class__ is not ClassDesc:
            raise Exception('Unsupported NewArray description class')
        desc = self.array_description.description
        if desc.__class__ is Reference:
            ref = desc.handle - Constants.BASE_WIRE_HANDLE
            desc = self.stream.references[ref]
        if desc.class_name.contents[0] != '[':  # array
            raise Exception('Unsupported NewArray description')
        decoded_type = desc.class_name.contents[1]
        if decoded_type in Constants.PRIMITIVE_TYPE_CODES.keys():
            return Constants.PRIMITIVE_TYPE_CODES[decoded_type]
        elif decoded_type == 'L':  # object
            return desc.class_name.contents[2:desc.class_name.contents.index(';')]
        else:
            raise Exception('Unsupported NewArray Type')

    def decode_value(self, io):
        if self.type == 'byte':
            value = io.read(1)
            if not value:
                raise Exception('Failed to deserialize NewArray value')
            value = struct.unpack('>B', value)[0]
        elif self.type == 'char':
            value = io.read(2)
            if not value or len(value) != 2:
                raise Exception('Failed to deserialize NewArray value')
            value = struct.unpack('>ss', value)[0]
        elif self.type == 'boolean':
            value = io.read(1)
            if not value:
                raise Exception('Failed to deserialize NewArray value')
            value = struct.unpack('>B', value)[0]
        elif self.type == 'short':
            value = io.read(2)
            if not value or len(value) != 2:
                raise Exception('Failed to deserialize NewArray value')
            value = struct.unpack('>H', value)[0]
        elif self.type == 'int':
            value = io.read(4)
            if not value or len(value) != 4:
                raise Exception('Failed to deserialize NewArray value')
            value = struct.unpack('>I', value)[0]
        elif self.type == 'long':
            value = io.read(8)
            if not value or len(value) != 8:
                raise Exception('Failed to deserialize NewArray value')
            value = struct.unpack('>Q', value)[0]
        elif self.type == 'float':
            value = io.read(4)
            if not value or len(value) != 4:
                raise Exception('Failed to deserialize NewArray value')
            value = struct.unpack('>F', value)[0]
        elif self.type == 'double':
            value = io.read(8)
            if not value or len(value) != 8:
                raise Exception('Failed to deserialize NewArray value')
            value = struct.unpack('>D', value)[0]
        else:
            value = decode_content(io, self.stream)
        return value

    def encode_value(self, value):
        if self.type == 'byte':
            res = struct.pack('>B', value)
        elif self.type == 'char':
            res = struct.pack('>ss', value)
        elif self.type == 'double':
            res = struct.pack('>D', value)
        elif self.type == 'float':
            res = struct.pack('>F', value)
        elif self.type == 'int':
            res = struct.pack('>I', value)
        elif self.type == 'long':
            res = struct.pack('>Q', value)
        elif self.type == 'short':
            res = struct.pack('>H', value)
        elif self.type == 'boolean':
            res = struct.pack('>B', value)
        elif self.type.__class__ is Element:
            res = value.encode()
        else:
            res = encode_content(value)
        return res

    def __str__(self):
        ret = self.type.__str__() + ', '
        ret += '\n'.join(value.__str__() for value in self.values)
        return ret


class NewClass(Element):
    def __init__(self, stream=''):
        Element.__init__(self, stream)
        self.class_description = None

    def decode(self, io):
        class_desc = ClassDesc(self.stream)
        self.class_description = class_desc.decode(io)
        if self.stream:
            self.stream.add_reference(self)
        return self

    def encode(self):
        if self.class_description.__class__ != ClassDesc:
            raise Exception('Failed to serialize NewClass')
        encoded = ''
        encoded += self.class_description.encode()
        return encoded

    def __str__(self):
        return self.class_description.__str__()


class NewClassDesc(Element):
    def __init__(self, stream=''):
        Element.__init__(self, stream)
        self.class_name = ""
        self.serial_version = 0
        self.flags = 0
        self.fields = []
        self.class_annotation = None
        self.super_class = None

    def decode(self, io):
        utf = Utf(self.stream)
        self.class_name = utf.decode(io)
        self.serial_version = self.decode_serial_version(io)
        if self.stream:
            self.stream.add_reference(self)
        self.flags = self.decode_flags(io)
        field_length = self.decode_fields_length(io)
        for i in range(0, field_length):
            temp_field = Field(self.stream)
            field = temp_field.decode(io)
            self.fields.append(field)
        annotation = Annotation(self.stream)
        super_class = ClassDesc(self.stream)
        self.class_annotation = annotation.decode(io)
        self.super_class = super_class.decode(io)
        return self

    def encode(self):
        if self.class_name.__class__ is not Utf \
                and self.class_annotation.__class__ is not Annotation \
                and self.super_class.__class__ is not ClassDesc:
            raise Exception('Filed to serialize NewClassDesc')
        encoded = ''
        encoded += self.class_name.encode()
        encoded += struct.pack('>Q', self.serial_version)
        encoded += struct.pack('>B', self.flags)
        encoded += struct.pack('>H', len(self.fields))
        for field in self.fields:
            encoded += field.encode()
        encoded += self.class_annotation.encode()
        encoded += self.super_class.encode()
        return encoded

    def decode_serial_version(self, io):
        raw_serial = io.read(8)
        if not raw_serial or len(raw_serial) != 8:
            raise Exception('Failed to unserialize ClassDescription')
        return struct.unpack('>Q', raw_serial)[0]

    def decode_flags(self, io):
        raw_flags = io.read(1)
        if not raw_flags:
            raise Exception('Failed to unserialize ClassDescription')
        return struct.unpack('>b', raw_flags)[0]

    def decode_fields_length(self, io):
        fields_length = io.read(2)
        if not fields_length or len(fields_length) != 2:
            raise Exception('Failed to unserialize ClassDescription')
        return struct.unpack('>h', fields_length)[0]

    def __str__(self):
        ret = self.class_name.__str__() + ", ["
        ret += ', '.join(field.__str__() for field in self.fields)
        ret += ']'

        # if self.super_class.description.__class__ is NewClassDesc:
        #     ret += ", super_class: " + self.super_class.description.class_name.__str__()
        # elif self.super_class.description.__class__ is Reference:
        #     ret += ", super_class: " + self.super_class.description.__str__()
        return ret


class NewEnum(Element):
    def __init__(self, stream=''):
        Element.__init__(self, stream)
        self.enum_description = None
        self.constant_name = None

    def decode(self, io):
        class_desc = ClassDesc(self.stream)
        self.enum_description = class_desc.decode(io)
        if self.stream:
            self.stream.add_reference(self)
        self.constant_name = self.decode_constant_name(io)
        return self

    def encode(self):
        if self.enum_description.__class__ is not ClassDesc or self.constant_name.__class__ is not Utf:
            raise Exception('Failed to serialize EnumDescription')
        encoded = ''
        encoded += self.enum_description.encode()
        encoded += encode_content(self.constant_name)
        return encoded

    def decode_constant_name(self, io):
        content = decode_content(io, self.stream)
        if content.__class__ is not Utf:
            raise Exception('Failed to unserialize NewEnum')
        return content


class NewObject(Element):
    def __init__(self, stream=None):
        Element.__init__(self, stream)
        self.class_desc = None
        self.class_data = []

    def decode(self, io):
        class_desc = ClassDesc(self.stream)
        self.class_desc = class_desc.decode(io)
        if self.stream:
            self.stream.add_reference(self)

        if self.class_desc.description.__class__ is NewClassDesc:
            self.class_data = self.decode_class_data(io, self.class_desc.description)
        elif self.class_desc.description.__class__ is Reference:
            ref = self.class_desc.description.handle - Constants.BASE_WIRE_HANDLE
            self.class_data = self.decode_class_data(io, self.stream.references[ref])
        return self

    def encode(self):
        if self.class_desc.__class__ is not ClassDesc:
            raise Exception('Failed to serialize NewObject')
        encoded = ''
        encoded += self.class_desc.encode()
        for value in self.class_data:
            if type(value) is list:
                encoded += self.encode_value(value)
            else:
                encoded += encode_content(value)
        return encoded

    def decode_class_data(self, io, my_class_desc):
        values = []
        if my_class_desc.super_class.description.__class__ is not NullReference:
            if my_class_desc.super_class.description.__class__ is Reference:
                ref = my_class_desc.super_class.description.handle - Constants.BASE_WIRE_HANDLE
                values.extend(self.decode_class_data(io, self.stream.references[ref]))
            else:
                values.extend(self.decode_class_data(io, my_class_desc.super_class.description))
        values.extend(self.decode_class_fields(io, my_class_desc))
        return values

    def decode_class_fields(self, io, my_class_desc):
        values = []
        for field in my_class_desc.fields:
            if field.is_primitive():
                values.append(self.decode_value(io, field.type))
            else:
                content = decode_content(io, self.stream)
                values.append(content)
        return values

    def decode_value(self, io, type):
        if type == 'byte':
            value_raw = io.read(1)
            val = struct.unpack(">b", value_raw)[0]
            value = ['byte', val]
        elif type == 'char':
            value_raw = io.read(2)
            val = struct.unpack(">h", value_raw)[0]
            value = ['char', val]
        elif type == 'boolean':
            value_raw = io.read(1)
            val = struct.unpack(">B", value_raw)[0]
            value = ['boolean', val]
        elif type == 'short':
            value_raw = io.read(2)
            val = struct.unpack(">h", value_raw)[0]
            value = ['short', val]
        elif type == 'int':
            value_raw = io.read(4)
            val = struct.unpack(">i", value_raw)[0]
            value = ['int', val]
        elif type == 'long':
            value_raw = io.read(8)
            val = struct.unpack(">q", value_raw)[0]
            value = ['long', val]
        elif type == 'float':
            value_raw = io.read(4)
            val = struct.unpack(">f", value_raw)[0]
            value = ['float', val]
        elif type == 'double':
            value_raw = io.read(8)
            val = struct.unpack(">d", value_raw)[0]
            value = ['double', val]
        else:
            raise Exception("Unknown typecode: %s" % type)
        return value

    def encode_value(self, value):
        res = ''
        if value[0] == 'byte':
            res = struct.pack('>b', value[1])
        elif value[0] == 'char':
            res = struct.pack('>h', value[1])
        elif value[0] == 'double':
            res = struct.pack('>d', value[1])
        elif value[0] == 'float':
            res = struct.pack('>f', value[1])
        elif value[0] == 'int':
            res = struct.pack('>i', value[1])
        elif value[0] == 'long':
            res = struct.pack('>Q', value[1])
        elif value[0] == 'short':
            res = struct.pack('>h', value[1])
        elif value[0] == 'boolean':
            res = struct.pack('>B', value[1])
        else:
            raise Exception('Unsupported NewArray type')
        return res

    def __str__(self):
        ret = ''
        if self.class_desc.description.__class__ is NewClassDesc:
            ret += self.class_desc.description.class_name.__str__()
        elif self.class_desc.description.__class__ is ProxyClassDesc:
            ret += ','.join(iface.contents.__str__() for iface in self.class_desc.description.interfaces)
        elif self.class_desc.description.__class__ is Reference:
            ret += hex(self.class_desc.description.handle - Constants.BASE_WIRE_HANDLE)
        ret += ' => {'
        data_str = ', '.join(data.__str__() for data in self.class_data)
        ret += data_str
        ret += '}'
        return ret


class NullReference(Element):
    pass


class ProxyClassDesc(Element):
    def __init__(self, stream=''):
        Element.__init__(self, stream)
        self.interfaces = []
        self.class_annotation = None
        self.super_class = None

    def decode(self, io):
        if self.stream:
            self.stream.add_reference(self)
        interfaces_length = self.decode_interfaces_length(io)
        for i in range(0, interfaces_length):
            utf = Utf(self.stream)
            interface = utf.decode(io)
            self.interfaces.append(interface)
        annotation = Annotation(self.stream)
        super_class = ClassDesc(self.stream)
        self.class_annotation = annotation.decode(io)
        self.super_class = super_class.decode(io)
        return self

    def encode(self):
        if self.class_annotation.__class__ is not Annotation and self.super_class.__class__ is not ClassDesc:
            raise Exception('Failed to serialize ProxyClassDesc')
        encoded = ''
        encoded += struct.pack('>I', len(self.interfaces))
        for interface in self.interfaces:
            encoded += interface.encode()
        encoded += self.class_annotation.encode()
        encoded += self.super_class.encode()
        return encoded

    def decode_interfaces_length(self, io):
        field_length = io.read(4)
        if not field_length or len(field_length) != 4:
            raise Exception('Failed to unserialize ProxyClassDesc')
        return struct.unpack('>I', field_length)[0]

    def __str__(self):
        ret = '['
        interfaces_str = ', '.join(interface.__str__() for interface in self.interfaces)
        ret += interfaces_str + ']'
        if self.super_class.description.__class__ is NewClassDesc:
            ret += ", super_class: " + self.super_class.description.class_name.__str__()
        elif self.super_class.description.__class__ is Reference:
            ret += ", super_class: " + self.super_class.description.__str__()
        return ret


class Reference(Element):
    def __init__(self, stream=''):
        Element.__init__(self, stream)
        self.handle = 0

    def decode(self, io):
        handle_raw = io.read(4)
        if not handle_raw or len(handle_raw) != 4:
            raise Exception('Failed to unserialize Reference')
        self.handle = struct.unpack('>I', handle_raw)[0]
        return self

    def encode(self):
        if self.handle < Constants.BASE_WIRE_HANDLE:
            raise Exception('Failed to serialize Reference')
        encoded = ""
        encoded += struct.pack('>I', self.handle)
        return encoded

    def __str__(self):
        return hex(self.handle)


class Reset(Element):
    pass


class Stream(Element):
    def __init__(self, stream=None):
        Element.__init__(self, stream)
        self.magic = Constants.STREAM_MAGIC
        self.version = Constants.STREAM_VERSION
        self.contents = []
        self.references = []

    def decode(self, io):
        self.magic = self.decode_magic(io)
        self.version = self.decode_version(io)
        try:
            while 1:
                content = decode_content(io, self)
                self.contents.append(content)
        except EOFError:
            pass
        return self

    def encode(self):
        encoded = ''
        encoded += struct.pack('>H', self.magic)
        encoded += struct.pack('>H', self.version)
        for content in self.contents:
            encoded += encode_content(content)
        return encoded

    def add_reference(self, ref):
        self.references.append(ref)

    def decode_magic(self, io):
        magic = io.read(2)
        if magic and len(magic) == 2 and struct.unpack('>H', magic)[0] == Constants.STREAM_MAGIC:
            return Constants.STREAM_MAGIC
        else:
            raise Exception("Failed to unserialize Stream")

    def decode_version(self, io):
        version = io.read(2)
        if version and struct.unpack('>H', version)[0] == Constants.STREAM_VERSION:
            return Constants.STREAM_VERSION
        else:
            raise Exception('Failed to unserialize Stream')


class Utf(Element):
    def __init__(self, stream='', contents=''):
        Element.__init__(self, stream)
        self.contents = contents
        self.length = len(contents)

    def decode(self, io):
        raw_length = io.read(2)
        if not raw_length or len(raw_length) != 2:
            raise Exception('Failed to unserialize Utf')
        self.length = struct.unpack('>H', raw_length)[0]
        if self.length == 0:
            self.contents = ""
        else:
            self.contents = io.read(self.length)
            if not self.contents or len(self.contents) != self.length:
                raise Exception('Failed to unserialize Utf')
        return self

    def encode(self):
        encoded = struct.pack('>H', self.length)
        encoded += self.contents
        return encoded

    def __str__(self):
        return self.contents


class LongUtf(Utf):
    def decode(self, io):
        raw_length = io.read(8)
        if not raw_length or len(raw_length) != 8:
            raise Exception('Failed to unserialize LongUtf')
        self.length = struct.unpack('>Q', raw_length)[0]
        if self.length == 0:
            self.contents = ""
        else:
            self.contents = io.read(self.length)
            if not self.contents or len(self.contents) != self.length:
                raise Exception('Failed to unserialize LongUtf')
        return self

    def encode(self):
        encoded = struct.pack('>Q', [self.length])
        encoded += self.contents
        return encoded


def decode_content(io, stream):
    opcode = io.read(1)
    if not opcode:
        raise EOFError()
    opcode = struct.unpack('>B', opcode)[0]
    if opcode == Constants.TC_BLOCKDATA:
        block_data = BlockData(stream)
        content = block_data.decode(io)
    elif opcode == Constants.TC_BLOCKDATALONG:
        block_data_long = BlockDataLong(stream)
        content = block_data_long.decode(io)
    elif opcode == Constants.TC_ENDBLOCKDATA:
        end_bd = EndBlockData(stream)
        content = end_bd.decode(io)
    elif opcode == Constants.TC_OBJECT:
        new_object = NewObject(stream)
        content = new_object.decode(io)
    elif opcode == Constants.TC_CLASS:
        new_class = NewClass(stream)
        content = new_class.decode(io)
    elif opcode == Constants.TC_ARRAY:
        new_array = NewArray(stream)
        content = new_array.decode(io)
    elif opcode == Constants.TC_STRING:
        utf = Utf(stream)
        content = utf.decode(io)
        if stream:
            stream.add_reference(content)
    elif opcode == Constants.TC_LONGSTRING:
        long_utf = LongUtf(stream)
        content = long_utf.decode(io)
        if stream:
            stream.add_reference(content)
    elif opcode == Constants.TC_ENUM:
        new_enum = NewEnum(stream)
        content = new_enum.decode(io)
    elif opcode == Constants.TC_CLASSDESC:
        new_class_desc = NewClassDesc(stream)
        content = new_class_desc.decode(io)
    elif opcode == Constants.TC_PROXYCLASSDESC:
        proxy = ProxyClassDesc(stream)
        content = proxy.decode(io)
    elif opcode == Constants.TC_REFERENCE:
        ref = Reference(stream)
        content = ref.decode(io)
    elif opcode == Constants.TC_NULL:
        ref = NullReference(stream)
        content = ref.decode(io)
    elif opcode == Constants.TC_EXCEPTION:
        raise Exception("Failed to unserialize unsupported TC_EXCEPTION content")
    elif opcode == Constants.TC_RESET:
        reset = Reset(stream)
        content = reset.decode(io)
    else:
        raise Exception('Failed to unserialize content')
    return content


def encode_content(content):
    # TODO encode content
    encoded = ''
    if content.__class__ is BlockData:
        encoded += struct.pack('>B', Constants.TC_BLOCKDATA)
    elif content.__class__ is BlockDataLong:
        encoded += struct.pack('>B', Constants.TC_BLOCKDATALONG)
    elif content.__class__ is EndBlockData:
        encoded += struct.pack('>B', Constants.TC_ENDBLOCKDATA)
    elif content.__class__ is NewObject:
        encoded += struct.pack('>B', Constants.TC_OBJECT)
    elif content.__class__ is NewClass:
        encoded += struct.pack('>B', Constants.TC_CLASS)
    elif content.__class__ is NewArray:
        encoded += struct.pack('>B', Constants.TC_ARRAY)
    elif content.__class__ is Utf:
        encoded += struct.pack('>B', Constants.TC_STRING)
    elif content.__class__ is LongUtf:
        encoded += struct.pack('>B', Constants.TC_LONGSTRING)
    elif content.__class__ is NewEnum:
        encoded += struct.pack('>B', Constants.TC_ENUM)
    elif content.__class__ is NewClassDesc:
        encoded += struct.pack('>B', Constants.TC_CLASSDESC)
    elif content.__class__ is ProxyClassDesc:
        encoded += struct.pack('>B', Constants.TC_PROXYCLASSDESC)
    elif content.__class__ is NullReference:
        encoded += struct.pack('>B', Constants.TC_NULL)
    elif content.__class__ is Reset:
        encoded += struct.pack('>B', Constants.TC_RESET)
    elif content.__class__ is Reference:
        encoded += struct.pack('>B', Constants.TC_REFERENCE)
    else:
        raise Exception('Failed to serialize content')
    encoded += content.encode()
    return encoded


def print_content(content):
    ret = ''
    if content.__class__ is BlockData:
        ret += "%s {%s}" % (print_class(content), str(content))
    elif content.__class__ is BlockDataLong:
        ret += "%s {%s}" % (print_class(content), str(content))
    elif content.__class__ is EndBlockData:
        ret += print_class(content)
    elif content.__class__ is NewObject:
        ret += "%s {%s}" % (print_class(content), str(content))
    elif content.__class__ is ClassDesc:
        ret += "%s {%s}" % (print_class(content), str(content))
    elif content.__class__ is NewClass:
        ret += "%s {%s}" % (print_class(content), str(content))
    elif content.__class__ is NewArray:
        ret += "%s {%s}" % (print_class(content), str(content))
    elif content.__class__ is Utf:
        ret += "%s {%s}" % (print_class(content), str(content))
    elif content.__class__ is LongUtf:
        ret += "%s {%s}" % (print_class(content), str(content))
    elif content.__class__ is NewEnum:
        ret += "%s {%s}" % (print_class(content), str(content))
    elif content.__class__ is NewClassDesc:
        ret += "%s {%s}" % (print_class(content), str(content))
    elif content.__class__ is ProxyClassDesc:
        ret += "%s {%s}" % (print_class(content), str(content))
    elif content.__class__ is NullReference:
        ret += print_class(content)
    elif content.__class__ is Reset:
        ret += print_class(content)
    elif content.__class__ is Reference:
        ret += "%s {%s}" % (print_class(content), str(content))
    else:
        raise Exception('Failed to serialize content')
    return ret


def print_class(content):
    return content.__class__.__name__


def get_key_by_value(dictionary, search_value):
    for key, value in dictionary.iteritems():
        if value == search_value:
            return key
    raise Exception("There is no selected element in dictionary")
