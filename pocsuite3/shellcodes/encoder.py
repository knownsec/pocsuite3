from random import *
import types

from pocsuite3.lib.core.common import create_shellcode
from pocsuite3.lib.core.enums import ENCODER_TPYE


class EncoderError(Exception):
    pass


class Encoder(object):
    def encode(self, payload):
        return payload


class AlphanumericEncoder(Encoder):
    def __init__(self, disallowed_chars="\x00\x0d\x0a", buffer_register='ecx', offset=0):
        self.buffer_register = buffer_register
        self.allowed_chars = self.create_allowed_chars(disallowed_chars)
        self.offset = offset

    @staticmethod
    def create_allowed_chars(bad_chars):
        allowed_chars = range(0x61, 0x7b)+range(0x42, 0x5b) + range(0x30,0x3a)
        for ch in bad_chars:
            if ord(ch) in allowed_chars:
                allowed_chars.remove(ord(ch))
        return allowed_chars

    def encode(self, payload):
        shell = [ord(c) for c in payload]
        reg = self.buffer_register.upper()
        stub =self.create_decoder_stub(reg)
        offset=0
        encoded=""
        while offset < len(shell):
            block = shell[offset: offset+1]
            encoded+=self.encode_byte(block)
            offset+=1

        return stub+encoded+'AA'

    def create_decoder_stub(self, reg):
        decoder = self.gen_decoder_prefix(reg) + (
             "jA"           # push 0x41
             "X"            # pop eax
             "P"           # push eax
             "0A0"          # xor byte [ecx+30], al
             "A"            # inc ecx                        <---
             "kAAQ"         # imul eax, [ecx+42], 51 -> 10       |
             "2AB"          # xor al, [ecx + 42]                 |
             "2BB"          # xor al, [edx + 42]                 |
             "0BB"          # xor [edx + 42], al                 |
             "A"            # inc ecx                            |
             "B"            # inc edx                            |
             "X"            # pop eax                            |
             "P"            # push eax                           |
             "8AB"         # cmp [ecx + 42], al                 |
             "uJ"           # jnz short -------------------------
             "I")             # first encoded char, fixes the above J

        return decoder

    def gen_decoder_prefix(self, reg):
        if self.offset > 32:
            raise Exception("Critical: Offset is greater than 32")

        # use inc ebx as a nop here so we still pad correctly
        if self.offset <= 16:
            nop = 'C' * self.offset
            mod = 'I' * (16 - self.offset) + nop + '7QZ'    # dec ecx,,, push ecx, pop edx
            edxmod = 'J' * (17 - self.offset)
        else:
            mod = 'A' * (self.offset - 16)
            nop = 'C' * (16 - mod.length)
            mod += nop + '7QZ'
            edxmod = 'B' * (17 - (self.offset - 16))

        regprefix = {
            'EAX'   : 'PY' + mod,                         # push eax, pop ecx
            'ECX'   : 'I' + mod,                          # dec ecx
            'EDX'   :  edxmod + nop + '7RY',			   # dec edx,,, push edx, pop ecx
            'EBX'   : 'SY' + mod,                         # push ebx, pop ecx
            'ESP'   : 'TY' + mod,                         # push esp, pop ecx
            'EBP'   : 'UY' + mod,                         # push ebp, pop ecx
            'ESI'   : 'VY' + mod,                         # push esi, pop ecx
            'EDI'   : 'WY' + mod,                         # push edi, pop ecx
        }

        reg = reg.upper()
        if reg not in regprefix.keys():
            raise Exception("Invalid register name")
        return regprefix[reg]

    def encode_byte(self, block):
        # No, not nipple.
        nibble_chars = [[],[],[],[],[],[],[],[],[],[],[],[],[],[],[],[]]
        for ch in self.allowed_chars:
            nibble_chars[ch & 0x0F].append(chr(ch))
        poss_encodings = []
        block_low_nibble = block[0] & 0x0F
        block_high_nibble = block[0] >> 4
        # Get list of chars suitable for expressing lower part of byte
        first_chars = nibble_chars[block_low_nibble]

        # Build a list of possible encodings
        for first_char in first_chars:
            first_high_nibble = ord(first_char[0]) >> 4

            # In the decoding process, the low nibble of the second char gets combined
            # (either ADDed or XORed depending on the encoder) with the high nibble of the first char,
            # and we want the high nibble of our input byte to result
            second_low_nibble = (block_high_nibble^first_high_nibble) & 0x0F

            # Find valid second chars for this first char and add each combination to our possible encodings
            second_chars = nibble_chars[second_low_nibble]
            for second_char in second_chars:
                poss_encodings.append(second_char + first_char)

            if len(poss_encodings) == 0:
                raise Exception("No encoding of 0x%02x possible with limited character set" % block)
            return poss_encodings[randint(0, len(poss_encodings)-1)]


class XorEncoder(Encoder):
    def __init__(self, disallowed_chars=(0x00, 0x0D, 0x0A)):
        self._disallowed_chars = self.set_disallowed_chars(disallowed_chars)
        self._usable_chars = set(range(256)) - self._disallowed_chars

    @staticmethod
    def set_disallowed_chars(chars):
        new_chars = set()
        for char in chars:
            new_chars.add(ord(char))
        return new_chars

    def _get_supported_register_sets(self):
        return []

    def _get_register_set(self, register_set):
        return {}

    def _get_header(self):
        return []

    def _get_payload_size_position(self):
        raise NotImplementedError()

    def _get_xor_key_position(self):
        raise NotImplementedError()

    def _encode_payload(self, payload, register_sets):
        buffer = []
        if isinstance(payload, types.StringTypes):
            buffer.extend(ord(x) & 0xFF for x in payload)
        else:
            buffer.extend(payload)

        for c in self._usable_chars:
            ret = buffer[:]
            for i in range(len(ret)):
                ret[i] = ret[i] ^ c
                if ret[i] in self._disallowed_chars:
                    # break inner for
                    break
            else:
                self._xor_key = c
                # break outer for
                break
        else:
            raise EncoderError('cannot encode')

        return ret

    def _prefix_header(self, payload, register_sets):
        ret = self._get_header()

        payload_len = 0x10000 - len(payload)
        payload_size_pos = self._get_payload_size_position()
        ret[payload_size_pos] = payload_len & 0xFF
        ret[payload_size_pos + 1] = (
            (payload_len & 0xFF00) >> 8)

        xor_key_pos = self._get_xor_key_position()
        for reg_set in register_sets:
            for pos, value in self._get_register_set(reg_set).iteritems():
                ret[pos] = value
            for i, c in enumerate(ret):
                if (c in self._disallowed_chars) and (
                            i != xor_key_pos):
                    # break the inner for
                    break
            else:
                # break the outter for
                break
        else:
            raise EncoderError('cannot encode')

        ret[xor_key_pos] = self._xor_key
        ret.extend(payload)

        return ret

    def encode(self, payload, register_sets=[]):
        """Encode payload.

        :param payload: the payload, either a string or a sequence of bytes
        :param register_sets: a sequence of registers to try in shellcode
        header. Sample names include 'eax', 'edx', and 'ebx'.
        :return: a sequence of encoded bytes
        """
        if len(payload) == 0:
            return []

        if len(payload) > 65535:
            raise EncoderError('cannot encode')

        if not self._usable_chars:
            raise EncoderError('cannot encode')

        if not register_sets:
            register_sets = self._get_supported_register_sets()

        encoded_payload = self._encode_payload(payload, register_sets)
        ret = self._prefix_header(encoded_payload, register_sets)

        return ret

    def encode_to_string(self, payload, register_sets=[]):
        """Encode payload. Return a string.

        :see: encode
        """
        return ''.join(chr(x) for x in self.encode(payload, register_sets))


class FnstenvXorEncoder(XorEncoder):
    """Fnstenv Xor based on
http://www.metasploit.com/sc/x86_fnstenv_xor_byte.asm."""

    HEADER = [
        0xD9, 0xE1,  # fabs
        0xD9, 0x34, 0x24,  # fnstenv [esp]
        0x5A,  # pop edx
        0x5A,  # pop edx
        0x5A,  # pop edx
        0x5A,  # pop edx
        0x80, 0xEA, 0xE7,  # sub dl,-25     (offset to payload)
        0x31, 0xC9,  # xor ecx,ecx
        0x66, 0x81, 0xE9, 0xA1, 0xFE,  # sub cx,-0x15F  (0x15F is size of payload)
        0x80, 0x32, 0x99,  # decode: xor byte [edx],0x99
        0x42,  # inc edx
        0xE2, 0xFA,  # loop decode
        # payload goes here
    ]

    REGISTER_SET = {
        'edx': {5: 0x5A, 6: 0x5A, 7: 0x5A, 8: 0x5A, 9: 0x80, 10: 0xEA,
                20: 0x32, 22: 0x42},
        'eax': {5: 0x58, 6: 0x58, 7: 0x58, 8: 0x58,  # 9: 0x90, 10: 0x2C,
                9: 0x80, 10: 0xE8,
                20: 0x30, 22: 0x40},
        'ebx': {5: 0x5B, 6: 0x5B, 7: 0x5B, 8: 0x5B, 9: 0x80, 10: 0xEB,
                20: 0x33, 22: 0x43},
    }

    XOR_KEY_POSITION = 21

    PAYLOAD_SIZE_POSITION = 17  # 17 and 18

    def _get_supported_register_sets(self):
        return FnstenvXorEncoder.REGISTER_SET.keys()

    def _get_register_set(self, register_set):
        return FnstenvXorEncoder.REGISTER_SET[register_set]

    def _get_header(self):
        return FnstenvXorEncoder.HEADER[:]

    def _get_payload_size_position(self):
        return FnstenvXorEncoder.PAYLOAD_SIZE_POSITION

    def _get_xor_key_position(self):
        return FnstenvXorEncoder.XOR_KEY_POSITION


class JumpCallXorEncoder(XorEncoder):
    HEADER = [
        0xeb, 0x10,  # jmp getdata
        0x5b,  # begin: pop ebx
        0x31, 0xc9,  # xor ecx, ecx
        0x66, 0x81, 0xe9, 0xa1, 0xfe,  # sub cx, -0x15F
        0x80, 0x33, 0x99,  # decode: xor byte[ebx], 0x99
        0x43,  # inc ebx
        0xe2, 0xfa,  # loop decode
        0xeb, 0x05,  # jmp payload
        0xe8, 0xeb, 0xff, 0xff, 0xff,  # getdata: call begin
        #  payload goes here
        #  payload:
    ]

    REGISTER_SET = {
        'eax': {2: 0x58, 11: 0x30, 13: 0x40},
        'ebx': {2: 0x5b, 11: 0x33, 13: 0x43},
        'edx': {2: 0x5a, 11: 0x32, 13: 0x42},
    }

    XOR_KEY_POSITION = 12

    PAYLOAD_SIZE_POSITION = 8

    def _get_header(self):
        return JumpCallXorEncoder.HEADER[:]

    def _get_supported_register_sets(self):
        return JumpCallXorEncoder.REGISTER_SET.keys()

    def _get_register_set(self, register_set):
        return JumpCallXorEncoder.REGISTER_SET[register_set]

    def _get_payload_size_position(self):
        return JumpCallXorEncoder.PAYLOAD_SIZE_POSITION

    def _get_xor_key_position(self):
        return JumpCallXorEncoder.XOR_KEY_POSITION


class CodeEncoders:
    """
        Class with Encoders
    """

    def __init__(self, OS_SYSTEM, OS_TARGET, OS_TARGET_ARCH, BADCHARS):
        self.name = ""
        self.OS_SYSTEM = OS_SYSTEM
        self.OS_TARGET = OS_TARGET
        self.OS_TARGET_ARCH = OS_TARGET_ARCH
        self.BADCHARS = BADCHARS
        self.TMP_DIR = 'tmp'
        self.step = 0
        self.max_steps = 20
        return

    def encode_shellcode(self, _byte_array, encoder_type, debug=0):
        """Encodes shellcode and returns encoded shellcode
        :param encoder_type: const of EncoderType
        """
        encoded_shellcode = ''
        if encoder_type == ENCODER_TPYE.XOR or encoder_type == 1:
            encoded_shellcode = self.xor_encoder(_byte_array, debug)
        elif encoder_type == ENCODER_TPYE.ALPHANUMERIC:
            encoded_shellcode = self.alphanum_encoder(_byte_array, debug)
        elif encoder_type == ENCODER_TPYE.ROT_13:
            encoded_shellcode = self.rot_13_encoder(_byte_array, debug)
        elif encoder_type == ENCODER_TPYE.FNSTENV_XOR:
            encoded_shellcode = self.fnst_encoder(_byte_array, debug)
        elif encoder_type == ENCODER_TPYE.JUMPCALL_XOR:
            encoded_shellcode = self.jumpcall_encoder(_byte_array, debug)
        else:
            print("There no encoder of this type")
            return None
        return encoded_shellcode

    def clean_bad_chars(self, orig_array, payload):
        if not self.BADCHARS:
            print("You must specify some params")
            return None
        for k in self.BADCHARS:
            # Ooops, BadChar found :( Do XOR stuff again with a new random value
            # This could run into an infinite loop in some cases
            if k in payload:
                payload = self.xor_bytes(orig_array)
        return payload

    def xor_bytes(self, byte_array):
        # Randomize first byte
        rnd = randint(1, 255)
        xor1 = (rnd ^ byte_array[0])
        xor2 = (xor1 ^ byte_array[1])
        xor3 = (xor2 ^ byte_array[2])
        xor_array = bytearray()
        xor_array.append(rnd)
        xor_array.append(xor1)
        xor_array.append(xor2)
        xor_array.append(xor3)

        return self.clean_bad_chars(byte_array, xor_array)

    def xor_decoder(self, _shellcode, debug=0):
        """
            The decoder stub is a small chunk of instructions
            that is prepended to the encoded payload.
            When this new payload is executed on the target system,
            the decoder stub executes first and is responsible for
            decoding the original payload data. Once the original
            payload data is decoded, the decoder stub passes execution
            to the original payload. Decoder stubs generally perform a
            reversal of the encoding function, or in the case of an XOR
            obfuscation encoding, simply perform the XOR again against
            the same key value.
        """

        asm_code = """
global _start

section .text
_start:
    jmp get_shellcode

decoder:
    pop esi         ;pointer to shellcode
    push esi        ;save address of shellcode for later execution
    mov edi, esi    ;copy address of shellcode to edi to work with it

    xor eax, eax    ;clear first XOR-operand register
    xor ebx, ebx    ;clear second XOR-operand register
    xor ecx, ecx    ;clear inner loop-counter
    xor edx, edx    ;clear outer loop-counter

loop0:
    mov al, [esi]   ;get first byte from the encoded shellcode
    mov bl, [esi+1] ;get second byte from the encoded shellcode
    xor al, bl      ;xor them (result is saved to eax)
    mov [edi], al   ;save (decode) to the same memory location as the encoded shellcode
    inc edi         ;move decoded-pointer 1 byte onward
    inc esi         ;move encoded-pointer 1 byte onward
    inc ecx         ;increment inner loop-counter
    cmp cl, 0x3     ;dealing with 4byte-blocks!
    jne loop0

    inc esi         ;move encoded-pointer 1 byte onward
    xor ecx, ecx    ;clear inner loop-counter
    add dx, 0x4     ;move outer loop-counter 4 bytes onward
    cmp dx, len     ;check whether the end of the shellcode is reached
    jne loop0

    call [esp]      ;execute decoded shellcode

get_shellcode:
    call decoder
    shellcode: db USER_SHELLCODE
    len:    equ $-shellcode

"""

        asm_code = asm_code.replace('USER_SHELLCODE', _shellcode)
        encoded_shellcode, _ = create_shellcode(asm_code, self.OS_TARGET, self.OS_TARGET_ARCH, debug=debug)
        return encoded_shellcode

    def xor_encoder(self, _byte_arr, debug=0):
        self.step += 1
        """
            Simple xor encoder
            https://www.rcesecurity.com/2015/01/slae-custom-rbix-shellcode-encoder-decoder/
        """

        shellcode = bytearray(_byte_arr)

        # Check whether shellcode is aligned
        if len(shellcode) % 3 == 1:
            shellcode.append(0x90)
            shellcode.append(0x90)
        elif len(shellcode) % 3 == 2:
            shellcode.append(0x90)

        # Loop to split shellcode into 3-byte-blocks
        final = ""
        for i in range(0, len(shellcode), 3):
            tmp_block = bytearray()
            tmp_block.append(shellcode[i])
            tmp_block.append(shellcode[i + 1])
            tmp_block.append(shellcode[i + 2])

            # Do the RND-Insertion and chained XORs
            tmp = self.xor_bytes(tmp_block)

            # Some formatting things for easier use in NASM :)
            for y in tmp:
                if len(str(hex(y))) == 3:
                    final += str(hex(y)[:2]) + "0" + str(hex(y)[2:]) + ","
                else:
                    final += hex(y) + ","

        final = final[:-1]
        encoded_shellcode = self.xor_decoder(final, debug)
        for i in self.BADCHARS:
            if i in encoded_shellcode:
                print("Founding BADHCARS")
                if self.step < self.max_steps:
                    return self.xor_encoder(_byte_arr, debug)
                else:
                    return None
        return encoded_shellcode

    def rot_13_decoder(self, _shellcode, debug=0):
        """
            The decoder stub
        """

        n = 13
        n_hex = hex(n)

        asm_code = """
global _start

section .text

_start:
    jmp short call_decoder

decoder:
    pop esi                     ; shellcode address
    xor ecx, ecx                ; zero out ecx
    mov cl, len                 ; initialize counter

decode:
    cmp byte [esi], %s          ; can we substract 13?
    jl wrap_around              ; nope, we need to wrap around
    sub byte [esi], %s          ; substract 13
    jmp short process_shellcode ; process the rest of the shellcode

wrap_around:
    xor edx, edx                ; zero out edx
    mov dl, %s                  ; edx = 13
    sub dl, byte [esi]          ; 13 - shellcode byte value
    xor ebx,ebx                 ; zero out ebx
    mov bl, 0xff                ; store 0x100 without introducing null bytes
    inc ebx
    sub bx, dx                  ; 256 - (13 - shellcode byte value)
    mov byte [esi], bl          ; write decoded value

process_shellcode:
    inc esi                     ; move to the next byte
    loop decode                 ; decode current byte
    jmp short shellcode         ; execute decoded shellcode

call_decoder:
    call decoder
    shellcode:
        db USER_SHELLCODE
    len: equ $-shellcode
""" % (n_hex, n_hex, n_hex)

        asm_code = asm_code.replace('USER_SHELLCODE', _shellcode)
        encoded_shellcode, _ = create_shellcode(asm_code, self.OS_TARGET, self.OS_TARGET_ARCH, debug=debug)
        return encoded_shellcode

    def rot_13_encoder(self, _shellcode, debug=0):
        """
            ROT13 ("rotate by 13 places", sometimes hyphenated ROT-13)
            is a simple letter substitution cipher that replaces a letter
            with the letter 13 letters after it in the alphabet. ROT13
            is a special case of the Caesar cipher, developed in ancient Rome.
        """

        n = 13  # rot-n
        max_value_without_wrapping = 256 - n

        encoded_shellcode = ""
        db_shellcode = []

        for x in bytearray(_shellcode):
            if x < max_value_without_wrapping:
                encoded_shellcode += '\\x%02x' % (x + n)
                db_shellcode.append('0x%02x' % (x + n))
            else:
                encoded_shellcode += '\\x%02x' % (n - 256 + x)
                db_shellcode.append('0x%02x' % (n - 256 + x))

        # print "Encoded shellcode:\n%s\n" % encoded_shellcode
        # print "DB formatted (paste in .nasm file):\n%s\n" % ','.join(db_shellcode)

        encode_shellcode = self.rot_13_decoder(','.join(db_shellcode), debug)
        return encode_shellcode

    def fnst_encoder(self, _byte_array, debug):
        encoder = FnstenvXorEncoder(self.BADCHARS)
        shellcode = _byte_array
        encoded_shell = encoder.encode_to_string(shellcode)
        if debug:
            print("Len of encoded shellcode:", len(encoded_shell))
        return encoded_shell

    def jumpcall_encoder(self, _byte_array, debug):
        encoder = JumpCallXorEncoder(self.BADCHARS)
        shellcode = _byte_array
        encoded_shell = encoder.encode_to_string(shellcode)
        if debug:
            print("Len of encoded shellcode:", len(encoded_shell))
        return encoded_shell

    def alphanum_encoder(self, byte_str, debug=0, buffer_register='ecx'):
        encoder = AlphanumericEncoder(self.BADCHARS, buffer_register=buffer_register)
        encoded_shell = encoder.encode(byte_str)
        if debug:
            print("Length of encoded shellcode: %s" % len(encoded_shell))
            print(''.join("\\x%02x"%ord(c) for c in encoded_shell))
        return encoded_shell
