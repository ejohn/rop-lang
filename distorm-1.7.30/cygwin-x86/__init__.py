# :[diStorm64}: Python binding
# Copyright (c) 2009, Mario Vilas
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright notice,
#       this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice,this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the copyright holder nor the names of its
#       contributors may be used to endorse or promote products derived from
#       this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

info = (
    ":[diStorm64}: by Gil Dabah, http://ragestorm.net/distorm/\n"
    "Python binding by Mario Vilas, http://breakingcode.wordpress.com/\n"
)

__revision__ = "$Id: __init__.py 376 2009-08-24 16:42:29Z QvasiModo $"

__all__ = [
    'Decode',
    'DecodeGenerator',
    'Decode16Bits',
    'Decode32Bits',
    'Decode64Bits',
]

from ctypes import *
from exceptions import *
from os.path import split, join

#==============================================================================
# Load the diStorm library

SUPPORT_64BIT_OFFSET = True
_OffsetType = c_ulonglong

try:
    _distorm_path = split(__file__)[0]
    _distorm_file = join(_distorm_path, 'distorm64.dll')
    _distorm      = cdll.LoadLibrary(_distorm_file)
except OSError:
    raise ImportError, "Error loading diStorm: dynamic link library not found"

try:
    distorm_decode  = _distorm.distorm_decode64
except AttributeError:
    raise ImportError, "Error loading diStorm: exported function not found"

#==============================================================================
# diStorm C interface

MAX_TEXT_SIZE       = 60
MAX_INSTRUCTIONS    = 1000

DECRES_NONE         = 0
DECRES_SUCCESS      = 1
DECRES_MEMORYERR    = 2
DECRES_INPUTERR     = 3

_DecodeType   = c_uint
_DecodeResult = c_uint

class _WString (Structure):
    _fields_ = [
        ('length',  c_uint),                    # unused
        ('p',       c_char * MAX_TEXT_SIZE),
    ]

class _DecodedInst (Structure):
    _fields_ = [
        ('mnemonic',        _WString),
        ('operands',        _WString),
        ('instructionHex',  _WString),
        ('size',            c_uint),
        ('offset',          _OffsetType),
    ]

distorm_decode.restype    = _DecodeResult
distorm_decode.argtypes   = [
                            _OffsetType,            # codeOffset
                            c_void_p,               # code
                            c_int,                  # codeLen
                            _DecodeType,            # dt
                            POINTER(_DecodedInst),  # result
                            c_uint,                 # maxInstructions
                            POINTER(c_uint)         # usedInstructionsCount
                            ]

#==============================================================================
# diStorm Python interface

Decode16Bits    = 0     # 80286 decoding
Decode32Bits    = 1     # IA-32 decoding
Decode64Bits    = 2     # AMD64 decoding

OffsetTypeSize  = sizeof(_OffsetType) * 8       # XXX why 8 ???

def DecodeGenerator(codeOffset, code, dt = Decode32Bits):
    """
    @type  codeOffset: long
    @param codeOffset: Memory address where the code is located.
        This is B{not} an offset into the code!
        It's the actual memory address where it was read from.

    @type  code: str
    @param code: Code to disassemble.

    @type  dt: int
    @param dt: Disassembly type. Can be one of the following:

         * L{Decode16Bits}: 80286 decoding

         * L{Decode32Bits}: IA-32 decoding

         * L{Decode64Bits}: AMD64 decoding

    @rtype:  generator of tuple( long, int, str, str )
    @return: Generator of tuples. Each tuple represents an assembly instruction
        and contains:
         - Memory address of instruction.
         - Size of instruction in bytes.
         - Disassembly line of instruction.
         - Hexadecimal dump of instruction.

    @raise ValueError: Invalid arguments.
    """

    # Sanitize the code parameter.
    code = str(code)

    # Stop the iteration if there's no code to disassemble.
    if code == '':
        return

    # Sanitize the codeOffset parameter.
    if not codeOffset:
        codeOffset = 0

    # Check the validity of the decode type.
    if dt not in (Decode16Bits, Decode32Bits, Decode64Bits):
        raise ValueError, "Invalid decode type value: %r" % (dt,)

    # Prepare input buffer.
    codeLen     = len(code)                     # total bytes to disassemble
    code        = create_string_buffer(code)    # allocate code buffer
    p_code      = addressof(code)               # pointer to code buffer

    # Prepare output buffer.
    l_result    = MAX_INSTRUCTIONS              # length of output array
    result      = (_DecodedInst * l_result)()   # allocate output array
    p_result    = pointer(result)               # pointer to output array
    p_result    = cast(p_result, POINTER(_DecodedInst))

    # Prepare used instructions counter.
    usedInstructionsCount   = c_uint(0)
    p_usedInstructionsCount = byref(usedInstructionsCount)

    # Loop while we have code left to disassemble.
    while codeLen > 0:

        # Call the decode function.
        status = distorm_decode(codeOffset, p_code, min(codeLen, l_result), dt,
                            p_result, l_result, p_usedInstructionsCount)
        if status == DECRES_INPUTERR:
            raise ValueError, "Invalid arguments passed to distorm_decode()"
        if status == DECRES_MEMORYERR:
            raise MemoryError, "Not enough memory to disassemble"
        used = usedInstructionsCount.value
        if not used:
            break
##            raise AssertionError, "Internal error while disassembling"

        # Yield each decoded instruction but the last one.
        for index in xrange(used - 1):
            di   = result[index]
            asm  = '%s %s' % (di.mnemonic.p, di.operands.p)
            pydi = ( di.offset, di.size, asm, di.instructionHex.p )
            yield pydi

        # Continue decoding from the last instruction found.
        # This prevents truncating the last instruction.
        # If there are no more instructions to decode, yield
        # the last one and stop the iteration.
        di         = result[used - 1]
        delta      = di.offset - codeOffset
        if delta <= 0:
            asm  = '%s %s' % (di.mnemonic.p, di.operands.p)
            pydi = ( di.offset, di.size, asm, di.instructionHex.p )
            yield pydi
            break
        codeOffset = codeOffset + delta
        p_code     = p_code + delta
        codeLen    = codeLen - delta

        # Reset the used instructions counter.
        usedInstructionsCount.value = 0


def Decode(offset, code, type = Decode32Bits):
    """
    @type  offset: long
    @param offset: Memory address where the code is located.
        This is B{not} an offset into the code!
        It's the actual memory address where it was read from.

    @type  code: str
    @param code: Code to disassemble.

    @type  type: int
    @param type: Disassembly type. Can be one of the following:

         * L{Decode16Bits}: 80286 decoding

         * L{Decode32Bits}: IA-32 decoding

         * L{Decode64Bits}: AMD64 decoding

    @rtype:  list of tuple( long, int, str, str )
    @return: List of tuples. Each tuple represents an assembly instruction
        and contains:
         - Memory address of instruction.
         - Size of instruction in bytes.
         - Disassembly line of instruction.
         - Hexadecimal dump of instruction.

    @raise ValueError: Invalid arguments.
    """
    return list( DecodeGenerator(offset, code, type) )