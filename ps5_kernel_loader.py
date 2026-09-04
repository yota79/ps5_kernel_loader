#!/usr/bin/env python

from idaapi import *
from idc import *

import idaapi
import idc
import struct

try:
    import ida_bytes
    import ida_funcs
    import ida_name
    import ida_segment
except ImportError:
    ida_bytes = idaapi
    ida_funcs = idaapi
    ida_name = idaapi
    ida_segment = idaapi


class Binary:

    __slots__ = ('EI_MAGIC', 'EI_CLASS', 'EI_DATA', 'EI_VERSION',
                 'EI_OSABI', 'EI_PADDING', 'EI_ABIVERSION', 'EI_SIZE',
                 'E_TYPE', 'E_MACHINE', 'E_VERSION', 'E_START_ADDR',
                 'E_PHT_OFFSET', 'E_SHT_OFFSET', 'E_FLAGS', 'E_SIZE',
                 'E_PHT_SIZE', 'E_PHT_COUNT', 'E_SHT_SIZE', 'E_SHT_COUNT',
                 'E_SHT_INDEX', 'E_SEGMENTS', 'E_SECTIONS', 'FILE_BASE', 'VALID')


    ET_NONE                   = 0x0
    ET_REL                    = 0x1
    ET_EXEC                   = 0x2
    ET_DYN                    = 0x3
    ET_CORE                   = 0x4
    ET_SCE_EXEC               = 0xfe00
    ET_SCE_REPLAY_EXEC        = 0xfe01
    ET_SCE_RELEXEC            = 0xfe04
    ET_SCE_STUBLIB            = 0xfe0c
    ET_SCE_DYNEXEC            = 0xfe10
    ET_SCE_DYNAMIC            = 0xfe18
    ET_LOPROC                 = 0xff00
    ET_HIPROC                 = 0xffff


    EM_X86_64                 = 0x3e


    ELFOSABI_FREEBSD          = 0x9


    KERNEL_MIN                = 0xFFFFFFFF80000000

    PS4_KERNEL_BASE           = 0xFFFFFFFF82200000

    WRAPPER_OFFSETS           = (0x0, 0x1000)

    def __init__(self, f, base = None):

        self.VALID     = False
        self.FILE_BASE = 0x0
        self.E_SEGMENTS = []
        self.E_SECTIONS = []

        bases = Binary.WRAPPER_OFFSETS if base is None else (base,)

        for candidate in bases:
            if self.parse(f, candidate):
                self.VALID = True
                return

    def parse(self, f, base):

        try:
            f.seek(base)

            self.EI_MAGIC      = struct.unpack('4s', f.read(4))[0]
            if self.EI_MAGIC != b'\x7fELF':
                return False

            self.EI_CLASS      = struct.unpack('<B', f.read(1))[0]
            self.EI_DATA       = struct.unpack('<B', f.read(1))[0]
            self.EI_VERSION    = struct.unpack('<B', f.read(1))[0]
            self.EI_OSABI      = struct.unpack('<B', f.read(1))[0]
            self.EI_ABIVERSION = struct.unpack('<B', f.read(1))[0]
            self.EI_PADDING    = struct.unpack('6x', f.read(6))
            self.EI_SIZE       = struct.unpack('<B', f.read(1))[0]

            
            self.E_TYPE        = struct.unpack('<H', f.read(2))[0]
            self.E_MACHINE     = struct.unpack('<H', f.read(2))[0]
            self.E_VERSION     = struct.unpack('<I', f.read(4))[0]
            self.E_START_ADDR  = struct.unpack('<Q', f.read(8))[0]
            self.E_PHT_OFFSET  = struct.unpack('<Q', f.read(8))[0]
            self.E_SHT_OFFSET  = struct.unpack('<Q', f.read(8))[0]
            self.E_FLAGS       = struct.unpack('<I', f.read(4))[0]
            self.E_SIZE        = struct.unpack('<H', f.read(2))[0]
            self.E_PHT_SIZE    = struct.unpack('<H', f.read(2))[0]
            self.E_PHT_COUNT   = struct.unpack('<H', f.read(2))[0]
            self.E_SHT_SIZE    = struct.unpack('<H', f.read(2))[0]
            self.E_SHT_COUNT   = struct.unpack('<H', f.read(2))[0]
            self.E_SHT_INDEX   = struct.unpack('<H', f.read(2))[0]
        except Exception:
            return False


        if self.EI_CLASS != 0x2 or self.EI_DATA != 0x1:
            return False
        if self.E_MACHINE != Binary.EM_X86_64:
            return False
        if self.E_PHT_SIZE != 0x38 or not 0 < self.E_PHT_COUNT < 0x40:
            return False

        if not Binary.KERNEL_MIN <= self.E_START_ADDR < Binary.PS4_KERNEL_BASE:
            return False

        try:
            f.seek(base + self.E_PHT_OFFSET)
            self.E_SEGMENTS = [Segment(f) for _ in range(self.E_PHT_COUNT)]
        except Exception:
            return False


        loads = [x for x in self.E_SEGMENTS if x.TYPE == Segment.PT_LOAD]
        dyn   = [x for x in self.E_SEGMENTS if x.TYPE == Segment.PT_DYNAMIC]
        if len(loads) < 2 or not dyn:
            return False


        if not Binary.KERNEL_MIN <= loads[0].MEM_ADDR < Binary.PS4_KERNEL_BASE:
            return False

        if self.E_SHT_OFFSET and self.E_SHT_COUNT:
            try:
                f.seek(base + self.E_SHT_OFFSET)
                self.E_SECTIONS = [Section(f) for _ in range(self.E_SHT_COUNT)]
            except Exception:
                self.E_SECTIONS = []

        self.FILE_BASE = base
        return True


    def v2f(self, address):

        for segm in self.E_SEGMENTS:
            if segm.TYPE != Segment.PT_LOAD or not segm.FILE_SIZE:
                continue
            if segm.MEM_ADDR <= address < segm.MEM_ADDR + segm.FILE_SIZE:
                return self.FILE_BASE + segm.OFFSET + (address - segm.MEM_ADDR)
        return None

    def procomp(self, processor, pointer, til):


        idc.set_processor_type(processor, SETPROC_LOADER)

        
        idc.set_inf_attr(INF_COMPILER, COMP_GNU)
        idc.set_inf_attr(INF_MODEL, pointer)
        idc.set_inf_attr(INF_SIZEOF_BOOL, 0x1)
        idc.set_inf_attr(INF_SIZEOF_LONG, 0x8)
        idc.set_inf_attr(INF_SIZEOF_LDBL, 0x10)

        
        idc.add_default_til(til)

        
        idc.set_inf_attr(INF_DEMNAMES, DEMNAM_GCC3 | DEMNAM_NAME)

        
        idc.set_inf_attr(INF_FILETYPE, FT_ELF)

        
        
        
        idc.set_inf_attr(INF_AF, 0xDFFFFFDF)

        
        return self.EI_CLASS


class Segment:

    __slots__ = ('TYPE', 'FLAGS', 'OFFSET', 'MEM_ADDR',
                 'FILE_ADDR', 'FILE_SIZE', 'MEM_SIZE', 'ALIGNMENT', 'LABEL')

    
    PT_NULL                = 0x0
    PT_LOAD                = 0x1
    PT_DYNAMIC             = 0x2
    PT_INTERP              = 0x3
    PT_NOTE                = 0x4
    PT_SHLIB               = 0x5
    PT_PHDR                = 0x6
    PT_TLS                 = 0x7
    PT_NUM                 = 0x8
    PT_GNU_EH_FRAME        = 0x6474e550
    PT_GNU_STACK           = 0x6474e551
    PT_GNU_RELRO           = 0x6474e552
    PT_SCE_DYNLIBDATA      = 0x61000000
    PT_SCE_PROCPARAM       = 0x61000001
    PT_SCE_MODULEPARAM     = 0x61000002
    PT_SCE_RELRO           = 0x61000010
    PT_SCE_COMMENT         = 0x6fffff00
    PT_SCE_LIBVERSION      = 0x6fffff01

    
    AL_NONE                = 0x0
    AL_BYTE                = 0x1
    AL_WORD                = 0x2
    AL_DWORD               = 0x4
    AL_QWORD               = 0x8
    AL_PARA                = 0x10
    AL_4K                  = 0x4000
    AL_2M                  = 0x200000

    def __init__(self, f):

        self.TYPE      = struct.unpack('<I', f.read(4))[0]
        self.FLAGS     = struct.unpack('<I', f.read(4))[0]
        self.OFFSET    = struct.unpack('<Q', f.read(8))[0]
        self.MEM_ADDR  = struct.unpack('<Q', f.read(8))[0]
        self.FILE_ADDR = struct.unpack('<Q', f.read(8))[0]
        self.FILE_SIZE = struct.unpack('<Q', f.read(8))[0]
        self.MEM_SIZE  = struct.unpack('<Q', f.read(8))[0]
        self.ALIGNMENT = struct.unpack('<Q', f.read(8))[0]
        self.LABEL     = None

    def alignment(self):

        return {
            Segment.AL_NONE  : saAbs,
            Segment.AL_BYTE  : saRelByte,
            Segment.AL_WORD  : saRelWord,
            Segment.AL_DWORD : saRelDble,
            Segment.AL_QWORD : saRelQword,
            Segment.AL_PARA  : saRelPara,
            Segment.AL_4K    : saRel4K,
        }.get(self.ALIGNMENT, saRel_MAX_ALIGN_CODE)

    def flags(self):

        return self.FLAGS & 0xF

    
    def name(self):

        if self.TYPE == Segment.PT_LOAD:
            if self.flags() & SEGPERM_EXEC:
                return 'CODE'
            if self.flags() & SEGPERM_WRITE:
                return 'DATA'
            return 'RODATA'

        return {
            Segment.PT_NULL            : 'NULL',
            Segment.PT_DYNAMIC         : 'DYNAMIC',
            Segment.PT_INTERP          : 'INTERP',
            Segment.PT_NOTE            : 'NOTE',
            Segment.PT_SHLIB           : 'SHLIB',
            Segment.PT_PHDR            : 'PHDR',
            Segment.PT_TLS             : 'TLS',
            Segment.PT_NUM             : 'NUM',
            Segment.PT_GNU_EH_FRAME    : 'GNU_EH_FRAME',
            Segment.PT_GNU_STACK       : 'GNU_STACK',
            Segment.PT_GNU_RELRO       : 'GNU_RELRO',
            Segment.PT_SCE_DYNLIBDATA  : 'SCE_DYNLIBDATA',
            Segment.PT_SCE_PROCPARAM   : 'SCE_PROCPARAM',
            Segment.PT_SCE_MODULEPARAM : 'SCE_MODULEPARAM',
            Segment.PT_SCE_RELRO       : 'SCE_RELRO',
            Segment.PT_SCE_COMMENT     : 'SCE_COMMENT',
            Segment.PT_SCE_LIBVERSION  : 'SCE_LIBVERSION',
        }.get(self.TYPE, 'UNK')

    def type(self):

        if self.TYPE == Segment.PT_LOAD:
            if self.flags() & SEGPERM_EXEC:
                return 'CODE'
            if self.flags() & SEGPERM_WRITE:
                return 'DATA'
            return 'CONST'

        return {
            Segment.PT_DYNAMIC         : 'DATA',
            Segment.PT_INTERP          : 'CONST',
            Segment.PT_NOTE            : 'CONST',
            Segment.PT_PHDR            : 'CONST',
            Segment.PT_TLS             : 'BSS',
            Segment.PT_GNU_EH_FRAME    : 'CONST',
            Segment.PT_GNU_RELRO       : 'DATA',
            Segment.PT_SCE_DYNLIBDATA  : 'CONST',
            Segment.PT_SCE_PROCPARAM   : 'DATA',
            Segment.PT_SCE_MODULEPARAM : 'CONST',
            Segment.PT_SCE_RELRO       : 'DATA',
            Segment.PT_SCE_COMMENT     : 'CONST',
            Segment.PT_SCE_LIBVERSION  : 'CONST',
        }.get(self.TYPE, 'UNK')


class Section:

    __slots__ = ('NAME', 'TYPE', 'FLAGS', 'MEM_ADDR',
                 'OFFSET', 'FILE_SIZE', 'LINK', 'INFO',
                 'ALIGNMENT', 'FSE_SIZE')

    def __init__(self, f):

        self.NAME      = struct.unpack('<I', f.read(4))[0]
        self.TYPE      = struct.unpack('<I', f.read(4))[0]
        self.FLAGS     = struct.unpack('<Q', f.read(8))[0]
        self.MEM_ADDR  = struct.unpack('<Q', f.read(8))[0]
        self.OFFSET    = struct.unpack('<Q', f.read(8))[0]
        self.FILE_SIZE = struct.unpack('<Q', f.read(8))[0]
        self.LINK      = struct.unpack('<I', f.read(4))[0]
        self.INFO      = struct.unpack('<I', f.read(4))[0]
        self.ALIGNMENT = struct.unpack('<Q', f.read(8))[0]
        self.FSE_SIZE  = struct.unpack('<Q', f.read(8))[0]


class Dynamic:

    __slots__ = ('TAG', 'VALUE')

    
    (DT_NULL, DT_NEEDED, DT_PLTRELSZ, DT_PLTGOT, DT_HASH, DT_STRTAB, DT_SYMTAB,
    DT_RELA, DT_RELASZ, DT_RELAENT, DT_STRSZ, DT_SYMENT, DT_INIT, DT_FINI,
    DT_SONAME, DT_RPATH, DT_SYMBOLIC, DT_REL, DT_RELSZ, DT_RELENT, DT_PLTREL,
    DT_DEBUG, DT_TEXTREL, DT_JMPREL, DT_BIND_NOW, DT_INIT_ARRAY, DT_FINI_ARRAY,
    DT_INIT_ARRAYSZ, DT_FINI_ARRAYSZ, DT_RUNPATH, DT_FLAGS, DT_ENCODING,
    DT_PREINIT_ARRAY, DT_PREINIT_ARRAYSZ) = range(0x22)
    DT_RELRSZ                   = 0x23
    DT_RELR                     = 0x24
    DT_RELRENT                  = 0x25
    DT_GNU_HASH                 = 0x6ffffef5
    DT_RELACOUNT                = 0x6ffffff9
    DT_RELCOUNT                 = 0x6ffffffa
    DT_FLAGS_1                  = 0x6ffffffb
    DT_VERDEF                   = 0x6ffffffc
    DT_VERDEFNUM                = 0x6ffffffd

    
    TABLE = {}

    def __init__(self, f):

        self.TAG   = struct.unpack('<Q', f.read(8))[0]
        self.VALUE = struct.unpack('<Q', f.read(8))[0]

    def tag(self):

        return {
            Dynamic.DT_NULL            : 'DT_NULL',
            Dynamic.DT_NEEDED          : 'DT_NEEDED',
            Dynamic.DT_PLTRELSZ        : 'DT_PLTRELSZ',
            Dynamic.DT_PLTGOT          : 'DT_PLTGOT',
            Dynamic.DT_HASH            : 'DT_HASH',
            Dynamic.DT_STRTAB          : 'DT_STRTAB',
            Dynamic.DT_SYMTAB          : 'DT_SYMTAB',
            Dynamic.DT_RELA            : 'DT_RELA',
            Dynamic.DT_RELASZ          : 'DT_RELASZ',
            Dynamic.DT_RELAENT         : 'DT_RELAENT',
            Dynamic.DT_STRSZ           : 'DT_STRSZ',
            Dynamic.DT_SYMENT          : 'DT_SYMENT',
            Dynamic.DT_INIT            : 'DT_INIT',
            Dynamic.DT_FINI            : 'DT_FINI',
            Dynamic.DT_SONAME          : 'DT_SONAME',
            Dynamic.DT_RPATH           : 'DT_RPATH',
            Dynamic.DT_SYMBOLIC        : 'DT_SYMBOLIC',
            Dynamic.DT_REL             : 'DT_REL',
            Dynamic.DT_RELSZ           : 'DT_RELSZ',
            Dynamic.DT_RELENT          : 'DT_RELENT',
            Dynamic.DT_PLTREL          : 'DT_PLTREL',
            Dynamic.DT_DEBUG           : 'DT_DEBUG',
            Dynamic.DT_TEXTREL         : 'DT_TEXTREL',
            Dynamic.DT_JMPREL          : 'DT_JMPREL',
            Dynamic.DT_BIND_NOW        : 'DT_BIND_NOW',
            Dynamic.DT_INIT_ARRAY      : 'DT_INIT_ARRAY',
            Dynamic.DT_FINI_ARRAY      : 'DT_FINI_ARRAY',
            Dynamic.DT_INIT_ARRAYSZ    : 'DT_INIT_ARRAYSZ',
            Dynamic.DT_FINI_ARRAYSZ    : 'DT_FINI_ARRAYSZ',
            Dynamic.DT_RUNPATH         : 'DT_RUNPATH',
            Dynamic.DT_FLAGS           : 'DT_FLAGS',
            Dynamic.DT_ENCODING        : 'DT_ENCODING',
            Dynamic.DT_PREINIT_ARRAY   : 'DT_PREINIT_ARRAY',
            Dynamic.DT_PREINIT_ARRAYSZ : 'DT_PREINIT_ARRAYSZ',
            Dynamic.DT_RELRSZ          : 'DT_RELRSZ',
            Dynamic.DT_RELR            : 'DT_RELR',
            Dynamic.DT_RELRENT         : 'DT_RELRENT',
            Dynamic.DT_GNU_HASH        : 'DT_GNU_HASH',
            Dynamic.DT_RELACOUNT       : 'DT_RELACOUNT',
            Dynamic.DT_RELCOUNT        : 'DT_RELCOUNT',
            Dynamic.DT_FLAGS_1         : 'DT_FLAGS_1',
            Dynamic.DT_VERDEF          : 'DT_VERDEF',
            Dynamic.DT_VERDEFNUM       : 'DT_VERDEFNUM',
        }.get(self.TAG, 'DT_%

    def process(self):

        Dynamic.TABLE[self.TAG] = self.VALUE
        return '%s | %


class Relocation:

    __slots__ = ('OFFSET', 'INFO', 'ADDEND')

    
    (R_X86_64_NONE, R_X86_64_64, R_X86_64_PC32, R_X86_64_GOT32,
    R_X86_64_PLT32, R_X86_64_COPY, R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT,
    R_X86_64_RELATIVE, R_X86_64_GOTPCREL, R_X86_64_32, R_X86_64_32S,
    R_X86_64_16, R_X86_64_PC16, R_X86_64_8, R_X86_64_PC8, R_X86_64_DTPMOD64,
    R_X86_64_DTPOFF64, R_X86_64_TPOFF64, R_X86_64_TLSGD, R_X86_64_TLSLD,
    R_X86_64_DTPOFF32, R_X86_64_GOTTPOFF, R_X86_64_TPOFF32, R_X86_64_PC64,
    R_X86_64_GOTOFF64, R_X86_64_GOTPC32, R_X86_64_GOT64, R_X86_64_GOTPCREL64,
    R_X86_64_GOTPC64, R_X86_64_GOTPLT64, R_X86_64_PLTOFF64, R_X86_64_SIZE32,
    R_X86_64_SIZE64, R_X86_64_GOTPC32_TLSDESC, R_X86_64_TLSDESC_CALL,
    R_X86_64_TLSDESC, R_X86_64_IRELATIVE, R_X86_64_RELATIVE64) = range(0x27)
    R_X86_64_ORBIS_GOTPCREL_LOAD = 0x28

    NAMES = {
        R_X86_64_NONE      : 'R_X86_64_NONE',
        R_X86_64_64        : 'R_X86_64_64',
        R_X86_64_GLOB_DAT  : 'R_X86_64_GLOB_DAT',
        R_X86_64_JUMP_SLOT : 'R_X86_64_JUMP_SLOT',
        R_X86_64_RELATIVE  : 'R_X86_64_RELATIVE',
        R_X86_64_IRELATIVE : 'R_X86_64_IRELATIVE',
        R_X86_64_64 + 0    : 'R_X86_64_64',
    }






def u64(value):

    return value & 0xFFFFFFFFFFFFFFFF


def s32(value):

    return value - 0x100000000 if value & 0x80000000 else value


def make_struct(name, members):

    

    entry = idc.get_struc_id(name)
    if entry not in (BADADDR, -1):
        return entry

    entry = idc.add_struc(BADADDR, name, False)
    location = 0x0

    for (member, comment, size) in members:
        flags = idaapi.get_flags_by_size(size)

        if member.startswith(('d_', 'sv_', 'sy_')) and size == 0x8 and member not in ('sv_size',):
            idc.add_struc_member(entry, member, location, flags | FF_0OFF, BADADDR, size, BADADDR, 0, REF_OFF64)
        elif member in ('function', 'offset'):
            idc.add_struc_member(entry, member, location, flags | FF_0OFF, BADADDR, size, BADADDR, 0, REF_OFF64)
        else:
            idc.add_struc_member(entry, member, location, flags, BADADDR, size)

        idc.set_member_cmt(entry, location, comment, False)
        location += size

    return entry


def apply_struct(address, size, sid):

    try:
        idaapi.del_items(address, 0, size)
    except Exception:
        pass
    try:
        return idaapi.create_struct(address, size, sid)
    except Exception:
        return ida_bytes.create_struct(address, size, sid)



def find_binary(address, end, search, radix, flags):

    if idaapi.IDA_SDK_VERSION > 760:
        binpat = idaapi.compiled_binpat_vec_t()
        idaapi.parse_binpat_str(binpat, address, search, radix)

        try:
            
            address, _ = idaapi.bin_search(address, end, binpat, flags)
        except Exception:
            
            address, _ = idaapi.bin_search3(address, end, binpat, flags)
    else:
        address = idaapi.find_binary(address, end, search, radix, flags)

    return address


def bytes_pattern(blob):

    return ' '.join('%02X' % x for x in bytearray(blob))


def qword_pattern(value):

    return bytes_pattern(struct.pack('<Q', u64(value)))


def segments():

    

    result = []
    for index in range(ida_segment.get_segm_qty()):
        result.append(ida_segment.getnseg(index))
    return result


def data_segments():

    return [x for x in segments() if idaapi.get_segm_name(x) != 'CODE']


def is_mapped(address):

    return address and ida_segment.getseg(address) is not None


def in_code(address):

    segm = ida_segment.getseg(address) if address else None
    return segm is not None and idaapi.get_segm_name(segm) == 'CODE'


def cstring(address, limit = 0x100):

    if not is_mapped(address):
        return None
    try:
        length = idaapi.get_max_strlit_length(address, STRTYPE_C)
        if not length or length > limit:
            return None
        blob = idaapi.get_strlit_contents(address, length, STRTYPE_C)
        if blob is None:
            return None
        text = blob.decode('ascii', 'replace').rstrip('\x00')
    except Exception:
        return None

    if not text or any(ord(c) < 0x20 or ord(c) > 0x7E for c in text):
        return None
    return text


def find_string(text, terminated = True):

    

    blob = text.encode('ascii')
    pattern = bytes_pattern(blob + b'\x00' if terminated else blob)

    for segm in segments():
        address = find_binary(segm.start_ea, segm.end_ea, pattern, 0x10, SEARCH_DOWN)
        if address != BADADDR:
            return address

    return BADADDR


def sanitize(name):

    

    if not name:
        return None

    if name.startswith('
        return None
    if name.startswith('obs_{') or name == 'obs_{':
        return None
    if '.' in name:
        name = name.replace('.', '_')

    result = ''.join(c if (c.isalnum() or c == '_') else '_' for c in name)
    if not result or result[0].isdigit():
        result = '_' + result
    return result


def set_func_name(address, name):

    

    if not in_code(address):
        return False

    if ida_funcs.get_func(address) is None:
        idaapi.del_items(address, 0)
        idaapi.create_insn(address)
        idaapi.add_func(address, BADADDR)

    return idaapi.set_name(address, name, SN_NOCHECK | SN_NOWARN | SN_FORCE)


def has_name(address):

    return bool(idaapi.get_name(address))











def is_thunk(address):

    if not in_code(address):
        return False
    try:
        return idaapi.get_byte(address) == 0xE9 and \
               idaapi.get_byte(address + 5) == 0xCC and \
               idaapi.get_byte(address + 6) == 0xCC and \
               idaapi.get_byte(address + 7) == 0xCC
    except Exception:
        return False


def thunk_target(address):

    

    if not is_thunk(address):
        return address

    target = u64(address + 5 + s32(idaapi.get_dword(address + 1)))
    return target if in_code(target) else address


def prospero(code):

    

    address = code.start_ea
    total = 0

    while address < code.end_ea - 8:
        address = find_binary(address, code.end_ea, 'E9 ?? ?? ?? ?? CC CC CC', 0x10, SEARCH_DOWN)
        if address == BADADDR:
            break

        
        if address & 0x7:
            address += 1
            continue

        target = u64(address + 5 + s32(idaapi.get_dword(address + 1)))
        if not in_code(target):
            address += 8
            continue

        
        
        if not (is_thunk(address - 8) or is_thunk(address + 8)):
            address += 8
            continue

        idaapi.del_items(address, 0, 0x8)
        if idaapi.create_insn(address):
            idaapi.add_func(address, address + 0x5)
            function = ida_funcs.get_func(address)
            if function is not None:
                function.flags |= FUNC_THUNK
                ida_funcs.update_func(function)
                total += 1

        address += 8

    return total







SYSENTVEC = [('sv_size',                'Number of syscalls',            0x4),
             ('_pad',                   'Padding',                       0x4),
             ('sv_table',               'Syscall table',                 0x8),
             ('sv_mask',                'Syscall mask',                  0x4),
             ('sv_sigsize',             'Size of signal translation tbl',0x4),
             ('sv_sigtbl',              'Signal translation table',      0x8),
             ('sv_transtrap',           'Translate trap-to-signal',      0x8),
             ('sv_fixup',               'Stack fixup function',          0x8),
             ('sv_sendsig',             'Send signal',                   0x8),
             ('sv_sigcode',             'Start of sigtramp code',        0x8),
             ('sv_szsigcode',           'Size of sigtramp code',         0x8),
             ('sv_name',                'ABI name',                      0x8),
             ('sv_coredump',            'Function to dump core',         0x8),
             ('sv_imgact_try',          'Image activator',               0x8),
             ('sv_minsigstksz',         'Minimum signal stack size',     0x4),
             ('sv_pagesize',            'Page size',                     0x4),
             ('sv_minuser',             'VM_MIN_ADDRESS',                0x8),
             ('sv_maxuser',             'VM_MAXUSER_ADDRESS',            0x8),
             ('sv_usrstack',            'USRSTACK',                      0x8),
             ('sv_psstrings',           'PS_STRINGS',                    0x8),
             ('sv_copyout_strings',     'Copy out strings',              0x8),
             ('sv_setregs',             'Set registers',                 0x8),
             ('sv_fixlimit',            'Fix limit',                     0x8),
             ('sv_maxssiz',             'Max stack size',                0x8),
             ('sv_flags',               'Flags (SV_LP64 | SV_ABI_...)',  0x4),
             ('_pad1',                  'Padding',                       0x4),
             ('sv_set_syscall_retval',  'Set syscall return value',      0x8),
             ('sv_fetch_syscall_args',  'Fetch syscall arguments',       0x8),
             ('sv_syscallnames',        'Syscall name table',            0x8),
             ('sv_shared_page_base',    'Shared page base',              0x8),
             ('sv_shared_page_len',     'Shared page length',            0x8),
             ('sv_sigcode_base',        'Sigcode base',                  0x8),
             ('sv_shared_page_obj',     'Shared page object',            0x8),
             ('sv_schedtail',           'Scheduler tail hook',           0x8),
             ('sv_thread_detach',       'Thread detach hook',            0x8),
             ('sv_trap',                'Trap hook',                     0x8)]

SYSENTVEC_SIZE = 0xF8


SV_NAME_OFFSETS = (0x48, 0x58, 0x60)


def looks_like_sysent(table, count = 8):

    

    if not is_mapped(table):
        return False

    for index in range(count):
        entry = table + index * 0x30
        if not is_mapped(entry):
            return False
        if idaapi.get_dword(entry) > 8:
            return False
        call = idaapi.get_qword(entry + 0x8)
        if not in_code(call):
            return False

    return True


def looks_like_syscallnames(table):

    

    if not is_mapped(table):
        return False

    expected = ('syscall', 'exit', 'fork')
    for index, want in enumerate(expected):
        if cstring(idaapi.get_qword(table + index * 0x8)) != want:
            return False

    return True


def find_sysentvec(name):



    string = find_string(name)
    if string == BADADDR:
        return None

    pattern = qword_pattern(string)

    for segm in data_segments():
        address = segm.start_ea

        while address < segm.end_ea:
            address = find_binary(address, segm.end_ea, pattern, 0x10, SEARCH_DOWN)
            if address == BADADDR:
                break

            for delta in SV_NAME_OFFSETS:
                sysvec = address - delta
                if not is_mapped(sysvec):
                    continue

                table = names = BADADDR
                size = 0

                for offset in range(0x0, 0x180, 0x8):
                    value = idaapi.get_qword(sysvec + offset)

                    if table == BADADDR and offset and looks_like_sysent(value):
                        candidate = idaapi.get_dword(sysvec + offset - 0x8)
                        if 0x100 <= candidate <= 0x1000:
                            table, size = value, candidate

                    if names == BADADDR and looks_like_syscallnames(value):
                        names = value

                if table != BADADDR and names != BADADDR:
                    return {'sysentvec' : sysvec,
                            'sv_name'   : string,
                            'sv_table'  : table,
                            'sv_size'   : size,
                            'sv_names'  : names,
                            'name_off'  : delta}

            address += 0x1

    return None


def znullptr(tables, struct_sysent, struct_sysentvec):



    
    targets = {}

    for tag, info in tables:
        table, names, size = info['sv_table'], info['sv_names'], info['sv_size']

        for index in range(size):
            thunk = idaapi.get_qword(table + index * 0x30 + 0x8)
            real = thunk_target(thunk)
            raw = cstring(idaapi.get_qword(names + index * 0x8))
            targets.setdefault(real, []).append((tag, index, raw, thunk))

    
    first = tables[0][1]
    nosys = thunk_target(idaapi.get_qword(first['sv_table'] + 0x8))

    chosen = {}

    for real, users in targets.items():
        if real == nosys:
            chosen[real] = 'nosys'
            continue

        clean = [sanitize(x[2]) for x in users]
        clean = [x for x in clean if x]

        if not clean:
            chosen[real] = 'sysent_stub_%X' % (real & 0xFFFFFFFF)
        elif len(set(clean)) == 1:
            chosen[real] = clean[0]
        elif len(users) <= 4:
            
            plain = [x for x in clean if not x.startswith(('compat', 'obs_', 'freebsd'))]
            chosen[real] = (plain or clean)[0]
        else:
            
            chosen[real] = 'sysent_stub_%X' % (real & 0xFFFFFFFF)

    
    for real, name in chosen.items():
        if set_func_name(real, 'sys_' + name):
            try:
                idc.apply_type(real, idc.parse_decl(
                    '__int64 __fastcall sys_%s(void *td, void *uap);' % name, 0), TINFO_DEFINITE)
            except Exception:
                pass

    named_thunks = set()

    for tag, info in tables:
        sysvec, table, names, size = info['sysentvec'], info['sv_table'], info['sv_names'], info['sv_size']

        print('
              (tag, sysvec, table, names, size))

        idaapi.set_name(sysvec, 'sysentvec_%s' % tag, SN_NOCHECK | SN_NOWARN | SN_FORCE)

        
        if not idaapi.get_name(table).startswith('sv_table_'):
            idaapi.set_name(table, 'sv_table_%s' % tag, SN_NOCHECK | SN_NOWARN | SN_FORCE)
        if not idaapi.get_name(names).startswith('sv_syscallnames_'):
            idaapi.set_name(names, 'sv_syscallnames_%s' % tag, SN_NOCHECK | SN_NOWARN | SN_FORCE)

        if info['name_off'] == 0x48 and struct_sysentvec not in (BADADDR, -1):
            apply_struct(sysvec, SYSENTVEC_SIZE, struct_sysentvec)

        for index in range(size):
            entry = table + index * 0x30
            apply_struct(entry, 0x30, struct_sysent)

            raw = cstring(idaapi.get_qword(names + index * 0x8)) or '
            idc.set_cmt(entry, '

            thunk = idaapi.get_qword(table + index * 0x30 + 0x8)
            real = thunk_target(thunk)

            if thunk != real and thunk not in named_thunks:
                named_thunks.add(thunk)
                idaapi.set_name(thunk, 'j_sys_%s' % chosen.get(real, 'nosys'),
                                SN_NOCHECK | SN_NOWARN | SN_FORCE)

            
            slot = names + index * 0x8
            idc.create_data(slot, FF_QWORD, 0x8, BADNODE)
            idc.op_plain_offset(slot, 0, 0)

    return len(chosen)






CDEVSW_OPS = [(0x10, 'open'), (0x18, 'fdopen'), (0x20, 'close'), (0x28, 'read'),
              (0x30, 'write'), (0x38, 'ioctl'), (0x40, 'poll'), (0x48, 'mmap'),
              (0x50, 'strategy'), (0x58, 'dump'), (0x60, 'kqfilter'), (0x68, 'purge'),
              (0x70, 'mmap_single')]


def chendo(struct_cdevsw):

    total = 0

    for segm in data_segments():
        address = segm.start_ea

        while address < segm.end_ea:
            address = find_binary(address, segm.end_ea, '09 20 12 17', 0x10, SEARCH_DOWN)
            if address == BADADDR:
                break

            name = cstring(idaapi.get_qword(address + 0x8))
            if not name or len(name) > 0x40:
                address += 0x4
                continue

            apply_struct(address, 0xB0, struct_cdevsw)
            idc.set_cmt(address, 'cdevsw %s' % name, False)

            label = sanitize(name)
            if label:
                idaapi.set_name(address, '%s_cdevsw' % label, SN_NOCHECK | SN_NOWARN | SN_FORCE)

                for (offset, operation) in CDEVSW_OPS:
                    thunk = idaapi.get_qword(address + offset)
                    if not in_code(thunk):
                        continue

                    real = thunk_target(thunk)
                    if not has_name(real):
                        set_func_name(real, '%s_%s' % (label, operation))
                    if thunk != real and not has_name(thunk):
                        idaapi.set_name(thunk, 'j_%s_%s' % (label, operation),
                                        SN_NOCHECK | SN_NOWARN | SN_FORCE)

            total += 1
            address += 0xB0

    return total






def pablo(mode, address, end, search):

    code = idaapi.get_segm_by_name('CODE')

    while address < end:
        address = find_binary(address, end, search, 0x10, SEARCH_DOWN)
        if address == BADADDR:
            break

        if code is not None and address > code.end_ea:
            offset = address - 0x3

            if ida_bytes.is_unknown(ida_bytes.get_flags(offset)):
                if idaapi.get_qword(offset) <= end:
                    idaapi.create_data(offset, FF_QWORD, 0x8, BADNODE)

            address = offset + 4

        else:
            address += mode
            idaapi.del_items(address, 0)
            idaapi.create_insn(address)
            idaapi.add_func(address, BADADDR)
            address += 1






def find_lea_ref(code, target):



    blob = ida_bytes.get_bytes(code.start_ea, code.end_ea - code.start_ea)
    if not blob:
        return BADADDR

    
    for prefix in (b'\x48\x8d\x3d', b'\x48\x8d\x35', b'\x48\x8d\x15',
                   b'\x48\x8d\x0d', b'\x48\x8d\x05', b'\x48\x8d\x1d'):
        position = blob.find(prefix)

        while position >= 0:
            address = code.start_ea + position
            displacement = struct.unpack('<i', blob[position + 3:position + 7])[0]

            if u64(address + 7 + displacement) == target:
                return address

            position = blob.find(prefix, position + 1)

    return BADADDR


def function_start(address, limit = 0x200):

    

    for delta in range(0, limit):
        candidate = address - delta
        if idaapi.get_byte(candidate) == 0x55 and \
           idaapi.get_byte(candidate + 1) == 0x48 and \
           idaapi.get_byte(candidate + 2) == 0x89 and \
           idaapi.get_byte(candidate + 3) == 0xE5:
            return candidate

    return BADADDR


def kiwidog(code):

    magic = find_string('stack overflow detected;', False)
    if magic == BADADDR:
        return False

    reference = idaapi.get_first_dref_to(magic)
    if reference == BADADDR:
        reference = find_lea_ref(code, magic)
    if reference == BADADDR:
        return False

    function = ida_funcs.get_func(reference)
    if function is None:
        start = function_start(reference)
        if start == BADADDR:
            return False
        idaapi.del_items(start, 0)
        idaapi.create_insn(start)
        idaapi.add_func(start, BADADDR)
        function = ida_funcs.get_func(start)
    if function is None:
        return False

    idaapi.set_name(function.start_ea, '__stack_chk_fail', SN_NOCHECK | SN_NOWARN | SN_FORCE)
    function.flags |= FUNC_NORET
    ida_funcs.update_func(function)
    print('
    return True






def accept_file(f, n):

    if f.size() < 0x1000:
        return 0

    ps5 = Binary(f)
    if not ps5.VALID:
        return 0

    return {'format'  : 'PS5 - Kernel',
            'options' : ACCEPT_FIRST}


def load_file(f, neflags, format):

    print('

    ps5 = Binary(f)
    if not ps5.VALID:
        print('
        return 0

    if ps5.FILE_BASE:
        print('

    
    bitness = ps5.procomp('metapc', CM_N64 | CM_M_NN | CM_CC_FASTCALL, 'gnulnx_x64')

    
    
    
    used = {}
    dynamic = None

    for segm in ps5.E_SEGMENTS:

        if segm.TYPE == Segment.PT_LOAD and segm.MEM_SIZE:

            label = segm.name()
            index = used.get(label, 0)
            used[label] = index + 1
            if index:
                label = '%s%i' % (label, index)
            segm.LABEL = label

            address = segm.MEM_ADDR
            size = segm.MEM_SIZE

            print('
                  (label, address, address + size, ps5.FILE_BASE + segm.OFFSET, segm.FILE_SIZE))

            if segm.FILE_SIZE:
                f.file2base(ps5.FILE_BASE + segm.OFFSET, address,
                            address + segm.FILE_SIZE, FILEREG_PATCHABLE)

            idaapi.add_segm(0, address, address + size, label, segm.type(),
                            ADDSEG_NOTRUNC | ADDSEG_FILLGAP)

            idc.set_segm_addressing(address, bitness)
            idc.set_segm_alignment(address, segm.alignment())
            idc.set_segm_attr(address, SEGATTR_PERM, segm.flags())

        elif segm.TYPE == Segment.PT_DYNAMIC:
            dynamic = segm

    code = idaapi.get_segm_by_name('CODE')
    if code is None:
        print('
        return 0

    
    
    
    if dynamic is not None:

        members = [('tag', 'Tag', 0x8),
                   ('value', 'Value', 0x8)]
        struct_tag = make_struct('Tag', members)

        Dynamic.TABLE = {}
        location = dynamic.MEM_ADDR

        f.seek(ps5.FILE_BASE + dynamic.OFFSET)
        for entry in range(int(dynamic.MEM_SIZE / 0x10)):
            comment = Dynamic(f).process()
            apply_struct(location + entry * 0x10, 0x10, struct_tag)
            idc.set_cmt(location + entry * 0x10, comment, False)

        idaapi.set_name(dynamic.MEM_ADDR, '_DYNAMIC', SN_NOCHECK | SN_NOWARN | SN_FORCE)

        
        
        
        
        
        
        
        relatab = Dynamic.TABLE.get(Dynamic.DT_RELA, 0)
        relasz = Dynamic.TABLE.get(Dynamic.DT_RELASZ, 0)
        relaent = Dynamic.TABLE.get(Dynamic.DT_RELAENT, 0x18) or 0x18

        if relatab and relasz:

            members = [('offset', 'Offset', 0x8),
                       ('info', 'Info (Symbol Index : Relocation Code)', 0x8),
                       ('addend', 'AddEnd', 0x8)]
            struct_rela = make_struct('Relocation', members)

            count = int(relasz / relaent)
            print('

            position = ps5.v2f(relatab)
            if relaent != 0x18:
                print('
            elif position is None:
                print('
            else:
                f.seek(position)
                blob = f.read(count * relaent)

                
                
                highest = 0
                for (offset, info, addend) in struct.iter_unpack('<QQQ', blob):
                    if (info & 0xFFFFFFFF) == Relocation.R_X86_64_RELATIVE and offset > highest:
                        highest = offset

                last = segments()[-1] if segments() else None
                if last is not None and highest + 0x8 > last.end_ea:
                    stretched = (highest + 0x8 + 0xFFF) & ~0xFFF
                    print('
                          (idaapi.get_segm_name(last), stretched,
                           sum(1 for (o, i, a) in struct.iter_unpack('<QQQ', blob) if o >= last.end_ea)))
                    ida_segment.set_segm_end(last.start_ea, stretched, SEGMOD_KEEP | SEGMOD_SILENT)

                applied = skipped = 0
                for (offset, info, addend) in struct.iter_unpack('<QQQ', blob):

                    if (info & 0xFFFFFFFF) != Relocation.R_X86_64_RELATIVE:
                        skipped += 1
                        continue

                    if not is_mapped(offset):
                        skipped += 1
                        continue

                    idaapi.put_qword(offset, addend)
                    idaapi.create_data(offset, FF_QWORD, 0x8, BADNODE)
                    if is_mapped(addend):
                        idc.op_plain_offset(offset, 0, 0)
                    applied += 1

                print('

                
                if is_mapped(relatab):
                    apply_struct(relatab, relaent, struct_rela)
                    idc.make_array(relatab, count)
                    idaapi.set_name(relatab, 'rela_dyn', SN_NOCHECK | SN_NOWARN | SN_FORCE)

        else:
            
            
            print('

        for (tag, name) in ((Dynamic.DT_HASH, 'hash_table'),
                            (Dynamic.DT_SYMTAB, 'symtab'),
                            (Dynamic.DT_STRTAB, 'strtab')):
            value = Dynamic.TABLE.get(tag, 0)
            
            
            if is_mapped(value) and not in_code(value):
                idaapi.set_name(value, name, SN_NOCHECK | SN_NOWARN | SN_FORCE)

        initial = Dynamic.TABLE.get(Dynamic.DT_INIT, 0)
        if is_mapped(initial):
            idc.add_entry(initial, initial, '.init', True)

    
    
    
    address = code.start_ea

    members = [('File format', 0x4),
               ('File class', 0x1),
               ('Data encoding', 0x1),
               ('File version', 0x1),
               ('OS/ABI', 0x1),
               ('ABI version', 0x1),
               ('Padding', 0x7),
               ('File type', 0x2),
               ('Machine', 0x2),
               ('File version', 0x4),
               ('Entry point', 0x8),
               ('PHT file offset', 0x8),
               ('SHT file offset', 0x8),
               ('Processor-specific flags', 0x4),
               ('ELF header size', 0x2),
               ('PHT entry size', 0x2),
               ('Number of entries in PHT', 0x2),
               ('SHT entry size', 0x2),
               ('Number of entries in SHT', 0x2),
               ('SHT entry index for string table\n', 0x2)]

    
    
    if idaapi.get_dword(address) == 0x464C457F:
        for (comment, size) in members:
            flags = idaapi.get_flags_by_size(size)
            idc.create_data(address, flags if flags != 0 else FF_STRLIT, size, BADNODE)
            idc.set_cmt(address, comment, False)
            address += size

        for entry in ps5.E_SEGMENTS:
            members = [('Type: %s' % entry.name(), 0x4),
                       ('Flags', 0x4),
                       ('File offset', 0x8),
                       ('Virtual address', 0x8),
                       ('Physical address', 0x8),
                       ('Size in file image', 0x8),
                       ('Size in memory image', 0x8),
                       ('Alignment\n', 0x8)]

            for (comment, size) in members:
                flags = idaapi.get_flags_by_size(size)
                idc.create_data(address, flags if flags != 0 else FF_STRLIT, size, BADNODE)
                idc.set_cmt(address, comment, False)
                address += size

    
    idc.add_entry(ps5.E_START_ADDR, ps5.E_START_ADDR, 'start', True)

    
    
    
    
    address = find_binary(code.start_ea, code.end_ea,
                          '0F 01 F8 65 48 89 24 25 ?? ?? 00 00 65 48 8B 24 25', 0x10, SEARCH_DOWN)
    if address != BADADDR:
        idaapi.del_items(address, 0)
        idaapi.create_insn(address)
        idaapi.add_func(address, BADADDR)
        idaapi.set_name(address, 'Xfast_syscall', SN_NOCHECK | SN_NOWARN | SN_FORCE)
        print('

    
    
    
    try:
        print('
        print('
    except Exception as exception:
        print('

    
    
    
    try:
        print('

        members = [('sy_narg', 'Number of Arguments', 0x4),
                   ('_pad', 'Padding', 0x4),
                   ('sy_call', 'Function', 0x8),
                   ('sy_auevent', 'Audit Event', 0x2),
                   ('_pad1', 'Padding', 0x2),
                   ('_pad2', 'Padding', 0x4),
                   ('sy_systrace_args_func', 'Trace Arguments Function', 0x8),
                   ('sy_entry', 'Entry', 0x4),
                   ('sy_return', 'Return', 0x4),
                   ('sy_flags', 'Flags', 0x4),
                   ('sy_thrcnt', 'Thread Count', 0x4)]
        struct_sysent = make_struct('Syscall', members)
        struct_sysentvec = make_struct('sysentvec', SYSENTVEC)

        tables = []
        for (tag, abi) in (('ps5', 'Native SELF'), ('ps4', 'PS4 SELF'), ('freebsd', 'FreeBSD ELF64')):
            info = find_sysentvec(abi)
            if info is None:
                print('
                continue
            tables.append((tag, info))

        if tables:
            print('
                  znullptr(tables, struct_sysent, struct_sysentvec))
        else:
            print('

    except Exception as exception:
        print('

    
    
    
    try:
        print('

        members = [('d_version', 'Version', 0x4),
                   ('d_flags', 'Flags', 0x4),
                   ('d_name', 'Name', 0x8),
                   ('d_open', 'Open', 0x8),
                   ('d_fdopen', 'File Descriptor Open', 0x8),
                   ('d_close', 'Close', 0x8),
                   ('d_read', 'Read', 0x8),
                   ('d_write', 'Write', 0x8),
                   ('d_ioctl', 'Input/Output Control', 0x8),
                   ('d_poll', 'Poll', 0x8),
                   ('d_mmap', 'Memory Mapping', 0x8),
                   ('d_strategy', 'Strategy', 0x8),
                   ('d_dump', 'Dump', 0x8),
                   ('d_kqfilter', 'KQFilter', 0x8),
                   ('d_purge', 'Purge', 0x8),
                   ('d_mmap_single', 'Single Memory Mapping', 0x8),
                   ('d_spare0', 'Spare0', 0x8),
                   ('d_spare1', 'Spare1', 0x8),
                   ('d_spare2', 'Spare2', 0x8),
                   ('d_spare3', 'Spare3', 0x8),
                   ('d_spare4', 'Spare4', 0x8),
                   ('d_spare5', 'Spare5', 0x8),
                   ('d_spare6', 'Spare6', 0x4),
                   ('d_spare7', 'Spare7', 0x4)]
        struct_cdevsw = make_struct('cdevsw', members)

        print('

    except Exception as exception:
        print('

    
    
    
    try:
        print('

        
        pablo(0, code.start_ea, 0x10, '55 48 89')
        pablo(2, code.start_ea, code.end_ea, '90 90 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, 'C3 90 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '66 90 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, 'C9 C3 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '0F 0B 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, 'EB ?? 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '5D C3 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, '5B C3 55 48 ??')
        pablo(2, code.start_ea, code.end_ea, 'CC CC 55 48 89 E5')
        pablo(2, code.start_ea, code.end_ea, '90 90 55 41 ?? 41 ??')
        pablo(2, code.start_ea, code.end_ea, '66 90 48 81 EC ?? 00 00 00')
        pablo(2, code.start_ea, code.end_ea, '0F 0B 48 89 9D ?? ?? FF FF 49 89')
        pablo(2, code.start_ea, code.end_ea, '90 90 53 4C 8B 54 24 20')
        pablo(2, code.start_ea, code.end_ea, '90 90 55 41 56 53')
        pablo(2, code.start_ea, code.end_ea, '90 90 53 48 89')
        pablo(2, code.start_ea, code.end_ea, '90 90 41 ?? 41 ??')
        pablo(3, code.start_ea, code.end_ea, '0F 0B 90 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, 'EB ?? 90 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 5F C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 5C C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '31 C0 C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 5D C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '41 5E C3 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '66 66 90 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, '0F 1F 00 55 48 ??')
        pablo(3, code.start_ea, code.end_ea, 'CC CC CC 55 48 89 E5')
        pablo(3, code.start_ea, code.end_ea, '41 ?? C3 53 48')
        pablo(3, code.start_ea, code.end_ea, '0F 1F 00 48 81 EC ?? 00 00 00')
        pablo(4, code.start_ea, code.end_ea, '0F 1F 40 00 55 48 ??')
        pablo(4, code.start_ea, code.end_ea, '0F 1F 40 00 48 81 EC ?? 00 00 00')
        pablo(5, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 55 48 ??')
        pablo(5, code.start_ea, code.end_ea, 'E8 ?? ?? ?? ?? 55 48 ??')
        pablo(5, code.start_ea, code.end_ea, '48 83 C4 ?? C3 55 48 ??')
        pablo(5, code.start_ea, code.end_ea, '0F 1F 44 00 00 55 48 ??')
        pablo(5, code.start_ea, code.end_ea, '0F 1F 44 00 00 48 81 EC ?? 00 00 00')
        pablo(6, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 55 48 ??')
        pablo(6, code.start_ea, code.end_ea, 'E8 ?? ?? ?? ?? 90 55 48 ??')
        pablo(6, code.start_ea, code.end_ea, '66 0F 1F 44 00 00 55 48 ??')
        pablo(7, code.start_ea, code.end_ea, '0F 1F 80 00 00 00 00 55 48 ??')
        pablo(8, code.start_ea, code.end_ea, '0F 1F 84 00 00 00 00 00 55 48 ??')
        pablo(8, code.start_ea, code.end_ea, 'C3 0F 1F 80 00 00 00 00 48')
        pablo(8, code.start_ea, code.end_ea, '0F 1F 84 00 00 00 00 00 53 48 83 EC')

        
        pablo(13, code.start_ea, code.end_ea, 'C3 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(13, code.start_ea, code.end_ea, 'C3 90 90 90 90 90 90 90 90 90 90 90 90 55')
        pablo(17, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(19, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(19, code.start_ea, code.end_ea, 'E8 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 48')
        pablo(20, code.start_ea, code.end_ea, 'E9 ?? ?? ?? ?? 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 48')

    except Exception as exception:
        print('

    
    
    
    try:
        print('
        if not kiwidog(code):
            print('
    except Exception as exception:
        print('

    print('
    return 1


