# ----------------------------------------------------------------------
# OpenRISC 1000 processor module
# Copyright (c) 2023 Ilya Kurdyukov
#
# Compatible with IDA 7.x and possibly later versions.

import sys
from ida_idp import *
from ida_ua import *
from ida_lines import *
from ida_problems import *
from ida_xref import *
from ida_idaapi import *
from ida_bytes import *
import ida_segment
import ida_segregs

if sys.version_info.major < 3:
  range = xrange

# sign extend b low bits in x
def SIGNEXT(x, b):
    m = 1 << (b - 1)
    return (x & (m - 1)) - (x & m)

# No Delay-Slot
# 0: CPU executes delay slot of jump/branch instructions before taking jump/branch
# 1: CPU does not execute instructions in delay slot if taking jump/branch
DEFAULT_ND = 1

# values for insn_t.auxpref
AUX_LO = 1 # lo(imm)

FIND_MOVHI_RANGE = 16

# ----------------------------------------------------------------------
class or1k_processor_t(processor_t):
    """
    Processor module classes must derive from processor_t
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    # elf.h: EM_OPENRISC = 92
    id = 0x8000 + 92

    # Processor features
    flag = PR_SEGS | PR_USE32 | PR_DEFSEG32 | PR_RNAMESOK | PRN_HEX | PR_SGROTHER | PR_DELAYED

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits (64 for IDA64)
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ["or1k"]

    # long processor names
    # No restriction on name lengthes.
    plnames = ["OpenRISC 1000"]

    # size of a segment register in bytes
    segreg_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 0)


    # only one assembler is supported
    assembler = {
        # flag
        "flag": ASH_HEXF3 | ASD_DECF0 | ASO_OCTF1 | ASB_BINF3 | AS_N2CHR,

        # user defined flags (local only for IDP) (optional)
        "uflag": 0,

        # Assembler name (displayed in menus)
        "name": "OpenRISC 1000 assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        # 'header': [".or1k"],

        # org directive
        "origin": ".org",

        # end directive
        "end": ".end",

        # comment string (see also cmnt2)
        "cmnt": "#",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        "accsep": "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': ".char",

        # byte directive
        'a_byte': ".byte",

        # word directive
        'a_word': ".half",

        # remove if not allowed
        'a_dword': ".word",

        # remove if not allowed
        'a_qword': ".dword",

        # float;  4bytes; remove if not allowed
        'a_float': ".float",

        # double; 8bytes; NULL if not allowed
        'a_double': ".double",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': ".space %s",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': ".",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "",

        # "extrn"  name keyword
        'a_extrn': ".extern",

        # "comm" (communal variable)
        "a_comdef": "",

        # "align" keyword
        "a_align": ".align",

        # Left and right braces used in complex expressions
        "lbrace": "(",
        "rbrace": ")",

        # %  mod     assembler time operation
        "a_mod": "%",

        # &  bit and assembler time operation
        "a_band": "&",

        # |  bit or  assembler time operation
        "a_bor": "|",

        # ^  bit xor assembler time operation
        "a_xor": "^",

        # ~  bit not assembler time operation
        "a_bnot": "~",

        # << shift left assembler time operation
        "a_shl": "<<",

        # >> shift right assembler time operation
        "a_shr": ">>",

        # size of type (format string) (optional)
        "a_sizeof_fmt": "size %s",

        'flag2': 0,

        # the include directive (format string) (optional)
        'a_include_fmt': '.include "%s"',
    }

    # ----------------------------------------------------------------------
    def notify_get_autocmt(self, insn):
        """
        Get instruction comment. 'insn' describes the instruction in question
        @return: None or the comment string
        """
        if 'cmt' in self.instruc[insn.itype]:
          return self.instruc[insn.itype]['cmt']

    # ----------------------------------------------------------------------

    maptbl_jump = ['l.j', 'l.jal', 'l.adrp', 'l.bnf', 'l.bf']
    maptbl_shift = ['l.sll', 'l.srl', 'l.sra', 'l.ror']
    maptbl_load = ['l.lf', 'l.lwa', 'l.cust1', 'l.cust2', 'l.cust3', 'l.cust4',
        'l.ld', 'l.lwz', 'l.lws', 'l.lbz', 'l.lbs', 'l.lhz', 'l.lhs']
    maptbl_store = ['l.swa', 'l.sd', 'l.sw', 'l.sb', 'l.sh']
    maptbl_27 = ['l.addi', 'l.addic', 'l.andi', 'l.ori', 'l.xori', 'l.muli', 'l.mfspr']
    maptbl_38 = ['l.add', 'l.addc', 'l.sub', 'l.and', 'l.or', 'l.xor', 'l.mul', 'l.muld',
        '', 'l.div', 'l.divu', 'l.mulu', 'l.muldu', '', 'l.cmov', '']
    maptbl_ext = ['l.exths', 'l.extbs', 'l.exthz', 'l.extbz', 'l.extws', 'l.extwz']

    maptbl_setflag = {
        0x00: 'l.sfeq',
        0x01: 'l.sfne',
        0x02: 'l.sfgtu',
        0x03: 'l.sfgeu',
        0x04: 'l.sfltu',
        0x05: 'l.sfleu',
        0x0a: 'l.sfgts',
        0x0b: 'l.sfges',
        0x0c: 'l.sflts',
        0x0d: 'l.sfles'
    }

    maptbl_float = {
        0x00: 'lf.add.s',
        0x01: 'lf.sub.s',
        0x02: 'lf.mul.s',
        0x03: 'lf.div.s',
        0x04: 'lf.itof.s',
        0x05: 'lf.ftoi.s',
        0x06: 'lf.rem.s', # removed in 1.3
        0x07: 'lf.madd.s',
        0x08: 'lf.sfeq.s',
        0x09: 'lf.sfne.s',
        0x0a: 'lf.sfgt.s',
        0x0b: 'lf.sfge.s',
        0x0c: 'lf.sflt.s',
        0x0d: 'lf.sfle.s',

        0x10: 'lf.add.d',
        0x11: 'lf.sub.d',
        0x12: 'lf.mul.d',
        0x13: 'lf.div.d',
        0x14: 'lf.itof.d',
        0x15: 'lf.ftoi.d',
        0x16: 'lf.rem.d', # removed in 1.3
        0x17: 'lf.madd.d',
        0x18: 'lf.sfeq.d',
        0x19: 'lf.sfne.d',
        0x1a: 'lf.sfgt.d',
        0x1b: 'lf.sfge.d',
        0x1c: 'lf.sflt.d',
        0x1d: 'lf.sfle.d',

        # new in 1.3
        0x28: 'lf.sfueq.s',
        0x29: 'lf.sfune.s',
        0x2a: 'lf.sfugt.s',
        0x2b: 'lf.sfuge.s',
        0x2c: 'lf.sfult.s',
        0x2d: 'lf.sfule.s',
        0x2e: 'lf.sfun.s',
        0x34: 'lf.stod.d',
        0x35: 'lf.dtos.d',
        0x38: 'lf.sfueq.d',
        0x39: 'lf.sfune.d',
        0x3a: 'lf.sfugt.d',
        0x3b: 'lf.sfuge.d',
        0x3c: 'lf.sfult.d',
        0x3d: 'lf.sfule.d',
        0x3e: 'lf.sfun.d'
    }

    maptbl_vec = {
        0x10: 'lv.all_eq.b',
        0x11: 'lv.all_eq.h',
        0x12: 'lv.all_ge.b',
        0x13: 'lv.all_ge.h',
        0x14: 'lv.all_gt.b',
        0x15: 'lv.all_gt.h',
        0x16: 'lv.all_le.b',
        0x17: 'lv.all_le.h',
        0x18: 'lv.all_lt.b',
        0x19: 'lv.all_lt.h',
        0x1a: 'lv.all_ne.b',
        0x1b: 'lv.all_ne.h',
        0x20: 'lv.any_eq.b',
        0x21: 'lv.any_eq.h',
        0x22: 'lv.any_ge.b',
        0x23: 'lv.any_ge.h',
        0x24: 'lv.any_gt.b',
        0x25: 'lv.any_gt.h',
        0x26: 'lv.any_le.b',
        0x27: 'lv.any_le.h',
        0x28: 'lv.any_lt.b',
        0x29: 'lv.any_lt.h',
        0x2a: 'lv.any_ne.b',
        0x2b: 'lv.any_ne.h',
        0x30: 'lv.add.b',
        0x31: 'lv.add.h',
        0x32: 'lv.adds.b',
        0x33: 'lv.adds.h',
        0x34: 'lv.addu.b',
        0x35: 'lv.addu.h',
        0x36: 'lv.addus.b',
        0x37: 'lv.addus.h',
        0x38: 'lv.and',
        0x39: 'lv.avg.b',
        0x3a: 'lv.avg.h',
        0x40: 'lv.cmp_eq.b',
        0x41: 'lv.cmp_eq.h',
        0x42: 'lv.cmp_ge.b',
        0x43: 'lv.cmp_ge.h',
        0x44: 'lv.cmp_gt.b',
        0x45: 'lv.cmp_gt.h',
        0x46: 'lv.cmp_le.b',
        0x47: 'lv.cmp_le.h',
        0x48: 'lv.cmp_lt.b',
        0x49: 'lv.cmp_lt.h',
        0x4a: 'lv.cmp_ne.b',
        0x4b: 'lv.cmp_ne.h',
        0x54: 'lv.madds.h',
        0x55: 'lv.max.b',
        0x56: 'lv.max.h',
        0x57: 'lv.merge.b',
        0x58: 'lv.merge.h',
        0x59: 'lv.min.b',
        0x5a: 'lv.min.h',
        0x5b: 'lv.msubs.h',
        0x5c: 'lv.muls.h',
        0x5d: 'lv.nand',
        0x5e: 'lv.nor',
        0x5f: 'lv.or',
        0x60: 'lv.pack.b',
        0x61: 'lv.pack.h',
        0x62: 'lv.packs.b',
        0x63: 'lv.packs.h',
        0x64: 'lv.packus.b',
        0x65: 'lv.packus.h',
        0x66: 'lv.perm.n',
        0x67: 'lv.rl.b',
        0x68: 'lv.rl.h',
        0x6b: 'lv.sll',
        0x69: 'lv.sll.b',
        0x6a: 'lv.sll.h',
        0x6e: 'lv.sra.b',
        0x6f: 'lv.sra.h',
        0x70: 'lv.srl',
        0x6c: 'lv.srl.b',
        0x6d: 'lv.srl.h',
        0x71: 'lv.sub.b',
        0x72: 'lv.sub.h',
        0x73: 'lv.subs.b',
        0x74: 'lv.subs.h',
        0x75: 'lv.subu.b',
        0x76: 'lv.subu.h',
        0x77: 'lv.subus.b',
        0x78: 'lv.subus.h',
        0x79: 'lv.unpack.b',
        0x7a: 'lv.unpack.h',
        0x7b: 'lv.xor'
    }

    def notify_ana(self, insn):
        """
        Decodes an instruction into 'insn'.
        Returns: insn.size (=the size of the decoded instruction) or zero
        """
        if insn.ea & 3 != 0:
            return 0
        raw = insn.get_next_dword()
        opc = (raw >> 26) & 0x3f
        rD = (raw >> 21) & 0x1f
        rA = (raw >> 16) & 0x1f
        rB = (raw >> 11) & 0x1f

        if opc < 0x05:
            insn.itype = self.maptbl_jump[opc]
            if opc == 0x02:
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
                insn.Op2.type = o_imm
                insn.Op2.value = raw & 0x1fffff
            else:
                addr = raw & 0x3ffffff
                insn.Op1.type = o_near
                insn.Op1.addr = (insn.ea + SIGNEXT(addr, 26) * 4) & 0xffffffff

        # raw 0x05
        elif raw >> 24 & 0xff == 0x15:
            insn.itype = self.name2icode['l.nop']
            insn.Op1.type = o_imm
            insn.Op1.value = raw & 0xffff

        elif opc == 0x06:
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            if raw & 0x10000 == 0:
                insn.itype = self.name2icode['l.movhi']
                insn.Op2.type = o_imm
                insn.Op2.value = raw & 0xffff
            else:
                if raw & 0xffff != 0:
                    return 0
                insn.itype = self.name2icode['l.macrc']

        elif opc == 0x08:
            raw &= 0xffffffff
            if raw >> 16 == 0x2000:
                insn.itype = self.name2icode['l.sys']
                insn.Op1.type = o_imm
                insn.Op1.value = raw & 0xffff
            elif raw >> 16 == 0x2100:
                insn.itype = self.name2icode['l.trap']
                insn.Op1.type = o_imm
                insn.Op1.value = raw & 0xffff
            elif raw == 0x22000000:
                insn.itype = self.name2icode['l.msync']
            elif raw == 0x22800000:
                insn.itype = self.name2icode['l.psync']
            elif raw == 0x23000000:
                insn.itype = self.name2icode['l.csync']
            else:
                return 0

        elif opc == 0x09:
            insn.itype = self.name2icode['l.rfe']
        elif opc == 0x11:
            insn.itype = self.name2icode['l.jr']
            insn.Op1.type = o_reg
            insn.Op1.reg = rB
        elif opc == 0x12:
            insn.itype = self.name2icode['l.jalr']
            insn.Op1.type = o_reg
            insn.Op1.reg = rB
        elif opc == 0x13:
            insn.itype = self.name2icode['l.maci']
            insn.Op1.type = o_reg
            insn.Op1.reg = rA
            insn.Op2.type = o_imm
            insn.Op2.value = SIGNEXT(raw, 16)

        # find
        elif opc == 0x38 and raw & 0x20f == 0xf:
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rA
            if raw & 0x300 == 0:
                insn.itype = self.name2icode['l.ff1']
            elif raw & 0x300 == 0x100:
                insn.itype = self.name2icode['l.fl1']

        # arith
        elif opc == 0x38 and raw & 0x300 == 0:
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rA
            opc2 = raw & 0xf
            mask = 1 << opc2
            # 0, 1, 2, 3, 4, 5, 8, 14
            if 0x413f & mask != 0:
                insn.Op3.type = o_reg
                insn.Op3.reg = rB
                if opc2 != 0x8:
                    insn.itype = self.maptbl_38[opc2]
                else:
                    insn.itype = self.maptbl_shift[raw >> 6 & 3]
            # 12, 13
            else:
                opc3 = (raw >> 6 & 3) | opc2 << 2
                if opc3 < 0x30 or opc3 >= 0x36:
                    return 0
                insn.itype = self.maptbl_ext[opc3 - 0x30]

        # mul/div
        elif opc == 0x38 and raw & 0x300 == 0x300:
            opc2 = raw & 0xf
            mask = 1 << opc2
            # 6, 7, 9, a, b, c
            if 0x1ec0 & mask == 0:
                return 0
            insn.itype = self.maptbl_38[opc2]
            # 0x7, 0xc: l.muld, l.muldu
            if 0x1080 & mask != 0:
                insn.Op1.type = o_reg
                insn.Op1.reg = rA
                insn.Op2.type = o_reg
                insn.Op2.reg = rB
            else:
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
                insn.Op2.type = o_reg
                insn.Op2.reg = rA
                insn.Op3.type = o_reg
                insn.Op3.reg = rB

        # arith imm16
        elif opc >= 0x27 and opc <= 0x2e:
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rA
            insn.Op3.type = o_imm
            if opc == 0x2e:
                insn.itype = self.maptbl_shift_imm[raw >> 6 & 3]
                insn.Op3.value = raw & 0x3f
            else:
                insn.itype = self.maptbl_27[opc - 0x27]
                # l.addi, l.addic, l.muli
                if opc == 0x27 or opc == 0x28 or opc == 0x2c:
                    insn.Op3.value = SIGNEXT(raw, 16)
                else:
                    insn.Op3.value = raw & 0xffff

                # try to find l.movhi to combine
                if insn.itype == self.itype_ori:
                    self.find_movhi(insn)

        # load
        elif opc >= 0x1a and opc <= 0x26:
            insn.itype = self.maptbl_load[opc - 0x1a]
            if opc < 0x1c or opc > 0x1f:
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
                insn.Op2.type = o_displ
                insn.Op2.addr = SIGNEXT(raw, 16)
                insn.Op2.reg = rA

        elif opc == 0x30:
            insn.itype = self.name2icode['l.mtspr']
            insn.Op1.type = o_reg
            insn.Op1.reg = rA
            insn.Op2.type = o_reg
            insn.Op2.reg = rB
            insn.Op3.type = o_imm
            insn.Op3.value = (raw & 0x7ff) | (raw >> 10 & 0xf800)

        elif opc == 0x31:
            insn.Op1.type = o_reg
            insn.Op1.reg = rA
            insn.Op2.type = o_reg
            insn.Op2.reg = rB
            opc2 = raw & 0xf
            if opc2 == 1:
                insn.itype = self.name2icode['l.mac']
            elif opc2 == 2:
                insn.itype = self.name2icode['l.msb']
            elif opc2 == 3:
                insn.itype = self.name2icode['l.macu']
            elif opc2 == 4:
                insn.itype = self.name2icode['l.msbu']
            else:
                return 0

        # set flag imm16
        elif opc == 0x2f:
            if not rD in self.maptbl_setflag:
                return 0
            insn.itype = self.maptbl_setflag_imm[rD]
            insn.Op1.type = o_reg
            insn.Op1.reg = rA
            insn.Op2.type = o_imm
            insn.Op2.value = SIGNEXT(raw, 16)
        # set flag
        elif opc == 0x39:
            if not rD in self.maptbl_setflag:
                return 0
            insn.itype = self.maptbl_setflag[rD]
            insn.Op1.type = o_reg
            insn.Op1.reg = rA
            insn.Op2.type = o_reg
            insn.Op2.reg = rB

        # store
        elif opc >= 0x33 and opc <= 0x37:
            insn.itype = self.maptbl_store[opc - 0x33]
            addr_imm = (raw & 0x7ff) | (raw >> 10 & 0xf800)
            insn.Op1.type = o_displ
            insn.Op1.addr = SIGNEXT(addr_imm, 16)
            insn.Op1.reg = rA
            insn.Op2.type = o_reg
            insn.Op2.reg = rB

        # float
        elif opc == 0x32:
            masked = raw & 0xce
            opc2 = raw & 0xff
            # lf.sf*
            if masked >= 0x08 and masked < 0x0e:
                insn.Op1.type = o_reg
                insn.Op1.reg = rA
                insn.Op2.type = o_reg
                insn.Op2.reg = rB
            else:
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
                insn.Op2.type = o_reg
                insn.Op2.reg = rA
                # lf.{i,f,s,d}to*
                if masked == 0x04:
                    if rB != 0:
                        return 0
                else:
                    insn.Op3.type = o_reg
                    insn.Op3.reg = rB

            if opc2 in self.maptbl_float:
                insn.itype = self.maptbl_float[opc2]
            elif opc2 & 0xf0 == 0xd0:
                insn.itype = self.name2icode['lf.cust1.s']
            elif opc2 & 0xf0 == 0xe0:
                insn.itype = self.name2icode['lf.cust1.d']

        # vector
        elif opc == 0x0a:
            opc2 = raw & 0xff
            if opc2 in maptbl_vec:
                insn.itype = self.maptbl_vec[opc2]
                insn.Op1.type = o_reg
                insn.Op1.reg = rD
                insn.Op2.type = o_reg
                insn.Op2.reg = rA
                insn.Op3.type = o_reg
                insn.Op3.reg = rB
            elif opc2 & 0xf0 == 0xc0:
                insn.itype = self.name2icode['lv.cust1']
            elif opc2 & 0xf0 == 0xd0:
                insn.itype = self.name2icode['lv.cust2']
            elif opc2 & 0xf0 == 0xe0:
                insn.itype = self.name2icode['lv.cust3']
            elif opc2 & 0xf0 == 0xf0:
                insn.itype = self.name2icode['lv.cust4']
            else:
                return 0

        # reserved
        elif opc == 0x3c:
            insn.itype = self.name2icode['l.cust5']
            insn.Op1.type = o_reg
            insn.Op1.reg = rD
            insn.Op2.type = o_reg
            insn.Op2.reg = rA
            insn.Op3.type = o_reg
            insn.Op3.reg = rB
            insn.Op4.type = o_imm
            insn.Op4.value = raw >> 5 & 0x3f # L
            insn.Op5.type = o_imm
            insn.Op5.value = raw & 0x1f # K
        elif opc == 0x3d:
            insn.itype = self.name2icode['l.cust6']
        elif opc == 0x3e:
            insn.itype = self.name2icode['l.cust7']
        elif opc == 0x3f:
            insn.itype = self.name2icode['l.cust8']

        else:
            return 0
        return insn.size

    # ----------------------------------------------------------------------
    # should be faster than using decode_insn
    def decode_rD(self, raw):
        opc = (raw >> 26) & 0x3f
        rD = (raw >> 21) & 0x1f
        # arith
        if opc == 0x38:
            opc2 = raw & 0xf
            if opc2 == 7 or opc2 == 0xc: # l.muld, l.muldu
                return 0
            return rD
        # load, arith imm16
        if opc >= 0x1a and opc <= 0x2e:
            if opc < 0x1c or opc > 0x1f:
                return rD
            return 0
        if opc in [0x00, 0x11, 0x09]: # l.j, l.jr, l.rfe
            return -2
        if opc == 0x01 or opc == 0x12: # l.jal, l.jalr
            return -3
        if opc == 0x02 or opc == 0x06: # l.adrp, l.movhi, l.macrc
            return rD
        if opc == 0x32: # float
            # lf.sf*, lf.cust1.*
            if raw & 0xc7 >= 8:
                return 0
            return rD
        if opc == 0x0a: # vector
            # lv.cust*
            if raw & 0xff >= 0xc0:
                return 0
            return rD
        return 0

    # ----------------------------------------------------------------------
    def find_movhi(self, insn):
        reg = insn.Op2.reg
        ea = insn.ea
        if reg == 0:
            return
        for i in range(0, FIND_MOVHI_RANGE):
            if not get_flags(ea) & FF_FLOW:
                return False
            ea -= 4
            prev = get_wide_dword(ea)
            rD = self.decode_rD(prev)
            if rD < 0: # jump, call
                break
            if rD != reg:
                continue
            if prev & 0xfc010000 != 0x18000000: # l.movhi
                break

            value = (prev & 0xffff) << 16
            if insn.itype == self.itype_ori:
                value |= insn.Op3.value
            else:
                value += insn.Op3.value
            insn.Op3.value = value & 0xffffffff
            insn.auxpref = AUX_LO
            return

    # ----------------------------------------------------------------------
    def handle_operand(self, insn, op, dref_flag, no_delay):
        if op.type == o_near:
            if insn.get_canon_feature() & CF_CALL:
                insn.add_cref(op.addr, 0, fl_CN)
            elif no_delay != 0:
                insn.add_cref(op.addr, 0, fl_JN)

    def notify_emu(self, insn):
        Feature = insn.get_canon_feature()
        nd = ida_segregs.get_sreg(insn.ea, self.ireg_ND)

        if Feature & CF_USE1:
            self.handle_operand(insn, insn.Op1, dr_R, nd)
        if Feature & CF_CHG1:
            self.handle_operand(insn, insn.Op1, dr_W, nd)
        if Feature & CF_USE2:
            self.handle_operand(insn, insn.Op2, dr_R, nd)
        if Feature & CF_USE3:
            self.handle_operand(insn, insn.Op3, dr_R, nd)
        if Feature & CF_JUMP:
            remember_problem(PR_JUMP, insn.ea)

        # delay slot (CPUCFGR[ND] == 0)
        if nd == 0:
            # try:
            if get_flags(insn.ea) & FF_FLOW != 0:
                prev = get_wide_dword(insn.ea - 4)
                prev_opc = prev >> 26 & 0x3f
                if prev_opc in [0, 3, 4]: # l.j, l.bnf, l.bf
                    addr = (insn.ea - 4 + SIGNEXT(prev, 26) * 4) & 0xffffffff
                    insn.add_cref(addr, 0, fl_JN)
            # except:
            else:
                prev_opc = 0x40

            cur = get_wide_dword(insn.ea)
            flow = cur >> 26 & 0x3f != 0x09 # l.rfe
            if flow:
                flow = not prev_opc in [0, 0x11] # l.j, l.jr
        # no delay slot
        else:
            flow = Feature & CF_STOP == 0
        if flow:
            add_cref(insn.ea, insn.ea + insn.size, fl_F)

        return True

    # ----------------------------------------------------------------------
    def notify_out_operand(self, ctx, op):
        optype = op.type

        if optype == o_reg:
            ctx.out_register(self.reg_names[op.reg])
        elif optype == o_imm:
            if ctx.insn.auxpref & AUX_LO:
                ctx.out_line('lo', COLOR_KEYWORD)
                ctx.out_symbol('(')
                ctx.out_value(op, OOFW_32)
                ctx.out_symbol(')')
            else:
                # TODO: OOFW_IMM uses op.dtype
                ctx.out_value(op, OOFW_32 | OOF_SIGNED)
        elif optype == o_near:
            r = ctx.out_name_expr(op, op.addr, BADADDR)
            if not r:
                ctx.out_tagon(COLOR_ERROR)
                ctx.out_long(op.addr, 16)
                ctx.out_tagoff(COLOR_ERROR)
                remember_problem(PR_NONAME, ctx.insn.ea)
        elif optype == o_displ:
            # 16-bit index is signed
            ctx.out_value(op, OOF_ADDR | OOFW_16 | OOF_SIGNED)
            ctx.out_symbol('(')
            ctx.out_register(self.reg_names[op.reg])
            ctx.out_symbol(')')
        else:
            return False

        return True

    # ----------------------------------------------------------------------
    def notify_newfile(self, ctx):
        """A new file is loaded (already)"""
        for n in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(n)
            if seg:
               ida_segregs.set_default_sreg_value(seg, self.ireg_ND, DEFAULT_ND)
        return 0

    # ----------------------------------------------------------------------
    def notify_out_assumes(self, ctx):
        """function to produce assume directives"""
        # or idc.get_sreg(ctx.insn.ea, "ND")
        seg = ida_segment.getseg(ctx.bin_ea)
        if not seg:
            return 0

        nd = ida_segregs.get_sreg(ctx.bin_ea, self.ireg_ND)
        if ctx.bin_ea == seg.start_ea:
            prev_nd = ~nd
        else:
            prev_nd = ida_segregs.get_sreg(ctx.bin_ea - 1, self.ireg_ND)

        if nd != prev_nd:
            ctx.out_line("# ND = " + str(nd), COLOR_REGCMT)
            ctx.flush_outbuf()
        return 1

    # ----------------------------------------------------------------------
    def out_mnem(self, ctx):
        ctx.out_mnem(16, "")
        return 1

    # ----------------------------------------------------------------------
    def notify_out_insn(self, ctx):
        ctx.out_mnemonic()

        if ctx.insn.Op1.type != o_void:
            ctx.out_one_operand(0)
        for i in range(1, 5):
            if ctx.insn[i].type == o_void:
                break
            ctx.out_symbol(',')
            ctx.out_char(' ')
            ctx.out_one_operand(i)

        ctx.set_gen_cmt()
        ctx.flush_outbuf()
        return True

    # ----------------------------------------------------------------------

    # Array of instructions
    instruc = [
        {'name': '', 'feature': 0, 'cmt': 'bad opcode'},

        # opcode 0x00..0x05
        {'name': 'l.j',     'feature': CF_USE1 | CF_JUMP | CF_STOP, 'cmt': 'Jump'},
        {'name': 'l.jal',   'feature': CF_USE1 | CF_CALL, 'cmt': 'Jump and Link'},
        {'name': 'l.adrp',  'feature': CF_CHG1 | CF_USE2, 'cmt': 'Compute Instruction Relative Address'},
        {'name': 'l.bnf',   'feature': CF_USE1 | CF_JUMP, 'cmt': 'Branch if No Flag'},
        {'name': 'l.bf',    'feature': CF_USE1 | CF_JUMP, 'cmt': 'Branch if Flag'},
        {'name': 'l.nop',   'feature': CF_USE1, 'cmt': 'No Operation'},
        # opcode 0x06
        {'name': 'l.movhi', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Move Immediate High'},
        {'name': 'l.macrc', 'feature': CF_CHG1, 'cmt': 'MAC Read and Clear'},
        # opcode 0x08
        {'name': 'l.sys',   'feature': CF_USE1, 'cmt': 'System Call'},
        {'name': 'l.trap',  'feature': CF_USE1, 'cmt': 'Trap'},
        {'name': 'l.msync', 'feature': 0, 'cmt': 'Memory Synchronization'},
        {'name': 'l.psync', 'feature': 0, 'cmt': 'Pipeline Synchronization'},
        {'name': 'l.csync', 'feature': 0, 'cmt': 'Context Synchronization'},
        # opcode 0x09
        {'name': 'l.rfe',   'feature': CF_STOP, 'cmt': 'Return From Exception'},
        # opcode 0x0a
        {'name': 'lv.cust1', 'feature': 0, 'cmt': 'Reserved for Custom Instructions'},
        {'name': 'lv.cust2', 'feature': 0, 'cmt': 'Reserved for Custom Instructions'},
        {'name': 'lv.cust3', 'feature': 0, 'cmt': 'Reserved for Custom Instructions'},
        {'name': 'lv.cust4', 'feature': 0, 'cmt': 'Reserved for Custom Instructions'},
        # lv.{all,any}_{cc}.{b,h}
        {'name': 'lv.add.b',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Add Signed'},
        {'name': 'lv.add.h',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Add Signed'},
        {'name': 'lv.adds.b',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Add Signed Saturated'},
        {'name': 'lv.adds.h',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Add Signed Saturated'},
        {'name': 'lv.addu.b',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Add Unsigned'},
        {'name': 'lv.addu.h',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Add Unsigned'},
        {'name': 'lv.addus.b',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Add Unsigned Saturated'},
        {'name': 'lv.addus.h',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Add Unsigned Saturated'},
        {'name': 'lv.and',      'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector And'},
        {'name': 'lv.avg.b',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Average'},
        {'name': 'lv.avg.h',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Average'},
        # lv.cmp_{cc}.{b,h}
        {'name': 'lv.madds.h',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Multiply Add Signed Saturated'},
        {'name': 'lv.max.b',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Maximum'},
        {'name': 'lv.max.h',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Maximum'},
        {'name': 'lv.merge.b',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Merge'},
        {'name': 'lv.merge.h',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Merge'},
        {'name': 'lv.min.b',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Minimum'},
        {'name': 'lv.min.h',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Minimum'},
        {'name': 'lv.msubs.h',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Multiply Subtract Signed Saturated'},
        {'name': 'lv.muls.h',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Multiply Signed Saturated'},
        {'name': 'lv.nand',     'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Not And'},
        {'name': 'lv.nor',      'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Not Or'},
        {'name': 'lv.or',       'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Or'},
        {'name': 'lv.pack.b',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Pack'},
        {'name': 'lv.pack.h',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-word Elements Pack'},
        {'name': 'lv.packs.b',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Pack Signed Saturated'},
        {'name': 'lv.packs.h',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-word Elements Pack Signed Saturated'},
        {'name': 'lv.packus.b', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Pack Unsigned Saturated'},
        {'name': 'lv.packus.h', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-word Elements Pack Unsigned Saturated'},
        {'name': 'lv.perm.n',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Nibble Elements Permute'},
        {'name': 'lv.rl.b',     'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Rotate Left'},
        {'name': 'lv.rl.h',     'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Rotate Left'},
        {'name': 'lv.sll.b',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Shift Left Logical'},
        {'name': 'lv.sll.h',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Shift Left Logical'},
        {'name': 'lv.sll',      'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Shift Left Logical'},
        {'name': 'lv.srl.b',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Shift Right Logical'},
        {'name': 'lv.srl.h',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Shift Right Logical'},
        {'name': 'lv.sra.b',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Shift Right Arithmetic'},
        {'name': 'lv.sra.h',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Shift Right Arithmetic'},
        {'name': 'lv.srl',      'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Shift Right Logical'},
        {'name': 'lv.sub.b',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Subtract Signed'},
        {'name': 'lv.sub.h',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Subtract Signed'},
        {'name': 'lv.subs.b',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Subtract Signed Saturated'},
        {'name': 'lv.subs.h',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Subtract Signed Saturated'},
        {'name': 'lv.subu.b',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Subtract Unsigned'},
        {'name': 'lv.subu.h',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Subtract Unsigned'},
        {'name': 'lv.subus.b',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Subtract Unsigned Saturated'},
        {'name': 'lv.subus.h',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Subtract Unsigned Saturated'},
        {'name': 'lv.unpack.b', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Byte Elements Unpack'},
        {'name': 'lv.unpack.h', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Half-Word Elements Unpack'},
        {'name': 'lv.xor',      'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Vector Exclusive Or'},

        # opcode 0x11..0x13
        {'name': 'l.jr',    'feature': CF_USE1 | CF_JUMP | CF_STOP, 'cmt': 'Jump Register'},
        {'name': 'l.jalr',  'feature': CF_USE1 | CF_CALL, 'cmt': 'Jump and Link Register'},
        {'name': 'l.maci',  'feature': CF_USE1 | CF_USE2, 'cmt': 'Multiply Immediate Signed and Accumulate'},

        # opcode 0x1a..0x26
        {'name': 'l.lf',  'feature': CF_CHG1 | CF_USE2, 'cmt': 'Load Single Float Word with NaN Boxing'},
        {'name': 'l.lwa', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Load Single Word Atomic'},
        {'name': 'l.cust1', 'feature': 0, 'cmt': 'Reserved for Custom Instructions'},
        {'name': 'l.cust2', 'feature': 0, 'cmt': 'Reserved for Custom Instructions'},
        {'name': 'l.cust3', 'feature': 0, 'cmt': 'Reserved for Custom Instructions'},
        {'name': 'l.cust4', 'feature': 0, 'cmt': 'Reserved for Custom Instructions'},
        {'name': 'l.ld',  'feature': CF_CHG1 | CF_USE2, 'cmt': 'Load Double Word'},
        {'name': 'l.lwz', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Load Single Word and Extend with Zero'},
        {'name': 'l.lws', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Load Single Word and Extend with Sign'},
        {'name': 'l.lbz', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Load Byte and Extend with Zero'},
        {'name': 'l.lbs', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Load Byte and Extend with Sign'},
        {'name': 'l.lhz', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Load Half Word and Extend with Zero'},
        {'name': 'l.lhs', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Load Half Word and Extend with Sign'},

        # opcode 0x27..0x2d
        {'name': 'l.addi',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Add Immediate Signed'},
        {'name': 'l.addic', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Add Immediate Signed and Carry'},
        {'name': 'l.andi',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'And with Immediate Half Word'},
        {'name': 'l.ori',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Or with Immediate Half Word'},
        {'name': 'l.xori',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Exclusive Or with Immediate Half Word'},
        {'name': 'l.muli',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Multiply Immediate Signed'},
        {'name': 'l.mfspr', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Move From Special-Purpose Register'},
        # opcode 0x2e
        {'name': 'l.slli', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Shift Left Logical with Immediate'},
        {'name': 'l.srli', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Shift Right Logical with Immediate'},
        {'name': 'l.srai', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Shift Right Logical with Immediate'},
        {'name': 'l.rori', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Rotate Right with Immediate'},
        # opcode 0x2f
        # l.sf{cc}i
        # opcode 0x30
        {'name': 'l.mtspr', 'feature': CF_USE1 | CF_USE2 | CF_USE3, 'cmt': 'Move To Special-Purpose Register'},
        # opcode 0x31
        {'name': 'l.mac', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Multiply Signed and Accumulate'},
        {'name': 'l.msb', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Multiply Signed and Subtract'},
        {'name': 'l.macu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Multiply Unsigned and Accumulate'},
        {'name': 'l.msbu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Multiply Unsigned and Subtract'},

        # opcode 0x32
        {'name': 'lf.add.s',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Add Floating-Point Single-Precision'},
        {'name': 'lf.sub.s',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Subtract Floating-Point Single-Precision'},
        {'name': 'lf.mul.s',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Multiply Floating-Point Single-Precision'},
        {'name': 'lf.div.s',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Divide Floating-Point Single-Precision'},
        {'name': 'lf.itof.s', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Integer To Floating-Point Single-Precision'},
        {'name': 'lf.ftoi.s', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Floating-Point Single-Precision To Integer'},
        {'name': 'lf.rem.s',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Remainder Floating-Point Single-Precision'},
        {'name': 'lf.madd.s', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Multiply and Add Floating-Point Single-Precision'},
        # lf.sf{cc}.s
        {'name': 'lf.add.d',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Add Floating-Point Double-Precision'},
        {'name': 'lf.sub.d',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Subtract Floating-Point Double-Precision'},
        {'name': 'lf.mul.d',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Multiply Floating-Point Double-Precision'},
        {'name': 'lf.div.d',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Divide Floating-Point Double-Precision'},
        {'name': 'lf.itof.d', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Integer To Floating-Point Double-Precision'},
        {'name': 'lf.ftoi.d', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Floating-Point Double-Precision To Integer'},
        {'name': 'lf.rem.d',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Remainder Floating-Point Double-Precision'},
        {'name': 'lf.madd.d', 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Multiply and Add Floating-Point Double-Precision'},
        # lf.sf{cc}.d
        # lf.sfu{cc}.s
        {'name': 'lf.stod.d',  'feature': CF_CHG1 | CF_USE2, 'cmt': 'Convert Single-precision Floating-Point Number To Double-precision'},
        {'name': 'lf.dtos.d',  'feature': CF_CHG1 | CF_USE2, 'cmt': 'Convert Double-precision Floating-Point Number to Single-precision'},
        # lf.sfu{cc}.d
        {'name': 'lf.cust1.s', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Reserved for Custom Instructions'},
        {'name': 'lf.cust1.d', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Reserved for Custom Instructions'},

        # opcode 0x33..0x37
        {'name': 'l.swa', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Store Single Word Atomic'},
        {'name': 'l.sd',  'feature': CF_USE1 | CF_USE2, 'cmt': 'Store Double Word'},
        {'name': 'l.sw',  'feature': CF_USE1 | CF_USE2, 'cmt': 'Store Single Word'},
        {'name': 'l.sb',  'feature': CF_USE1 | CF_USE2, 'cmt': 'Store Byte'},
        {'name': 'l.sh',  'feature': CF_USE1 | CF_USE2, 'cmt': 'Store Half Word'},
        # opcode 0x38
        {'name': 'l.exths', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Extend Half Word with Sign'},
        {'name': 'l.extbs', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Extend Byte with Sign'},
        {'name': 'l.exthz', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Extend Half Word with Zero'},
        {'name': 'l.extbz', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Extend Byte with Zero'},
        {'name': 'l.extws', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Extend Word with Sign'},
        {'name': 'l.extwz', 'feature': CF_CHG1 | CF_USE2, 'cmt': 'Extend Word with Zero'},
        {'name': 'l.add',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Add Signed'},
        {'name': 'l.addc',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Add Signed and Carry'},
        {'name': 'l.sub',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Subtract Signed'},
        {'name': 'l.and',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'And'},
        {'name': 'l.or',    'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Or'},
        {'name': 'l.xor',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Exclusive Or'},
        {'name': 'l.sll',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Shift Left Logical'},
        {'name': 'l.srl',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Shift Right Logical'},
        {'name': 'l.sra',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Shift Right Arithmetic'},
        {'name': 'l.ror',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Rotate Right'},
        {'name': 'l.cmov',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Conditional Move'},
        {'name': 'l.ff1',   'feature': CF_CHG1 | CF_USE2, 'cmt': 'Find First 1'},
        {'name': 'l.fl1',   'feature': CF_CHG1 | CF_USE2, 'cmt': 'Find Last 1'},
        {'name': 'l.mul',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Multiply Signed'},
        {'name': 'l.muld',  'feature': CF_USE1 | CF_USE2, 'cmt': 'Multiply Signed to Double'},
        {'name': 'l.div',   'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Divide Signed'},
        {'name': 'l.divu',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Divide Unsigned'},
        {'name': 'l.mulu',  'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': 'Multiply Unsigned'},
        {'name': 'l.muldu', 'feature': CF_USE1 | CF_USE2, 'cmt': 'Multiply Unsigned to Double'},

        # opcode 0x39
        # l.sf{cc}
        # opcode 0x3c..0x3f
        {'name': 'l.cust5', 'feature': CF_USE1 | CF_USE2 | CF_USE3 | CF_USE4 | CF_USE5, 'cmt': 'Reserved for Custom Instructions'},
        {'name': 'l.cust6', 'feature': 0, 'cmt': 'Reserved for Custom Instructions'},
        {'name': 'l.cust7', 'feature': 0, 'cmt': 'Reserved for Custom Instructions'},
        {'name': 'l.cust8', 'feature': 0, 'cmt': 'Reserved for Custom Instructions'}
    ]

    # icode of the first instruction
    instruc_start = 0

    def maptbl_icode(self, tab):
        for i, s in enumerate(tab):
            tab[i] = self.name2icode[s]

    def mapdict_icode(self, tab):
        for i, s in tab.items():
            tab[i] = self.name2icode[s]

    def init_instructions(self):

        setflag_names = [
            ['eq', 'Equal', ''],
            ['ne', 'Not Equal', ''],
            ['gtu', 'Greater Than', ' Unsigned'],
            ['geu', 'Greater or Equal Than', ' Unsigned'],
            ['ltu', 'Less Than', ' Unsigned'],
            ['leu', 'Less or Equal Than', ' Unsigned'],
            ['gts', 'Greater Than', ' Signed'],
            ['ges', 'Greater or Equal Than', ' Signed'],
            ['lts', 'Less Than', ' Signed'],
            ['les', 'Less or Equal Than', ' Signed']
        ]

        # opcode 0x2f, 0x39
        for x in setflag_names:
            name = 'l.sf' + x[0]
            cmt = 'Set Flag if ' + x[1]
            self.instruc.append({'name': name, 'feature': CF_USE1 | CF_USE2, 'cmt': cmt + x[2]})
            self.instruc.append({'name': name + 'i', 'feature': CF_USE1 | CF_USE2, 'cmt': cmt + ' Immediate' + x[2]})

        vcmp_names = [
            ['eq', 'Equal'],
            ['ge', 'Greater Than or Equal To'],
            ['gt', 'Greater Than'],
            ['le', 'Less Than or Equal To'],
            ['lt', 'Less Than'],
            ['ne', 'Not Equal']
        ]

        # opcode 0x0a
        for n1, c1 in [['all_', 'All '], ['any_', 'Any '], ['cmp_', 'Compare ']]:
            for x in vcmp_names:
                for n2, c2 in [['.b', 'Byte'], ['.h', 'Half-Word']]:
                    name = 'lv.' + n1 + x[0] + n2
                    cmt = 'Vector ' + c2 + ' Elements ' + c1 + x[1]
                    self.instruc.append({'name': name, 'feature': CF_CHG1 | CF_USE2 | CF_USE3, 'cmt': cmt})

        fcmp_names = [
            ['eq', 'Equal'],
            ['ne', 'Not Equal'],
            ['gt', 'Greater Than'],
            ['ge', 'Greater Than or Equal'],
            ['lt', 'Less Than'],
            ['le', 'Less Than or Equal'],
            ['ueq', 'Unordered or Equal'],
            ['une', 'Unordered or Not Equal'],
            ['ugt', 'Unordered or Greater Than'],
            ['uge', 'Unordered or Greater Than or Equal'],
            ['ult', 'Unordered or Less Than'],
            ['ule', 'Unordered or Less Than or Equal'],
            ['un', 'Unordered']
        ]

        # opcode 0x32
        for n, c in [['.s', 'Single'], ['.d', 'Double']]:
            for x in fcmp_names:
                name = 'lf.sf' + x[0] + n
                cmt = 'Set Flag if ' + x[1] + ' Floating-Point ' + c + '-Precision'
                self.instruc.append({'name': name, 'feature': CF_USE1 | CF_USE2, 'cmt': cmt})

        self.name2icode = {}
        for i, x in enumerate(self.instruc):
            self.name2icode[x['name']] = i

        # icode of the last instruction + 1
        self.instruc_end = len(self.instruc)

        self.itype_movhi = self.name2icode['l.movhi']
        self.itype_ori = self.name2icode['l.ori']

        self.maptbl_shift_imm = list()
        for s in self.maptbl_shift:
            self.maptbl_shift_imm.append(self.name2icode[s + 'i'])

        self.maptbl_setflag_imm = dict()
        for i, s in self.maptbl_setflag.items():
            self.maptbl_setflag_imm[i] = self.name2icode[s + 'i']

        self.maptbl_icode(self.maptbl_jump)
        self.maptbl_icode(self.maptbl_shift)
        self.maptbl_icode(self.maptbl_load)
        self.maptbl_icode(self.maptbl_store)
        self.maptbl_icode(self.maptbl_27)
        self.maptbl_icode(self.maptbl_38)
        self.mapdict_icode(self.maptbl_setflag)
        self.mapdict_icode(self.maptbl_float)
        self.mapdict_icode(self.maptbl_vec)

    # ----------------------------------------------------------------------

    # Registers definition
    reg_names = [
        # General purpose registers
        # r0: fixed to zero
        # r1: SP (Stack pointer)
        # r2: FP (Frame pointer)
        # r3..r8: function args
        # r9: LR (Link Register)
        # r10: TLS (Thread Local Storage)
        # r11: return value
        # r12: return value high
        # r13..r31: odd = temp, even = callee-saved
        "r0",  "sp",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
        "r8",  "lr",  "r10", "r11", "r12", "r13", "r14", "r15",
        "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
        "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",

        # Fake segment registers
        "CS", "ND", "DS"
    ]

    def init_registers(self):
        self.ireg_ND = self.reg_names.index("ND")

        # number of CS register
        self.reg_code_sreg = self.reg_names.index("CS")

        # number of DS register
        self.reg_data_sreg = self.reg_names.index("DS")

        # Segment register information (use virtual CS and DS registers if your
        # processor doesn't have segment registers):
        self.reg_first_sreg = self.reg_code_sreg
        self.reg_last_sreg  = self.reg_data_sreg

    # ----------------------------------------------------------------------
    def __init__(self):
        processor_t.__init__(self)
        self.init_instructions()
        self.init_registers()

# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from processor_t
def PROCESSOR_ENTRY():
    return or1k_processor_t()
