import struct
import re

import idaapi
import idc
import ida_bytes
import ida_ua
import ida_segment
import ida_auto
import ida_hexrays
import ida_lines
import ida_xref
import ida_funcs
import ida_kernwin

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_RBP, UC_X86_REG_RSP,
    UC_X86_REG_R8, UC_X86_REG_R9, UC_X86_REG_R10, UC_X86_REG_R11,
    UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14, UC_X86_REG_R15,
    UC_X86_REG_RIP, UC_X86_REG_EFLAGS,
)

BADADDR = idaapi.BADADDR

MASK64 = 0xffffffffffffffff

PAGE_SIZE = 4096

MAX_X86_INSN_SIZE = 15

MAX_BACK_INSNS = 288

MAX_EMU_INSNS = 2000

FINAL_AUTO_WAIT = True

RUN_MAKECODE_FIRST = True

ANALYZE_ALL_EXEC_AT_START = True

AGGRESSIVE_MAKE_CODE_ALL_EXEC = True

FIRST_SEGMENT_ONLY = True

FIRST_SEGMENT_MUST_BE_EXEC = True

FIRST_SEGMENT_INDEX = 0

ENABLE_JMP_RAX_PATCH = True

JMP_RAX_ONLY_MAX_PASSES = 100

JMP_RAX_ONLY_AUTO_WAIT = True

ENABLE_GLOBAL_QWORD_REBASE_PATCH = True

GLOBAL_QWORD_REBASE_BASE = 0x7FFFEF8F9000

GLOBAL_QWORD_REBASE_ALIGN = 8

GLOBAL_QWORD_REBASE_MAX = 65536

GLOBAL_QWORD_REBASE_MAX_PASSES = 3

GLOBAL_QWORD_REBASE_REQUIRE_ALL_XREFS_SAFE = True

GLOBAL_QWORD_REBASE_PATCH_ONLY_TARGET_RANGE = True

GLOBAL_QWORD_REBASE_SKIP_UNINIT_MEM_POINTER_VALUE = True

GLOBAL_QWORD_REBASE_SKIP_UNINIT_MEM_STORAGE = True

GLOBAL_QWORD_REBASE_SKIP_UNKNOWN_QWORD_VALUE = True

GLOBAL_QWORD_MEMOP_SUPPORTED_MNEMS = {'add', 'sub'}

GLOBAL_QWORD_MEMOP_SKIP_RSP_DST = True

STACK_BASE = 0x7000000000

STACK_SIZE = 0x200000

STACK_RESET_SIZE = 0x20000

ZERO_STACK_CHUNK = b'\x00' * STACK_RESET_SIZE

_GLOBAL_UC_CTX = None

REG64 = {'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'}

REG32_TO_64 = {'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx', 'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp', 'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11', 'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15'}

REG16_TO_64 = {'ax': 'rax', 'bx': 'rbx', 'cx': 'rcx', 'dx': 'rdx', 'si': 'rsi', 'di': 'rdi', 'bp': 'rbp', 'sp': 'rsp', 'r8w': 'r8', 'r9w': 'r9', 'r10w': 'r10', 'r11w': 'r11', 'r12w': 'r12', 'r13w': 'r13', 'r14w': 'r14', 'r15w': 'r15'}

REG8_TO_64 = {'al': 'rax', 'bl': 'rbx', 'cl': 'rcx', 'dl': 'rdx', 'sil': 'rsi', 'dil': 'rdi', 'bpl': 'rbp', 'spl': 'rsp', 'r8b': 'r8', 'r9b': 'r9', 'r10b': 'r10', 'r11b': 'r11', 'r12b': 'r12', 'r13b': 'r13', 'r14b': 'r14', 'r15b': 'r15'}

UC_REG64 = {'rax': UC_X86_REG_RAX, 'rbx': UC_X86_REG_RBX, 'rcx': UC_X86_REG_RCX, 'rdx': UC_X86_REG_RDX, 'rsi': UC_X86_REG_RSI, 'rdi': UC_X86_REG_RDI, 'rbp': UC_X86_REG_RBP, 'rsp': UC_X86_REG_RSP, 'r8': UC_X86_REG_R8, 'r9': UC_X86_REG_R9, 'r10': UC_X86_REG_R10, 'r11': UC_X86_REG_R11, 'r12': UC_X86_REG_R12, 'r13': UC_X86_REG_R13, 'r14': UC_X86_REG_R14, 'r15': UC_X86_REG_R15}

REG_TOKEN_RE = re.compile('\\b(?:r1[0-5]|r[8-9]|rax|rbx|rcx|rdx|rsi|rdi|rbp|rsp|e[abcd]x|esi|edi|ebp|esp|r(?:8|9|1[0-5])d|[abcd]x|si|di|bp|sp|r(?:8|9|1[0-5])w|[abcd]l|sil|dil|bpl|spl|r(?:8|9|1[0-5])b|rip)\\b', re.IGNORECASE)

COND_ALIAS_TO_CANON = {'o': 'o', 'no': 'no', 'b': 'b', 'c': 'b', 'nae': 'b', 'ae': 'ae', 'nb': 'ae', 'nc': 'ae', 'e': 'e', 'z': 'e', 'ne': 'ne', 'nz': 'ne', 'be': 'be', 'na': 'be', 'a': 'a', 'nbe': 'a', 's': 's', 'ns': 'ns', 'p': 'p', 'pe': 'p', 'np': 'np', 'po': 'np', 'l': 'l', 'nge': 'l', 'ge': 'ge', 'nl': 'ge', 'le': 'le', 'ng': 'le', 'g': 'g', 'nle': 'g'}

COND_TO_JCC = {'o': ('jo', 128), 'no': ('jno', 129), 'b': ('jb', 130), 'ae': ('jae', 131), 'e': ('jz', 132), 'ne': ('jnz', 133), 'be': ('jbe', 134), 'a': ('ja', 135), 's': ('js', 136), 'ns': ('jns', 137), 'p': ('jp', 138), 'np': ('jnp', 139), 'l': ('jl', 140), 'ge': ('jge', 141), 'le': ('jle', 142), 'g': ('jg', 143)}

CANON_CONDS = ['e', 'ne', 'l', 'ge', 'le', 'g', 'b', 'ae', 'be', 'a', 'o', 'no', 's', 'ns', 'p', 'np']

TEST_CASES = [('eq_1_1', 1, 1), ('eq_0_0', 0, 0), ('lt_1_2', 1, 2), ('gt_2_1', 2, 1), ('lt_0_1', 0, 1), ('gt_1_0', 1, 0), ('signed_lt_uabove', 18446744073709551615, 1), ('signed_gt_ubelow', 1, 18446744073709551615), ('of_min_minus_1', 9223372036854775808, 1), ('of_max_minus_neg1', 9223372036854775807, 18446744073709551615), ('of_min_minus_max', 9223372036854775808, 9223372036854775807), ('of_max_minus_min', 9223372036854775807, 9223372036854775808), ('parity_even', 3, 0), ('parity_odd', 1, 0)]

def page_down(x):
    return x & ~(PAGE_SIZE - 1)

def page_up(x):
    return x + PAGE_SIZE - 1 & ~(PAGE_SIZE - 1)

def ea_s(ea):
    if ea is None or ea == BADADDR:
        return 'BADADDR'
    return '0x%016X' % ea

def log(s):
    print('[deob_uc_loop] ' + s)

def mnem(ea):
    return idc.print_insn_mnem(ea).lower()

def op(ea, n):
    return idc.print_operand(ea, n).lower().replace(' ', '')

def item_size(ea):
    size = idc.get_item_size(ea)
    if size <= 0:
        size = 1
    return size

def item_end(ea):
    return ea + item_size(ea)

def previ(ea):
    return idc.prev_head(ea, idc.get_inf_attr(idc.INF_MIN_EA))

def nexti(ea):
    return idc.next_head(ea, idc.get_inf_attr(idc.INF_MAX_EA))

def is_code_head(ea):
    flags = ida_bytes.get_full_flags(ea)
    try:
        return ida_bytes.is_code(flags) and ida_bytes.is_head(flags)
    except Exception:
        return False

def normalize_reg(x):
    x = x.lower().strip()
    if x in REG64:
        return x
    if x in REG32_TO_64:
        return REG32_TO_64[x]
    if x in REG16_TO_64:
        return REG16_TO_64[x]
    if x in REG8_TO_64:
        return REG8_TO_64[x]
    return x

def is_reg_any(x):
    x = x.lower().strip()
    return x in REG64 or x in REG32_TO_64 or x in REG16_TO_64 or (x in REG8_TO_64)

def reg_bits(x):
    x = x.lower().strip()
    if x in REG64:
        return 64
    if x in REG32_TO_64:
        return 32
    if x in REG16_TO_64:
        return 16
    if x in REG8_TO_64:
        return 8
    return 0

def regs_in_text(s):
    regs = set()
    if not s:
        return regs
    for m in REG_TOKEN_RE.finditer(s.lower()):
        r = normalize_reg(m.group(0))
        if r == 'rip':
            continue
        if r in REG64:
            regs.add(r)
    return regs

def dst_reg_of_insn(ea):
    dst = op(ea, 0)
    if not dst:
        return None
    if not is_reg_any(dst):
        return None
    dst64 = normalize_reg(dst)
    if dst64 not in REG64:
        return None
    return dst64

def mask_for_bits(bits):
    return (1 << bits) - 1

def sign_bit_for_bits(bits):
    return 1 << bits - 1

def parity8(x):
    x &= 255
    return bin(x).count('1') % 2 == 0

def flags_sub(a, b, bits):
    mask = mask_for_bits(bits)
    sign = sign_bit_for_bits(bits)
    a &= mask
    b &= mask
    result = a - b & mask
    return {'CF': a < b, 'ZF': result == 0, 'SF': bool(result & sign), 'OF': bool((a ^ b) & (a ^ result) & sign != 0), 'PF': parity8(result)}

def eval_cond(cond, flags):
    cond = COND_ALIAS_TO_CANON.get(cond, cond)
    CF = bool(flags.get('CF', False))
    ZF = bool(flags.get('ZF', False))
    SF = bool(flags.get('SF', False))
    OF = bool(flags.get('OF', False))
    PF = bool(flags.get('PF', False))
    if cond == 'o':
        return OF
    if cond == 'no':
        return not OF
    if cond == 'b':
        return CF
    if cond == 'ae':
        return not CF
    if cond == 'e':
        return ZF
    if cond == 'ne':
        return not ZF
    if cond == 'be':
        return CF or ZF
    if cond == 'a':
        return not CF and (not ZF)
    if cond == 's':
        return SF
    if cond == 'ns':
        return not SF
    if cond == 'p':
        return PF
    if cond == 'np':
        return not PF
    if cond == 'l':
        return SF != OF
    if cond == 'ge':
        return SF == OF
    if cond == 'le':
        return ZF or SF != OF
    if cond == 'g':
        return not ZF and SF == OF
    raise ValueError('unknown condition: %s' % cond)

def get_first_target_segment():
    if FIRST_SEGMENT_MUST_BE_EXEC:
        idx = 0
        for i in range(ida_segment.get_segm_qty()):
            seg = ida_segment.getnseg(i)
            if not seg:
                continue
            try:
                if not seg.perm & ida_segment.SEGPERM_EXEC:
                    continue
            except Exception:
                continue
            if idx == FIRST_SEGMENT_INDEX:
                return seg
            idx += 1
        return None
    return ida_segment.getnseg(FIRST_SEGMENT_INDEX)

def get_first_segment_range():
    seg = get_first_target_segment()
    if not seg:
        return None
    start = int(seg.start_ea)
    end = int(seg.end_ea)
    if start == BADADDR or end == BADADDR or end <= start:
        return None
    return (start, end)

def get_exec_ranges():
    ranges = []
    if FIRST_SEGMENT_ONLY:
        seg = get_first_target_segment()
        if not seg:
            return ranges
        start = int(seg.start_ea)
        end = int(seg.end_ea)
        if start != BADADDR and end != BADADDR and (end > start):
            ranges.append((start, end))
        return ranges
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue
        try:
            if not seg.perm & ida_segment.SEGPERM_EXEC:
                continue
        except Exception:
            pass
        start = int(seg.start_ea)
        end = int(seg.end_ea)
        if start == BADADDR or end == BADADDR or end <= start:
            continue
        ranges.append((start, end))
    return ranges

def get_loaded_segment_ranges():
    ranges = []
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        if not seg:
            continue
        start = int(seg.start_ea)
        end = int(seg.end_ea)
        if start == BADADDR or end == BADADDR or end <= start:
            continue
        ranges.append((start, end))
    return ranges

def ea_in_ranges(ea, ranges):
    for start, end in ranges:
        if start <= ea < end:
            return True
    return False

def ea_in_exec(ea):
    return ea_in_ranges(ea, get_exec_ranges())

def ea_in_loaded(ea):
    return ea_in_ranges(ea, get_loaded_segment_ranges())

def is_uninitialized_memory_ea(ea, size=1):
    if ea is None or ea == BADADDR:
        return False
    ea = int(ea) & MASK64
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    try:
        if seg.perm & ida_segment.SEGPERM_EXEC:
            return False
    except Exception:
        pass
    if ea + max(1, int(size)) > int(seg.end_ea):
        return True
    try:
        data = ida_bytes.get_bytes(ea, max(1, int(size)))
    except Exception:
        data = None
    if data is None or len(data) != max(1, int(size)):
        return True
    if max(1, int(size)) == 8 and int.from_bytes(data, 'little') == MASK64:
        return True
    if max(1, int(size)) == 1 and data == b'\xff':
        return True
    return False

def qword_storage_is_uninitialized(mem_ea):
    if mem_ea is None or mem_ea == BADADDR:
        return False
    ea = int(mem_ea) & MASK64
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    try:
        if seg.perm & ida_segment.SEGPERM_EXEC:
            return False
    except Exception:
        pass
    if ea + 8 > int(seg.end_ea):
        return True
    data = ida_bytes.get_bytes(ea, 8)
    if data is None or len(data) != 8:
        return True
    return int.from_bytes(data, 'little') == MASK64

def qword_value_is_unknown_sentinel(value):
    return (value & MASK64) == MASK64

def qword_value_points_to_uninitialized_memory(value):
    return is_uninitialized_memory_ea(value & MASK64, 1)

def merge_ranges(ranges):
    if not ranges:
        return []
    ranges = sorted(((page_down(start), page_up(end)) for start, end in ranges))
    merged = []
    cur_start, cur_end = ranges[0]
    for start, end in ranges[1:]:
        if start <= cur_end:
            cur_end = max(cur_end, end)
        else:
            merged.append((cur_start, cur_end))
            cur_start, cur_end = (start, end)
    merged.append((cur_start, cur_end))
    return merged

def ida_get_bytes_fill(start, size):
    data = ida_bytes.get_bytes(start, size)
    if data is None:
        return b'\x00' * size
    if len(data) < size:
        data += b'\x00' * (size - len(data))
    return data

def plan_all_exec_segments():
    ranges = get_exec_ranges()
    for start, end in ranges:
        try:
            ida_auto.plan_range(start, end)
        except Exception:
            pass
    ida_auto.auto_wait()

def force_make_code_range(start, end):
    total_created = 0
    total_failed = 0
    ea = start
    while ea < end:
        flags = ida_bytes.get_full_flags(ea)
        try:
            if ida_bytes.is_code(flags) and ida_bytes.is_head(flags):
                ea += max(item_size(ea), 1)
                continue
        except Exception:
            pass
        try:
            ida_bytes.del_items(ea, ida_bytes.DELIT_EXPAND, MAX_X86_INSN_SIZE)
        except Exception:
            pass
        made = False
        try:
            made = bool(ida_ua.create_insn(ea))
        except Exception:
            made = False
        if not made:
            try:
                made = bool(idc.create_insn(ea))
            except Exception:
                made = False
        if made and is_code_head(ea):
            total_created += 1
            ea += max(item_size(ea), 1)
        else:
            total_failed += 1
            ea += 1
    return (total_created, total_failed)

def force_make_code_exec_segments():
    ranges = get_exec_ranges()
    total_created = 0
    total_failed = 0
    for start, end in ranges:
        created, failed = force_make_code_range(start, end)
        total_created += created
        total_failed += failed
        try:
            ida_auto.plan_range(start, end)
        except Exception:
            pass
    ida_auto.auto_wait()
    if FIRST_SEGMENT_ONLY:
        log('force_make_code_first_segment done. created=%d failed=%d' % (total_created, total_failed))
    else:
        log('force_make_code_exec_segments done. created=%d failed=%d' % (total_created, total_failed))

def analyze_all_exec_segments_at_start():
    if not ANALYZE_ALL_EXEC_AT_START:
        return
    log('initial executable segment analysis started')
    plan_all_exec_segments()
    if AGGRESSIVE_MAKE_CODE_ALL_EXEC:
        force_make_code_exec_segments()
    plan_all_exec_segments()
    log('initial executable segment analysis done')

def run_makecode_first():
    if not RUN_MAKECODE_FIRST:
        log('makecode first step disabled')
        return
    log('makecode first step started')
    analyze_all_exec_segments_at_start()
    log('makecode first step done')

def is_jmp_rax(ea):
    if not is_code_head(ea):
        return False
    if ida_bytes.get_bytes(ea, 2) != b'\xff\xe0':
        return False
    if idc.get_item_size(ea) != 2:
        return False
    return mnem(ea) == 'jmp' and op(ea, 0) == 'rax'

def is_boundary(ea):
    mn = mnem(ea)
    if mn in ('ret', 'retn', 'int3', 'int'):
        return True
    if mn == 'jmp':
        return True
    if mn == 'call':
        return True
    if mn.startswith('j') and mn != 'jmp':
        return True
    return False

def is_sub_reg64_reg64(ea):
    if mnem(ea) != 'sub':
        return False
    dst = op(ea, 0)
    src = op(ea, 1)
    if not is_reg_any(dst) or not is_reg_any(src):
        return False
    if reg_bits(dst) != 64 or reg_bits(src) != 64:
        return False
    dst64 = normalize_reg(dst)
    src64 = normalize_reg(src)
    if dst64 == 'rsp' or dst64 == src64:
        return False
    return dst64 in REG64 and src64 in REG64

def is_sub_reg_imm(ea):

    if mnem(ea) != 'sub':
        return False
    dst = op(ea, 0)
    if not is_reg_any(dst):
        return False
    bits = reg_bits(dst)
    if bits not in (8, 16, 32, 64):
        return False
    dst64 = normalize_reg(dst)
    if dst64 == 'rsp':
        return False
    return idc.get_operand_type(ea, 1) == idc.o_imm

def is_flag_candidate_for_jmp(ea):
    return is_sub_reg64_reg64(ea) or is_sub_reg_imm(ea)

def flag_candidate_info(ea):
    if is_sub_reg64_reg64(ea):
        return {
            'kind': 'sub_regreg',
            'reg1': normalize_reg(op(ea, 0)),
            'reg2': normalize_reg(op(ea, 1)),
            'imm': None,
            'bits': 64,
        }
    if is_sub_reg_imm(ea):
        dst = op(ea, 0)
        bits = reg_bits(dst)
        mask = mask_for_bits(bits)
        return {
            'kind': 'sub_regimm',
            'reg1': normalize_reg(dst),
            'reg2': '',
            'imm': idc.get_operand_value(ea, 1) & mask,
            'bits': bits,
        }
    return None

def is_fixed_mem_src(ea, operand_index):
    src = op(ea, operand_index)
    if not src:
        return False
    if is_reg_any(src):
        return False
    if regs_in_text(src):
        return False
    operand_type = idc.get_operand_type(ea, operand_index)
    if operand_type == idc.o_imm:
        return False
    return True

class UnicornContext:

    def __init__(self):
        self.uc = Uc(UC_ARCH_X86, UC_MODE_64)
        self.stack_base = STACK_BASE
        self.stack_size = STACK_SIZE
        self.stack_top = self.stack_base + self.stack_size // 2
        self.mapped_ranges = []
        self._map_ida_segments_once()
        self._map_optional_extra_ranges_once()
        self._map_stack_once()
        log('unicorn mapped once. ranges=%d stack=%s-%s' % (
            len(self.mapped_ranges), ea_s(self.stack_base), ea_s(self.stack_base + self.stack_size)
        ))

    def _range_is_mapped(self, start, end):
        for a, b in self.mapped_ranges:
            if start >= a and end <= b:
                return True
        return False

    def _map_range_once(self, start, end, data_reader=None):
        start = page_down(int(start))
        end = page_up(int(end))
        if end <= start:
            return False
        if self._range_is_mapped(start, end):
            return False
        try:
            self.uc.mem_map(start, end - start, UC_PROT_ALL)
        except UcError:

            pass
        self.mapped_ranges.append((start, end))
        self.mapped_ranges = merge_ranges(self.mapped_ranges)
        if data_reader is not None:
            try:
                data = data_reader(start, end - start)
                if data:
                    self.uc.mem_write(start, data)
            except Exception:
                pass
        return True

    def _map_ida_segments_once(self):
        seg_ranges = get_loaded_segment_ranges()
        mapped_ranges = merge_ranges(seg_ranges)
        for start, end in mapped_ranges:
            self._map_range_once(start, end)
        for start, end in seg_ranges:
            data = ida_get_bytes_fill(start, end - start)
            try:
                self.uc.mem_write(start, data)
            except Exception:
                pass

    def _map_optional_extra_ranges_once(self):

        base = globals().get('GLOBAL_QWORD_REBASE_BASE', None)
        max_size = globals().get('GLOBAL_QWORD_REBASE_MAX', 0)
        if base is None or max_size is None or int(max_size) <= 0:
            return
        try:
            self._map_range_once(int(base), int(base) + int(max_size))
        except Exception:
            pass

    def _map_stack_once(self):
        self._map_range_once(self.stack_base, self.stack_base + self.stack_size)
        self.uc.reg_write(UC_X86_REG_RSP, self.stack_top)
        self.uc.reg_write(UC_X86_REG_RBP, self.stack_top)

    def reset_clean(self):

        start = self.stack_top - STACK_RESET_SIZE // 2
        if start < self.stack_base:
            start = self.stack_base
        end = start + STACK_RESET_SIZE
        max_end = self.stack_base + self.stack_size
        if end > max_end:
            end = max_end
        size = end - start
        if size > 0:
            self.uc.mem_write(start, ZERO_STACK_CHUNK[:size])
        for _, uc_reg in UC_REG64.items():
            self.uc.reg_write(uc_reg, 0)
        self.uc.reg_write(UC_X86_REG_RSP, self.stack_top)
        self.uc.reg_write(UC_X86_REG_RBP, self.stack_top)
        self.uc.reg_write(UC_X86_REG_RIP, 0)
        self.uc.reg_write(UC_X86_REG_EFLAGS, 2)

def init_unicorn_context_once():
    global _GLOBAL_UC_CTX
    if _GLOBAL_UC_CTX is None:
        _GLOBAL_UC_CTX = UnicornContext()
    else:
        log('unicorn context already initialized; no remap')
    return _GLOBAL_UC_CTX

def get_uc_context():

    return init_unicorn_context_once()

def sync_uc_bytes(ea, data):
    global _GLOBAL_UC_CTX
    if _GLOBAL_UC_CTX is None:
        return
    try:
        _GLOBAL_UC_CTX.uc.mem_write(int(ea), data)
    except Exception:

        pass

def write_uc_reg64(uc, reg_name, value):
    reg_name = normalize_reg(reg_name)
    if reg_name not in UC_REG64:
        raise RuntimeError('unknown uc reg: %s' % reg_name)
    uc.reg_write(UC_REG64[reg_name], value & MASK64)

def read_uc_reg64(uc, reg_name):
    reg_name = normalize_reg(reg_name)
    if reg_name not in UC_REG64:
        raise RuntimeError('unknown uc reg: %s' % reg_name)
    return uc.reg_read(UC_REG64[reg_name]) & MASK64

def read_int_le(ea, size):
    data = ida_bytes.get_bytes(ea, size)
    if data is None or len(data) != size:
        return None
    return int.from_bytes(data, 'little') & (1 << size * 8) - 1

def read_mov_reg_fixed_mem64(ea):
    if not is_code_head(ea):
        return (None, None, None)
    if mnem(ea) != 'mov':
        return (None, None, None)
    dst = op(ea, 0)
    if not is_reg_any(dst) or reg_bits(dst) != 64:
        return (None, None, None)
    if not is_fixed_mem_src(ea, 1):
        return (None, None, None)
    mem_ea = idc.get_operand_value(ea, 1)
    if mem_ea is None or mem_ea == BADADDR or (not ea_in_loaded(mem_ea)):
        return (None, None, None)
    if GLOBAL_QWORD_REBASE_SKIP_UNINIT_MEM_STORAGE and qword_storage_is_uninitialized(mem_ea):
        return (None, None, None)
    value = read_int_le(mem_ea, 8)
    if value is None:
        return (None, None, None)
    if GLOBAL_QWORD_REBASE_SKIP_UNKNOWN_QWORD_VALUE and qword_value_is_unknown_sentinel(value):
        return (None, None, None)
    return (normalize_reg(dst), value & MASK64, mem_ea)

def emulate_to_jmp_with_assignments(start_ea, stop_ea, assignments):

    ctx = get_uc_context()
    uc = ctx.uc
    ctx.reset_clean()

    for reg, value in assignments.items():
        write_uc_reg64(uc, reg, value)

    try:
        uc.emu_start(start_ea, stop_ea, 0, MAX_EMU_INSNS)
    except UcError as ex:
        return (None, 'unicorn error %s -> %s: %s' % (ea_s(start_ea), ea_s(stop_ea), ex))

    rip = uc.reg_read(UC_X86_REG_RIP) & MASK64
    if rip != stop_ea:
        return (None, 'stopped early RIP=%s stop=%s' % (ea_s(rip), ea_s(stop_ea)))
    return (read_uc_reg64(uc, 'rax'), None)

class FoundPattern:

    def __init__(self):
        self.jmp_ea = BADADDR
        self.sub_ea = BADADDR
        self.emu_start_ea = BADADDR
        self.patch_start = BADADDR
        self.end_ea = BADADDR
        self.reg1 = ''
        self.reg2 = ''
        self.imm = None
        self.sub_kind = ''
        self.sub_bits = 64
        self.cond = None
        self.jcc_mnem = ''
        self.jcc_opcode2 = None
        self.true_target = None
        self.false_target = None
        self.case_results = {}
        self.flag_cases = {}
        self.reason = ''

def build_regreg_cases():
    cases = []
    for name, v1, v2 in TEST_CASES:
        cases.append((name, v1 & MASK64, v2 & MASK64, 64, {0: v1 & MASK64, 1: v2 & MASK64}))
    return cases

def build_regimm_cases(imm, bits):
    mask = mask_for_bits(bits)
    sign = sign_bit_for_bits(bits)
    imm &= mask
    raw_values = [imm, (imm - 1) & mask, (imm + 1) & mask, 0, 1, 2, 3, mask, sign, (sign - 1) & mask, (sign + 1) & mask]
    values = []
    seen = set()
    for v in raw_values:
        v &= mask
        if v not in seen:
            seen.add(v)
            values.append(v)
    cases = []
    for i, v in enumerate(values):
        if v == imm:
            name = 'imm_eq_%X' % imm
        elif v == ((imm - 1) & mask):
            name = 'imm_below_%X' % imm
        elif v == ((imm + 1) & mask):
            name = 'imm_above_%X' % imm
        else:
            name = 'imm_case_%02d_%X' % (i, v)
        cases.append((name, v, imm, bits, {0: v}))
    return cases

def infer_condition(p):
    unique_targets = sorted(set(p.case_results.values()))
    if len(unique_targets) != 2:
        p.reason = 'expected 2 targets, got %d' % len(unique_targets)
        return False
    candidates = []
    for cond in CANON_CONDS:
        true_targets = set()
        false_targets = set()
        for name, lhs, rhs, bits in p.flag_cases.values():
            target = p.case_results.get(name)
            if target is None:
                continue
            flags = flags_sub(lhs, rhs, bits)
            if eval_cond(cond, flags):
                true_targets.add(target)
            else:
                false_targets.add(target)
        if len(true_targets) == 1 and len(false_targets) == 1:
            true_target = list(true_targets)[0]
            false_target = list(false_targets)[0]
            if true_target != false_target:
                candidates.append((cond, true_target, false_target))
    if not candidates:
        p.reason = 'cannot infer condition'
        return False
    cond, true_target, false_target = candidates[0]
    p.cond = cond
    p.true_target = true_target
    p.false_target = false_target
    p.jcc_mnem, p.jcc_opcode2 = COND_TO_JCC[cond]
    return True

def analyze_candidate(jmp_ea, flag_ea):
    info = flag_candidate_info(flag_ea)
    if info is None:
        return None
    p = FoundPattern()
    p.jmp_ea = jmp_ea
    p.sub_ea = flag_ea
    p.emu_start_ea = flag_ea
    p.patch_start = item_end(flag_ea)
    p.end_ea = item_end(jmp_ea)
    p.reg1 = info['reg1']
    p.reg2 = info['reg2']
    p.imm = info['imm']
    p.sub_kind = info['kind']
    p.sub_bits = info['bits']
    if p.sub_kind == 'sub_regreg':
        cases = build_regreg_cases()
    elif p.sub_kind == 'sub_regimm':
        cases = build_regimm_cases(p.imm, p.sub_bits)
    else:
        return None
    for name, lhs, rhs, bits, assign_values in cases:
        assignments = {p.reg1: assign_values[0]}
        if p.sub_kind == 'sub_regreg':
            assignments[p.reg2] = assign_values[1]
        target, err = emulate_to_jmp_with_assignments(p.emu_start_ea, jmp_ea, assignments)
        if err is not None:
            p.reason = err
            return None
        p.case_results[name] = target & MASK64
        p.flag_cases[name] = (name, lhs, rhs, bits)
    if not infer_condition(p):
        return None
    return p

def iter_flag_candidates_backwards(jmp_ea):

    ea = previ(jmp_ea)
    count = 0
    while ea != BADADDR and count < MAX_BACK_INSNS:
        if is_boundary(ea):
            return
        if is_flag_candidate_for_jmp(ea):
            yield ea
        ea = previ(ea)
        count += 1

def analyze_jmp(jmp_ea):
    for flag_ea in iter_flag_candidates_backwards(jmp_ea):
        p = analyze_candidate(jmp_ea, flag_ea)
        if p is not None:
            return p
    return None

def rel32(src_ea, insn_len, dst_ea):
    rel = int(dst_ea) - int(src_ea + insn_len)
    if rel < -2147483648 or rel > 2147483647:
        return None
    return struct.pack('<i', rel)

def make_jcc_near(ea, opcode2, target):
    rel = rel32(ea, 6, target)
    if rel is None:
        return None
    return b'\x0f' + bytes([opcode2]) + rel

def make_jmp_near(ea, target):
    rel = rel32(ea, 5, target)
    if rel is None:
        return None
    return b'\xe9' + rel

def nop_range(start, end):
    if end <= start:
        return
    data = b'\x90' * (end - start)
    ida_bytes.patch_bytes(start, data)
    sync_uc_bytes(start, data)

def patch_pattern(p):
    start = p.patch_start
    end = p.end_ea
    total_size = end - start
    jcc_bytes = make_jcc_near(start, p.jcc_opcode2, p.true_target)
    if jcc_bytes is None:
        return False
    jmp_ea = start + len(jcc_bytes)
    jmp_bytes = make_jmp_near(jmp_ea, p.false_target)
    if jmp_bytes is None:
        return False
    payload = jcc_bytes + jmp_bytes
    if len(payload) > total_size:
        return False
    try:
        ida_bytes.del_items(start, ida_bytes.DELIT_EXPAND, total_size)
    except Exception:
        pass
    ida_bytes.patch_bytes(start, payload)
    sync_uc_bytes(start, payload)
    nop_range(start + len(payload), end)
    try:
        ida_ua.create_insn(start)
        ida_ua.create_insn(start + len(jcc_bytes))
    except Exception:
        pass
    log('patched jmp %s flag_ins=%s kind=%s cond=%s true=%s false=%s' % (ea_s(p.jmp_ea), ea_s(p.sub_ea), p.sub_kind, p.jcc_mnem, ea_s(p.true_target), ea_s(p.false_target)))
    return True

def iter_jmp_rax_fast(start, end):
    size = end - start
    if size <= 0:
        return
    data = ida_bytes.get_bytes(start, size)
    if not data:
        return
    pos = 0
    needle = b'\xff\xe0'
    while True:
        idx = data.find(needle, pos)
        if idx < 0:
            break
        ea = start + idx
        if is_jmp_rax(ea):
            yield ea
        pos = idx + 1

ENABLE_CFF_ANALYZER = True

CFF_SCAN_ALL_FUNCTIONS_IN_FIRST_SEGMENT = True

CFF_TARGET_EA = BADADDR

CFF_PATCH = True

CFF_MIN_FLATTENING_SCORE = 0.9

CFF_MIN_DISPATCH_CASES = 2

CFF_MAX_HANDLER_BLOCKS = 16

CFF_MAX_PATCHED_EDGES_PER_FUNC = 256

CFF_BYPASS_SCORE_IF_STATE_COPY = True

def cff_log(s):
    print('[cff_ida_v2] ' + str(s))

def cff_is_jcc_mnem(mn):
    if not mn:
        return False
    mn = mn.lower()
    return mn.startswith('j') and mn not in ('jmp', 'jmpfi')

def cff_get_target_segment_range():
    if not FIRST_SEGMENT_ONLY:
        ranges = get_exec_ranges()
        return ranges[0] if ranges else None
    return get_first_segment_range()

def cff_get_target_eas():
    import ida_funcs
    if CFF_TARGET_EA not in (None, BADADDR):
        f = ida_funcs.get_func(CFF_TARGET_EA)
        return [int(f.start_ea)] if f else [int(CFF_TARGET_EA)]
    if not CFF_SCAN_ALL_FUNCTIONS_IN_FIRST_SEGMENT:
        f = ida_funcs.get_func(idc.here())
        return [int(f.start_ea)] if f else []
    r = cff_get_target_segment_range()
    if not r:
        return []
    start, end = r
    out = []
    ea = start
    while True:
        f = ida_funcs.get_next_func(ea - 1 if ea == start else ea)
        if not f:
            break
        fea = int(f.start_ea)
        if fea >= end:
            break
        if fea >= start:
            out.append(fea)
        ea = int(f.end_ea)
        if ea <= fea:
            ea = fea + 1
    return sorted(set(out))

def cff_func_blocks(func_ea):
    import ida_funcs
    import ida_gdl
    f = ida_funcs.get_func(func_ea)
    if not f:
        return ([], {}, {}, {})
    fc = ida_gdl.FlowChart(f, flags=ida_gdl.FC_PREDS)
    blocks = list(fc)
    id_to_block = {int(b.id): b for b in blocks}
    succs = {int(b.id): [int(s.id) for s in b.succs()] for b in blocks}
    preds = {int(b.id): [int(p.id) for p in b.preds()] for b in blocks}
    return (blocks, id_to_block, succs, preds)

def cff_block_heads(block):
    ea = int(block.start_ea)
    end = int(block.end_ea)
    out = []
    while ea != BADADDR and ea < end:
        if is_code_head(ea):
            out.append(ea)
            ea = nexti(ea)
        else:
            ea += 1
    return [x for x in out if x < end]

def cff_find_block_by_ea(blocks, ea):
    for b in blocks:
        if int(b.start_ea) <= ea < int(b.end_ea):
            return int(b.id)
    return None

def cff_find_block_start_map(blocks):
    return {int(b.start_ea): int(b.id) for b in blocks}

def cff_calc_flattening_score(blocks, succs, preds, entry_id=None):
    n = len(blocks)
    if n <= 1:
        return 0.0
    node_ids = {int(b.id) for b in blocks}
    if entry_id is None or entry_id not in node_ids:
        entry_id = int(min(blocks, key=lambda b: int(b.start_ea)).id)
    dom = {}
    for bid in node_ids:
        if bid == entry_id:
            dom[bid] = {bid}
        else:
            dom[bid] = set(node_ids)
    changed = True
    while changed:
        changed = False
        for bid in node_ids:
            if bid == entry_id:
                continue
            ps = [p for p in preds.get(bid, []) if p in node_ids]
            if ps:
                new_dom = set(node_ids)
                for p in ps:
                    new_dom &= dom.get(p, set())
                new_dom.add(bid)
            else:
                new_dom = {bid}
            if new_dom != dom.get(bid):
                dom[bid] = new_dom
                changed = True
    best = 0.0
    for bid in node_ids:
        dominated = {x for x in node_ids if bid in dom.get(x, set())}
        if not dominated:
            continue
        has_back_edge = False
        for p in preds.get(bid, []):
            if p in dominated:
                has_back_edge = True
                break
        if has_back_edge:
            best = max(best, len(dominated) / float(n))
    return best

def cff_mem_key_from_text(txt):
    if not txt:
        return None
    t = txt.lower().replace(' ', '')
    for prefix in ('byteptr', 'wordptr', 'dwordptr', 'qwordptr', 'xmmwordptr', 'ymmwordptr'):
        t = t.replace(prefix, '')
    for seg in ('cs:', 'ds:', 'ss:', 'es:', 'fs:', 'gs:'):
        t = t.replace(seg, '')
    if '[' in t and ']' in t:
        return t[t.find('['):t.rfind(']') + 1]
    return None

def cff_mem_key(ea, idx):
    return cff_mem_key_from_text(op(ea, idx))

def cff_next_non_nop(ea, limit_end=BADADDR, max_steps=16):
    cur = nexti(ea)
    steps = 0
    while cur != BADADDR and steps < max_steps:
        if limit_end != BADADDR and cur >= limit_end:
            return BADADDR
        if mnem(cur) not in ('nop', 'int3'):
            return cur
        cur = nexti(cur)
        steps += 1
    return BADADDR

def cff_get_imm_operand(ea, idx):
    try:
        if idc.get_operand_type(ea, idx) == idc.o_imm:
            return idc.get_operand_value(ea, idx) & MASK64
    except Exception:
        pass
    return None

def cff_read_mov_reg_imm_any(ea):
    if mnem(ea) not in ('mov', 'movabs'):
        return (None, None)
    dst = op(ea, 0)
    if not is_reg_any(dst):
        return (None, None)
    imm = cff_get_imm_operand(ea, 1)
    if imm is None:
        return (None, None)
    return (normalize_reg(dst), imm)

def cff_state_copy_pair_at(ea):
    if mnem(ea) != 'mov':
        return None
    dst = dst_reg_of_insn(ea)
    src_key = cff_mem_key(ea, 1)
    if dst is None or src_key is None:
        return None
    ea2 = cff_next_non_nop(ea, max_steps=4)
    if ea2 == BADADDR or mnem(ea2) != 'mov':
        return None
    dst_key2 = cff_mem_key(ea2, 0)
    src2 = op(ea2, 1)
    if dst_key2 is None or not is_reg_any(src2):
        return None
    if normalize_reg(src2) != dst:
        return None
    return (src_key, dst_key2, ea, ea2)

def cff_count_dispatch_cases_for_current_key(blocks, current_key):
    count = 0
    for b in blocks:
        for ea in cff_block_heads(b):
            if cff_dispatch_case_at(ea, current_key) is not None:
                count += 1
    return count

def cff_count_stores_to_key(blocks, key):
    count = 0
    for b in blocks:
        for ea in cff_block_heads(b):
            if mnem(ea) == 'mov' and cff_mem_key(ea, 0) == key:
                count += 1
    return count

def cff_find_state_copy_pair(blocks):
    candidates = []
    for b in blocks:
        for ea in cff_block_heads(b):
            p = cff_state_copy_pair_at(ea)
            if not p:
                continue
            next_key, current_key, ea1, ea2 = p
            dispatch_count = cff_count_dispatch_cases_for_current_key(blocks, current_key)
            store_count = cff_count_stores_to_key(blocks, next_key)
            score = dispatch_count * 100 + store_count * 10
            candidates.append((score, dispatch_count, store_count, next_key, current_key, ea1, ea2, int(b.id)))
    if not candidates:
        return None
    candidates.sort(reverse=True)
    score, dc, sc, nk, ck, ea1, ea2, bid = candidates[0]
    if dc < CFF_MIN_DISPATCH_CASES or sc < 1:
        return None
    return {'next_key': nk, 'current_key': ck, 'copy_ea': ea1, 'copy_ea2': ea2, 'block_id': bid, 'dispatch_count': dc, 'store_count': sc, 'score': score}

def cff_dispatch_case_at(ea, current_key):
    if mnem(ea) != 'mov':
        return None
    state_reg = dst_reg_of_insn(ea)
    if state_reg is None:
        return None
    if cff_mem_key(ea, 1) != current_key:
        return None
    cur = cff_next_non_nop(ea, max_steps=3)
    if cur == BADADDR:
        return None
    imm_by_reg = {}
    cmp_seen = False
    state_imm = None
    steps = 0
    while cur != BADADDR and steps < 8:
        mn = mnem(cur)
        if mn in ('mov', 'movabs'):
            r, imm = cff_read_mov_reg_imm_any(cur)
            if r is not None and imm is not None:
                imm_by_reg[r] = imm
        elif mn in ('sub', 'cmp'):
            left = op(cur, 0)
            right = op(cur, 1)
            if is_reg_any(left) and normalize_reg(left) == state_reg:
                if is_reg_any(right):
                    rr = normalize_reg(right)
                    if rr in imm_by_reg:
                        state_imm = imm_by_reg[rr]
                        cmp_seen = True
                else:
                    imm = cff_get_imm_operand(cur, 1)
                    if imm is not None:
                        state_imm = imm
                        cmp_seen = True
        elif mn in ('jz', 'je') and cmp_seen and (state_imm is not None):
            return (state_imm & MASK64, idc.get_operand_value(cur, 0), cur)
        elif mn == 'jmp' or mn == 'ret' or mn == 'call':
            return None
        cur = cff_next_non_nop(cur, max_steps=3)
        steps += 1
    return None

def cff_recover_dispatch_cases(blocks, current_key):
    state_to_handler = {}
    case_eas = {}
    for b in blocks:
        for ea in cff_block_heads(b):
            r = cff_dispatch_case_at(ea, current_key)
            if not r:
                continue
            state, target, jcc_ea = r
            state_to_handler[state] = target
            case_eas[state] = jcc_ea
    return (state_to_handler, case_eas)

def cff_find_state_copy_block_start(blocks, copy_ea):
    bid = cff_find_block_by_ea(blocks, copy_ea)
    if bid is None:
        return BADADDR
    for b in blocks:
        if int(b.id) == bid:
            return int(b.start_ea)
    return BADADDR

def cff_is_trampoline_to_loop(blocks, start_map, target, loop_start, depth=0):
    if target == loop_start:
        return True
    if depth >= 4:
        return False
    bid = start_map.get(target)
    if bid is None:
        return False
    block = next((b for b in blocks if int(b.id) == bid), None)
    if not block:
        return False
    heads = [h for h in cff_block_heads(block) if mnem(h) not in ('nop', 'int3')]
    if not heads:
        return False
    non_jmp = [h for h in heads if mnem(h) != 'jmp']
    if non_jmp:
        return False
    last = heads[-1]
    nxt = idc.get_operand_value(last, 0)
    return cff_is_trampoline_to_loop(blocks, start_map, nxt, loop_start, depth + 1)

def cff_collect_handler_heads(blocks, start_map, handler_ea, loop_start):
    bid = start_map.get(handler_ea)
    if bid is None:
        bid = cff_find_block_by_ea(blocks, handler_ea)
    if bid is None:
        return (None, BADADDR)
    heads = []
    seen = set()
    cur_bid = bid
    for _ in range(CFF_MAX_HANDLER_BLOCKS):
        if cur_bid in seen:
            return (None, BADADDR)
        seen.add(cur_bid)
        block = next((b for b in blocks if int(b.id) == cur_bid), None)
        if not block:
            return (None, BADADDR)
        bh = cff_block_heads(block)
        heads.extend(bh)
        if not bh:
            return (None, BADADDR)
        last = bh[-1]
        mn = mnem(last)
        if mn == 'jmp':
            target = idc.get_operand_value(last, 0)
            if cff_is_trampoline_to_loop(blocks, start_map, target, loop_start):
                return (heads, last)
            nbid = start_map.get(target)
            if nbid is None:
                return (None, BADADDR)
            cur_bid = nbid
            continue
        if mn in ('ret', 'retn'):
            return (heads, BADADDR)
        return (None, BADADDR)
    return (None, BADADDR)

def cff_cond_from_cmov_mnem(mn):
    mn = mn.lower()
    if not mn.startswith('cmov'):
        return None
    cc = mn[4:]
    return COND_ALIAS_TO_CANON.get(cc, cc)

def cff_set_reg_value(regvals, reg, val):
    reg = normalize_reg(reg)
    if reg not in REG64:
        return
    regvals[reg] = val

def cff_get_reg_value(regvals, reg):
    reg = normalize_reg(reg)
    return regvals.get(reg)

def cff_eval_handler_until_store(heads, next_key):
    regvals = {}
    last_cmp_ea = BADADDR
    last_cmp_mnem = ''
    for ea in heads:
        mn = mnem(ea)
        if mn in ('ret', 'retn'):
            return None
        if mn == 'jmp':
            return None
        dst = op(ea, 0)
        src = op(ea, 1)
        if mn == 'xor' and is_reg_any(dst) and is_reg_any(src) and (normalize_reg(dst) == normalize_reg(src)):
            cff_set_reg_value(regvals, dst, 0)
            continue
        if mn in ('mov', 'movabs'):
            dst_key = cff_mem_key(ea, 0)
            if dst_key == next_key:
                val = None
                if is_reg_any(src):
                    val = cff_get_reg_value(regvals, src)
                else:
                    val = cff_get_imm_operand(ea, 1)
                return {'store_ea': ea, 'value': val, 'regvals': dict(regvals)}
            if is_reg_any(dst):
                imm = cff_get_imm_operand(ea, 1)
                if imm is not None:
                    cff_set_reg_value(regvals, dst, imm)
                elif is_reg_any(src):
                    cff_set_reg_value(regvals, dst, cff_get_reg_value(regvals, src))
                else:
                    cff_set_reg_value(regvals, dst, None)
            continue
        if mn == 'sub' and is_reg_any(dst):
            old = cff_get_reg_value(regvals, dst)
            if is_reg_any(src):
                rhs = cff_get_reg_value(regvals, src)
            else:
                rhs = cff_get_imm_operand(ea, 1)
            if isinstance(old, int) and isinstance(rhs, int):
                cff_set_reg_value(regvals, dst, old - rhs & MASK64)
            else:
                cff_set_reg_value(regvals, dst, None)
            continue
        if mn == 'add' and is_reg_any(dst):
            old = cff_get_reg_value(regvals, dst)
            if is_reg_any(src):
                rhs = cff_get_reg_value(regvals, src)
            else:
                rhs = cff_get_imm_operand(ea, 1)
            if isinstance(old, int) and isinstance(rhs, int):
                cff_set_reg_value(regvals, dst, old + rhs & MASK64)
            else:
                cff_set_reg_value(regvals, dst, None)
            continue
        if mn in ('cmp', 'test'):
            last_cmp_ea = ea
            last_cmp_mnem = mn
            continue
        if mn.startswith('cmov') and is_reg_any(dst) and is_reg_any(src):
            cond = cff_cond_from_cmov_mnem(mn)
            old = cff_get_reg_value(regvals, dst)
            new = cff_get_reg_value(regvals, src)
            if cond is not None and isinstance(old, int) and isinstance(new, int) and (last_cmp_ea != BADADDR):
                cff_set_reg_value(regvals, dst, ('cond', cond, old & MASK64, new & MASK64, last_cmp_ea, ea))
            else:
                cff_set_reg_value(regvals, dst, None)
            continue
        if mn.startswith('set') and is_reg_any(dst):
            cff_set_reg_value(regvals, dst, None)
            continue
        dreg = dst_reg_of_insn(ea)
        if dreg is not None:
            cff_set_reg_value(regvals, dreg, None)
    return None

def cff_sidefx_heads_between(heads, start_ea, end_ea):
    return [h for h in heads if start_ea < h < end_ea and mnem(h) not in ('nop', 'int3')]

def cff_insn_uses_rip_relative(ea):
    return 'rip' in op(ea, 0) or 'rip' in op(ea, 1) or 'rip' in op(ea, 2)

def cff_is_safe_sidefx_to_copy(ea, conditional):
    mn = mnem(ea)
    if mn in ('jmp', 'call', 'ret', 'retn', 'int', 'int3') or cff_is_jcc_mnem(mn):
        return False
    if cff_insn_uses_rip_relative(ea):
        return False
    if conditional:
        return mn in ('mov', 'movzx', 'movsx', 'movsxd', 'lea', 'nop')
    return True

def cff_collect_sidefx_bytes(sidefx_heads, conditional):
    data = b''
    for ea in sidefx_heads:
        if not cff_is_safe_sidefx_to_copy(ea, conditional):
            return None
        b = ida_bytes.get_bytes(ea, item_size(ea))
        if b is None:
            return None
        data += b
    return data

def cff_short_rel(src_ea, insn_len, dst_ea):
    r = int(dst_ea) - int(src_ea + insn_len)
    if -128 <= r <= 127:
        return struct.pack('b', r)
    return None

def cff_make_jmp_auto(ea, target):
    s = cff_short_rel(ea, 2, target)
    if s is not None:
        return b'\xeb' + s
    n = rel32(ea, 5, target)
    if n is not None:
        return b'\xe9' + n
    return None

def cff_make_jcc_auto(ea, cond, target):
    cond = COND_ALIAS_TO_CANON.get(cond, cond)
    if cond not in COND_TO_JCC:
        return None
    _, opcode2 = COND_TO_JCC[cond]
    s = cff_short_rel(ea, 2, target)
    if s is not None:
        return bytes([112 + (opcode2 - 128)]) + s
    n = rel32(ea, 6, target)
    if n is not None:
        return b'\x0f' + bytes([opcode2]) + n
    return None

def cff_patch_bytes_range(start, end, payload, tag):
    total = end - start
    if total <= 0 or len(payload) > total:
        cff_log('patch skip %s at %s: not enough room need=%d have=%d' % (tag, ea_s(start), len(payload), total))
        return False
    try:
        ida_bytes.del_items(start, ida_bytes.DELIT_EXPAND, total)
    except Exception:
        pass
    ida_bytes.patch_bytes(start, payload)
    sync_uc_bytes(start, payload)
    if len(payload) < total:
        rest = b'\x90' * (total - len(payload))
        ida_bytes.patch_bytes(start + len(payload), rest)
        sync_uc_bytes(start + len(payload), rest)
    cur = start
    while cur < end:
        try:
            ida_ua.create_insn(cur)
        except Exception:
            pass
        nxt = nexti(cur)
        if nxt == BADADDR or nxt <= cur or nxt > end:
            cur += max(item_size(cur), 1)
        else:
            cur = nxt
    cff_log('patched %s at %s size=%d payload=%d' % (tag, ea_s(start), total, len(payload)))
    return True

def cff_patch_handler_edge(blocks, start_map, handler_ea, loop_start, next_key, state_to_handler):
    heads, dispatch_jmp_ea = cff_collect_handler_heads(blocks, start_map, handler_ea, loop_start)
    if not heads or dispatch_jmp_ea == BADADDR:
        return False
    r = cff_eval_handler_until_store(heads, next_key)
    if not r:
        return False
    store_ea = r['store_ea']
    value = r['value']
    if value is None:
        cff_log('  handler %s skip: next-state value unknown at %s' % (ea_s(handler_ea), ea_s(store_ea)))
        return False
    patch_start = store_ea
    patch_end = item_end(dispatch_jmp_ea)
    sidefx_heads = cff_sidefx_heads_between(heads, store_ea, dispatch_jmp_ea)
    conditional = isinstance(value, tuple) and len(value) >= 6 and (value[0] == 'cond')
    sidefx_bytes = cff_collect_sidefx_bytes(sidefx_heads, conditional)
    if sidefx_bytes is None:
        cff_log('  handler %s skip: unsafe side effects after state-store' % ea_s(handler_ea))
        return False
    payload = bytearray(sidefx_bytes)
    pos = patch_start + len(payload)
    if conditional:
        _, cond, false_state, true_state, cmp_ea, cmov_ea = value
        if false_state not in state_to_handler or true_state not in state_to_handler:
            cff_log('  handler %s skip: cond states not in dispatcher false=%s true=%s' % (ea_s(handler_ea), ea_s(false_state), ea_s(true_state)))
            return False
        true_target = state_to_handler[true_state]
        false_target = state_to_handler[false_state]
        jcc = cff_make_jcc_auto(pos, cond, true_target)
        if jcc is None:
            cff_log('  handler %s skip: cannot encode jcc %s -> %s' % (ea_s(handler_ea), cond, ea_s(true_target)))
            return False
        payload += jcc
        pos += len(jcc)
        jmp = cff_make_jmp_auto(pos, false_target)
        if jmp is None:
            cff_log('  handler %s skip: cannot encode jmp -> %s' % (ea_s(handler_ea), ea_s(false_target)))
            return False
        payload += jmp
        return cff_patch_bytes_range(patch_start, patch_end, bytes(payload), 'cff_cond %s true=%s false=%s' % (cond, ea_s(true_target), ea_s(false_target)))
    if not isinstance(value, int) or value not in state_to_handler:
        cff_log('  handler %s skip: state %s not in dispatcher' % (ea_s(handler_ea), str(value)))
        return False
    target = state_to_handler[value]
    jmp = cff_make_jmp_auto(pos, target)
    if jmp is None:
        cff_log('  handler %s skip: cannot encode jmp -> %s' % (ea_s(handler_ea), ea_s(target)))
        return False
    payload += jmp
    return cff_patch_bytes_range(patch_start, patch_end, bytes(payload), 'cff_uncond target=%s' % ea_s(target))

def analyze_flattening_function(func_ea):
    blocks, id_to_block, succs, preds = cff_func_blocks(func_ea)
    if not blocks:
        return (False, 0)
    entry_block = cff_find_block_by_ea(blocks, func_ea)
    score = cff_calc_flattening_score(blocks, succs, preds, entry_block)
    cff_log('function %s blocks=%d flattening_score=%.3f' % (ea_s(func_ea), len(blocks), score))
    copy = cff_find_state_copy_pair(blocks)
    if score < CFF_MIN_FLATTENING_SCORE:
        if not (CFF_BYPASS_SCORE_IF_STATE_COPY and copy is not None and (copy.get('dispatch_count', 0) >= CFF_MIN_DISPATCH_CASES)):
            cff_log('skip %s: score below %.2f' % (ea_s(func_ea), CFF_MIN_FLATTENING_SCORE))
            return (False, 0)
        cff_log('score below %.2f, but state-copy/dispatcher cases found; continue' % CFF_MIN_FLATTENING_SCORE)
    if not copy:
        cff_log('skip %s: cannot identify state copy pair mov reg,[next] ; mov [current],reg' % ea_s(func_ea))
        return (False, 0)
    next_key = copy['next_key']
    current_key = copy['current_key']
    loop_start = cff_find_state_copy_block_start(blocks, copy['copy_ea'])
    if loop_start == BADADDR:
        cff_log('skip %s: cannot identify loop/state-copy block start' % ea_s(func_ea))
        return (False, 0)
    state_to_handler, case_eas = cff_recover_dispatch_cases(blocks, current_key)
    if len(state_to_handler) < CFF_MIN_DISPATCH_CASES:
        cff_log('skip %s: dispatcher cases too few recovered=%d' % (ea_s(func_ea), len(state_to_handler)))
        return (False, 0)
    cff_log('state copy: next=%s current=%s copy=%s loop=%s dispatch_cases=%d stores=%d' % (next_key, current_key, ea_s(copy['copy_ea']), ea_s(loop_start), len(state_to_handler), copy['store_count']))
    for st, h in sorted(state_to_handler.items()):
        cff_log('  state %s -> handler %s' % (ea_s(st), ea_s(h)))
    if not CFF_PATCH:
        return (True, 0)
    start_map = cff_find_block_start_map(blocks)
    patched = 0
    patched_handlers = set()
    for st, handler in sorted(state_to_handler.items()):
        if patched >= CFF_MAX_PATCHED_EDGES_PER_FUNC:
            break
        if handler in patched_handlers:
            continue
        patched_handlers.add(handler)
        if cff_patch_handler_edge(blocks, start_map, handler, loop_start, next_key, state_to_handler):
            patched += 1
    return (True, patched)

def run_flattening_analyzer():
    if not ENABLE_CFF_ANALYZER:
        cff_log('disabled')
        return
    targets = cff_get_target_eas()
    if not targets:
        cff_log('no target function. Put cursor inside a function or set CFF_TARGET_EA')
        return
    cff_log('started targets=%d patch=%s' % (len(targets), str(CFF_PATCH)))
    matched = 0
    total_patched = 0
    for ea in targets:
        try:
            ok, patched = analyze_flattening_function(ea)
            if ok:
                matched += 1
                total_patched += patched
        except Exception as ex:
            cff_log('error at %s: %s' % (ea_s(ea), ex))
    cff_log('done. analyzed=%d matched=%d patched_edges=%d' % (len(targets), matched, total_patched))
    if total_patched:
        ida_auto.auto_wait()

class FoundGlobalQwordRebaseRef:

    def __init__(self):
        self.ins_ea = BADADDR
        self.next_ea = BADADDR
        self.kind = ''
        self.mn = ''
        self.mem_ea = BADADDR
        self.value = None
        self.operand_index = 1
        self.new_mem_ea = BADADDR
        self.reason = ''

_GLOBAL_QWORD_REBASE_CURSOR = GLOBAL_QWORD_REBASE_BASE

_GLOBAL_QWORD_REBASE_USED_RANGES = []

_GLOBAL_QWORD_REBASE_MAP = {}

def align_up_value(x, align):
    if align <= 1:
        return x
    return x + align - 1 & ~(align - 1)

def rebase_segment_ok(ea, size):
    seg = ida_segment.getseg(ea)
    if not seg:
        return False
    return ea + size <= int(seg.end_ea)

def rebase_slot_bytes_free(ea, size):
    data = ida_bytes.get_bytes(ea, size)
    if data is None:
        return True
    if len(data) != size:
        return False
    return all((b in (0, 144, 204, 255) for b in data))

def ranges_overlap(a0, a1, b0, b1):
    return a0 < b1 and b0 < a1

def rebase_overlaps_allocated(ea, size):
    end = ea + size
    for start, stop in _GLOBAL_QWORD_REBASE_USED_RANGES:
        if ranges_overlap(ea, end, start, stop):
            return True
    return False

def mark_rebase_allocated(ea, size):
    _GLOBAL_QWORD_REBASE_USED_RANGES.append((ea, ea + size))
    _GLOBAL_QWORD_REBASE_USED_RANGES.sort()

def alloc_global_qword_rebase_slot(size=8):
    global _GLOBAL_QWORD_REBASE_CURSOR
    align = max(1, int(GLOBAL_QWORD_REBASE_ALIGN))
    alloc_size = align_up_value(int(size), align)
    cur = align_up_value(_GLOBAL_QWORD_REBASE_CURSOR, align)
    limit = GLOBAL_QWORD_REBASE_BASE + GLOBAL_QWORD_REBASE_MAX
    while cur + alloc_size <= limit:
        if rebase_segment_ok(cur, alloc_size) and (not rebase_overlaps_allocated(cur, alloc_size)) and rebase_slot_bytes_free(cur, alloc_size):
            mark_rebase_allocated(cur, alloc_size)
            _GLOBAL_QWORD_REBASE_CURSOR = cur + alloc_size
            return cur
        cur = align_up_value(cur + align, align)
    return BADADDR

def read_fixed_qword_mem_src_from_op(ea, operand_index=1):
    if not is_fixed_mem_src(ea, operand_index):
        return (None, None)
    raw_src = ''
    try:
        raw_src = ida_lines.tag_remove(idc.print_operand(ea, operand_index)).lower()
    except Exception:
        raw_src = op(ea, operand_index)
    raw_src_compact = raw_src.replace(' ', '')
    if 'qword' not in raw_src_compact and 'off_' not in raw_src_compact:
        return (None, None)
    if regs_in_text(raw_src_compact):
        return (None, None)
    mem_ea = idc.get_operand_value(ea, operand_index)
    if mem_ea is None or mem_ea == BADADDR or (not ea_in_loaded(mem_ea)):
        return (None, None)
    if GLOBAL_QWORD_REBASE_SKIP_UNINIT_MEM_STORAGE and qword_storage_is_uninitialized(mem_ea):
        return (None, None)
    value = read_int_le(mem_ea, 8)
    if value is None:
        return (None, None)
    if GLOBAL_QWORD_REBASE_SKIP_UNKNOWN_QWORD_VALUE and qword_value_is_unknown_sentinel(value):
        return (None, None)
    return (mem_ea, value & MASK64)

def is_global_qword_rebase_candidate(ea):
    if not is_code_head(ea):
        return None
    mn = mnem(ea)
    if mn == 'mov':
        reg, value, mem_ea = read_mov_reg_fixed_mem64(ea)
        if reg is None:
            return None
        raw_src = ''
        try:
            raw_src = ida_lines.tag_remove(idc.print_operand(ea, 1)).lower()
        except Exception:
            raw_src = op(ea, 1)
        raw_src_compact = raw_src.replace(' ', '')
        if 'qword' not in raw_src_compact and 'off_' not in raw_src_compact:
            return None
        if regs_in_text(raw_src_compact):
            return None
        if GLOBAL_QWORD_REBASE_SKIP_UNINIT_MEM_POINTER_VALUE and qword_value_points_to_uninitialized_memory(value):
            return None
        p = FoundGlobalQwordRebaseRef()
        p.ins_ea = ea
        p.next_ea = item_end(ea)
        p.kind = 'mov'
        p.mn = mn
        p.mem_ea = mem_ea
        p.value = value & MASK64
        p.operand_index = 1
        return p
    if mn not in GLOBAL_QWORD_MEMOP_SUPPORTED_MNEMS:
        return None
    dst = op(ea, 0)
    if not is_reg_any(dst):
        return None
    if reg_bits(dst) != 64:
        return None
    dst_reg = normalize_reg(dst)
    if dst_reg not in REG64:
        return None
    if GLOBAL_QWORD_MEMOP_SKIP_RSP_DST and dst_reg == 'rsp':
        return None
    mem_ea, value = read_fixed_qword_mem_src_from_op(ea, 1)
    if mem_ea is None:
        return None
    if GLOBAL_QWORD_REBASE_SKIP_UNINIT_MEM_POINTER_VALUE and qword_value_points_to_uninitialized_memory(value):
        return None
    p = FoundGlobalQwordRebaseRef()
    p.ins_ea = ea
    p.next_ea = item_end(ea)
    p.kind = 'memop'
    p.mn = mn
    p.mem_ea = mem_ea
    p.value = value & MASK64
    p.operand_index = 1
    return p

def iter_global_qword_rebase_candidates(start, end):
    ea = start
    while ea < end:
        if not is_code_head(ea):
            ea += 1
            continue
        p = is_global_qword_rebase_candidate(ea)
        if p is not None:
            yield p
            ea = item_end(ea)
            continue
        ea = item_end(ea)

def get_data_xrefs_to_ea(mem_ea):
    refs = set()
    try:
        x = ida_xref.get_first_dref_to(mem_ea)
        while x != BADADDR:
            refs.add(int(x))
            x = ida_xref.get_next_dref_to(mem_ea, x)
    except Exception:
        pass
    return sorted(refs)

def operand_is_memory_ea(ea, idx, mem_ea):
    try:
        optype = idc.get_operand_type(ea, idx)
        if optype not in (idc.o_mem, idc.o_displ, idc.o_phrase):
            return False
        return (idc.get_operand_value(ea, idx) & MASK64) == (mem_ea & MASK64)
    except Exception:
        return False

def instruction_writes_global_qword(ea, mem_ea):
    return operand_is_memory_ea(ea, 0, mem_ea)

def ref_in_target_ranges(ea):
    return ea_in_ranges(ea, get_exec_ranges())

def classify_allowed_global_qword_ref(ea, mem_ea):
    if not is_code_head(ea):
        return None
    p = is_global_qword_rebase_candidate(ea)
    if p is None:
        return None
    if p.mem_ea != mem_ea:
        return None
    if instruction_writes_global_qword(ea, mem_ea):
        return None
    return p

def validate_global_qword_xrefs(mem_ea, known_refs):
    refs = set(get_data_xrefs_to_ea(mem_ea))
    refs.update(known_refs)
    safe = []
    unsafe = []
    for ea in sorted(refs):
        if ea == BADADDR:
            continue
        if GLOBAL_QWORD_REBASE_PATCH_ONLY_TARGET_RANGE and not ref_in_target_ranges(ea):
            unsafe.append((ea, 'xref outside target range'))
            continue
        p = classify_allowed_global_qword_ref(ea, mem_ea)
        if p is None:
            unsafe.append((ea, 'xref is not allowed read pattern'))
            continue
        safe.append(p)
    if unsafe and GLOBAL_QWORD_REBASE_REQUIRE_ALL_XREFS_SAFE:
        return (False, safe, unsafe)
    return (True, safe, unsafe)

def find_riprel_disp32_offset(ea, mem_ea):
    size = item_size(ea)
    data = ida_bytes.get_bytes(ea, size)
    if data is None or len(data) != size or size < 5:
        return None
    next_ea = item_end(ea)
    disp = (int(mem_ea) - int(next_ea)) & 0xFFFFFFFF
    needle = struct.pack('<I', disp)
    hits = []
    for i in range(0, size - 3):
        if data[i:i + 4] == needle:
            hits.append(i)
    if len(hits) == 1:
        return hits[0]
    if hits:
        return hits[-1]
    return None

def write_rebased_global_qword(mem_ea, value):
    if mem_ea in _GLOBAL_QWORD_REBASE_MAP:
        return _GLOBAL_QWORD_REBASE_MAP[mem_ea]
    new_ea = alloc_global_qword_rebase_slot(8)
    if new_ea == BADADDR:
        return BADADDR
    try:
        ida_bytes.del_items(new_ea, ida_bytes.DELIT_EXPAND, 8)
    except Exception:
        pass
    ida_bytes.patch_bytes(new_ea, struct.pack('<Q', value & MASK64))
    sync_uc_bytes(new_ea, struct.pack('<Q', value & MASK64))
    try:
        ida_bytes.create_qword(new_ea, 8)
    except Exception:
        try:
            idc.create_qword(new_ea)
        except Exception:
            pass
    _GLOBAL_QWORD_REBASE_MAP[mem_ea] = new_ea
    return new_ea

def patch_instruction_global_operand_to_new_qword(p, new_mem_ea):
    disp_off = find_riprel_disp32_offset(p.ins_ea, p.mem_ea)
    if disp_off is None:
        p.reason = 'cannot find old rip-relative disp32'
        return False
    new_disp = int(new_mem_ea) - int(item_end(p.ins_ea))
    if new_disp < -2147483648 or new_disp > 2147483647:
        p.reason = 'new global out of rel32 range'
        return False
    try:
        ida_bytes.patch_bytes(p.ins_ea + disp_off, struct.pack('<i', new_disp))
        sync_uc_bytes(p.ins_ea + disp_off, struct.pack('<i', new_disp))
        try:
            ida_ua.create_insn(p.ins_ea)
        except Exception:
            pass
        try:
            ida_xref.add_dref(p.ins_ea, new_mem_ea, ida_xref.dr_R)
        except Exception:
            pass
        return True
    except Exception as ex:
        p.reason = str(ex)
        return False

def patch_global_qword_rebase_refs():
    if not ENABLE_GLOBAL_QWORD_REBASE_PATCH:
        log('global_qword_rebase patch disabled')
        return
    total_groups = 0
    total_refs = 0
    total_patched = 0
    total_skipped = 0
    log('global_qword_rebase pass started base=%s align=0x%X cursor=%s' % (ea_s(GLOBAL_QWORD_REBASE_BASE), GLOBAL_QWORD_REBASE_ALIGN, ea_s(_GLOBAL_QWORD_REBASE_CURSOR)))
    for pass_no in range(1, int(GLOBAL_QWORD_REBASE_MAX_PASSES) + 1):
        groups = {}
        for start, end in get_exec_ranges():
            for p in iter_global_qword_rebase_candidates(start, end):
                groups.setdefault(p.mem_ea, []).append(p)
        pass_patched = 0
        pass_skipped = 0
        for mem_ea, refs in sorted(groups.items()):
            total_groups += 1
            known = [p.ins_ea for p in refs]
            ok, safe_refs, unsafe = validate_global_qword_xrefs(mem_ea, known)
            if not ok:
                pass_skipped += 1
                total_skipped += 1
                detail = ', '.join('%s:%s' % (ea_s(ea), reason) for ea, reason in unsafe[:5])
                log('global_qword_rebase skip %s: unsafe xrefs=%d %s' % (ea_s(mem_ea), len(unsafe), detail))
                continue
            if not safe_refs:
                pass_skipped += 1
                total_skipped += 1
                continue
            value = safe_refs[0].value & MASK64
            if any((p.value & MASK64) != value for p in safe_refs):
                pass_skipped += 1
                total_skipped += 1
                log('global_qword_rebase skip %s: inconsistent qword values across refs' % ea_s(mem_ea))
                continue
            new_mem_ea = write_rebased_global_qword(mem_ea, value)
            if new_mem_ea == BADADDR:
                pass_skipped += 1
                total_skipped += 1
                log('global_qword_rebase skip %s: no new global slot' % ea_s(mem_ea))
                continue
            patched_this = 0
            failed_this = 0
            seen_eas = set()
            for p in safe_refs:
                if p.ins_ea in seen_eas:
                    continue
                seen_eas.add(p.ins_ea)
                total_refs += 1
                p.new_mem_ea = new_mem_ea
                if patch_instruction_global_operand_to_new_qword(p, new_mem_ea):
                    patched_this += 1
                    pass_patched += 1
                    total_patched += 1
                else:
                    failed_this += 1
                    log('global_qword_rebase patch failed at %s old=%s new=%s reason=%s' % (ea_s(p.ins_ea), ea_s(mem_ea), ea_s(new_mem_ea), p.reason))
            log('global_qword_rebase %s -> %s value=0x%016X refs=%d patched=%d failed=%d unsafe=%d' % (ea_s(mem_ea), ea_s(new_mem_ea), value, len(safe_refs), patched_this, failed_this, len(unsafe)))
        log('global_qword_rebase pass %d done. groups=%d patched_refs=%d skipped_groups=%d' % (pass_no, len(groups), pass_patched, pass_skipped))
        if pass_patched == 0:
            break
    try:
        ida_auto.auto_wait()
    except Exception:
        pass
    log('global_qword_rebase done. groups=%d refs=%d patched=%d skipped=%d next_global=%s' % (total_groups, total_refs, total_patched, total_skipped, ea_s(_GLOBAL_QWORD_REBASE_CURSOR)))

def patch_jmp_rax_only():
    if not ENABLE_JMP_RAX_PATCH:
        log('jmp_rax patch disabled')
        return
    log('jmp_rax explicit multi-pass started')
    total_seen = 0
    total_resolved = 0
    total_patched = 0
    total_unresolved = 0
    total_failed = 0
    stop_reason = 'max passes reached'
    for pass_no in range(1, int(JMP_RAX_ONLY_MAX_PASSES) + 1):
        pass_seen = 0
        pass_resolved = 0
        pass_patched = 0
        pass_unresolved = 0
        pass_failed = 0
        progress = False
        for start, end in get_exec_ranges():
            for ea in iter_jmp_rax_fast(start, end):
                pass_seen += 1
                p = analyze_jmp(ea)
                if p is None:
                    pass_unresolved += 1
                    continue
                pass_resolved += 1
                if patch_pattern(p):
                    pass_patched += 1
                    progress = True
                else:
                    pass_failed += 1
        total_seen += pass_seen
        total_resolved += pass_resolved
        total_patched += pass_patched
        total_unresolved += pass_unresolved
        total_failed += pass_failed
        log('jmp_rax pass %d done. seen=%d resolved=%d patched=%d unresolved=%d failed=%d progress=%s' % (pass_no, pass_seen, pass_resolved, pass_patched, pass_unresolved, pass_failed, progress))
        if JMP_RAX_ONLY_AUTO_WAIT:
            try:
                ida_auto.auto_wait()
            except Exception:
                pass
        if pass_seen == 0:
            stop_reason = 'no jmp_rax left'
            break
        if not progress:
            stop_reason = 'no progress'
            break
    if FINAL_AUTO_WAIT:
        try:
            ida_auto.auto_wait()
        except Exception:
            pass
    log('jmp_rax explicit done. total_seen=%d total_resolved=%d total_patched=%d total_unresolved=%d total_failed=%d stop_reason=%s' % (total_seen, total_resolved, total_patched, total_unresolved, total_failed, stop_reason))

_HR_TEXT_PATCH_HOOK = None

ENABLE_HEXRAYS_TEXT_PATCH_HOOK = True

HR_TEXT_PATCH_VERBOSE = False

HR_TEXT_PATCH_CREATE_FUNC = True

HR_TEXT_PATCH_CREATE_XREF = True

HR_TEXT_PATCH_SKIP_UNINIT_MEM_STORAGE = True

HR_TEXT_PATCH_SKIP_UNKNOWN_QWORD_VALUE = True

HR_TEXT_PATCH_SKIP_UNINIT_TARGET_VALUE = True

def hr_text_log(s):
    print('[hr_text_patch] ' + s)

def hr_text_read_qword(ea):
    try:
        data = ida_bytes.get_bytes(int(ea), 8)
    except Exception:
        data = None
    if data is None or len(data) != 8:
        return None
    return int.from_bytes(data, 'little') & MASK64

def hr_text_parse_int(tok):
    if tok is None:
        return None
    t = str(tok).strip().lower()
    for suf in ('ull', 'llu', 'll', 'ui64', 'i64'):
        if t.endswith(suf):
            t = t[:-len(suf)]
            break
    try:
        if t.startswith('0x'):
            return int(t, 16) & MASK64
        if t.endswith('h'):
            return int(t[:-1], 16) & MASK64
        return int(t, 10) & MASK64
    except Exception:
        try:
            return int(t, 16) & MASK64
        except Exception:
            return None

def hr_text_name_to_ea(name):
    if not name:
        return BADADDR
    try:
        ea = idc.get_name_ea_simple(str(name))
        if ea != BADADDR:
            return int(ea)
    except Exception:
        pass
    try:
        return int(str(name).rsplit('_', 1)[1], 16)
    except Exception:
        return BADADDR

def hr_text_is_code_target(ea):
    try:
        return ea is not None and ea != BADADDR and ea_in_exec(int(ea))
    except Exception:
        return False

def hr_text_ensure_func_name(ea):
    ea = int(ea) & MASK64
    if HR_TEXT_PATCH_CREATE_FUNC:
        try:
            if idc.get_func_attr(ea, idc.FUNCATTR_START) == BADADDR:
                idc.create_insn(ea)
                idc.add_func(ea)
        except Exception:
            pass
    try:
        nm = idc.get_name(ea, idc.GN_VISIBLE)
    except Exception:
        nm = ''
    if not nm:
        nm = 'sub_%X' % ea
        try:
            idc.set_name(ea, nm, idc.SN_CHECK)
            nm = idc.get_name(ea, idc.GN_VISIBLE) or nm
        except Exception:
            pass
    return nm

def hr_text_should_skip_global_qword(gea, base):
    if HR_TEXT_PATCH_SKIP_UNINIT_MEM_STORAGE and qword_storage_is_uninitialized(gea):
        return True
    if HR_TEXT_PATCH_SKIP_UNKNOWN_QWORD_VALUE and qword_value_is_unknown_sentinel(base):
        return True
    return False

def hr_text_should_skip_arith_target(target):
    if HR_TEXT_PATCH_SKIP_UNKNOWN_QWORD_VALUE and qword_value_is_unknown_sentinel(target):
        return True
    if HR_TEXT_PATCH_SKIP_UNINIT_TARGET_VALUE and qword_value_points_to_uninitialized_memory(target):
        return True
    return False

def hr_text_eval_global_arith(name, opch, imm_tok):
    gea = hr_text_name_to_ea(name)
    if gea == BADADDR:
        return None
    base = hr_text_read_qword(gea)
    if base is None:
        return None
    if hr_text_should_skip_global_qword(gea, base):
        return None
    imm = hr_text_parse_int(imm_tok)
    if imm is None:
        imm = 0
    if opch == '-':
        target = base - imm & MASK64
    else:
        target = base + imm & MASK64
    if hr_text_is_code_target(target):
        return target
    if hr_text_should_skip_arith_target(target):
        return None
    return target

def hr_text_cname(s):
    return str(s)

def hr_text_number(value):
    return '0x%XLL' % (int(value) & MASK64)

def hr_text_func_call(name):
    return '%s()' % hr_text_cname(name)

def hr_text_func_ptr_literal(value):
    return '((void (*)(void))%s)()' % hr_text_number(value)

_HR_GENERIC_CALL_ARITH_RE = re.compile('\\(\\((?P<cast>[^\\n]*?)\\)\\((?P<name>(?:unk|qword|off)_[0-9A-Fa-f]+)\\s*(?P<op>[+-])\\s*(?P<imm>(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h|\\d+)(?:u?ll|i64)?)\\)\\)\\s*\\(', re.IGNORECASE)

_HR_GENERIC_CALL_LITERAL_RE = re.compile('\\(\\((?P<cast>[^\\n]*?)\\)(?P<addr>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h)(?:u?ll|i64)?\\)\\s*\\(', re.IGNORECASE)

_HR_CALL_ARITH_RE = re.compile('\\(\\(void\\s*\\(\\*\\)\\(void\\)\\)\\((?P<name>(?:unk|qword|off)_[0-9A-Fa-f]+)\\s*(?P<op>[+-])\\s*(?P<imm>(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h|\\d+)(?:u?ll|i64)?)\\)\\)\\(\\)', re.IGNORECASE)

_HR_CALL_LITERAL_RE = re.compile('\\(\\(void\\s*\\(\\*\\)\\(void\\)\\)(?P<addr>0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h)(?:u?ll|i64)?\\)\\(\\)', re.IGNORECASE)

_HR_GLOBAL_ARITH_RE = re.compile('(?P<name>(?:unk|qword|off)_[0-9A-Fa-f]+)\\s*(?P<op>[+-])\\s*(?P<imm>(?:0x[0-9A-Fa-f]+|[0-9A-Fa-f]+h|\\d+)(?:u?ll|i64)?)', re.IGNORECASE)

def hr_text_find_replacements(clean_line, ea=BADADDR):
    reps = []
    occupied = []

    def overlaps(a, b):
        for x0, x1 in occupied:
            if a < x1 and x0 < b:
                return True
        return False

    def add_rep(start, end, text):
        if start >= end or overlaps(start, end):
            return
        reps.append((start, end, text))
        occupied.append((start, end))
    for m in _HR_GENERIC_CALL_ARITH_RE.finditer(clean_line):
        target = hr_text_eval_global_arith(m.group('name'), m.group('op'), m.group('imm'))
        if target is None:
            continue
        if hr_text_is_code_target(target):
            nm = hr_text_ensure_func_name(target)
            if HR_TEXT_PATCH_CREATE_XREF and ea != BADADDR:
                try:
                    ida_xref.add_cref(int(ea), int(target), ida_xref.fl_CN)
                except Exception:
                    pass
            add_rep(m.start(), m.end(), hr_text_cname(nm) + '(')
        else:
            add_rep(m.start(), m.end(), hr_text_func_ptr_literal(target)[:-1])
    for m in _HR_GENERIC_CALL_LITERAL_RE.finditer(clean_line):
        target = hr_text_parse_int(m.group('addr'))
        if target is None or not hr_text_is_code_target(target):
            continue
        nm = hr_text_ensure_func_name(target)
        if HR_TEXT_PATCH_CREATE_XREF and ea != BADADDR:
            try:
                ida_xref.add_cref(int(ea), int(target), ida_xref.fl_CN)
            except Exception:
                pass
        add_rep(m.start(), m.end(), hr_text_cname(nm) + '(')
    for m in _HR_CALL_ARITH_RE.finditer(clean_line):
        target = hr_text_eval_global_arith(m.group('name'), m.group('op'), m.group('imm'))
        if target is None:
            continue
        if hr_text_is_code_target(target):
            nm = hr_text_ensure_func_name(target)
            if HR_TEXT_PATCH_CREATE_XREF and ea != BADADDR:
                try:
                    ida_xref.add_cref(int(ea), int(target), ida_xref.fl_CN)
                except Exception:
                    pass
            add_rep(m.start(), m.end(), hr_text_func_call(nm))
        else:
            add_rep(m.start(), m.end(), hr_text_func_ptr_literal(target))
    for m in _HR_CALL_LITERAL_RE.finditer(clean_line):
        target = hr_text_parse_int(m.group('addr'))
        if target is None or not hr_text_is_code_target(target):
            continue
        nm = hr_text_ensure_func_name(target)
        if HR_TEXT_PATCH_CREATE_XREF and ea != BADADDR:
            try:
                ida_xref.add_cref(int(ea), int(target), ida_xref.fl_CN)
            except Exception:
                pass
        add_rep(m.start(), m.end(), hr_text_func_call(nm))
    for m in _HR_GLOBAL_ARITH_RE.finditer(clean_line):
        target = hr_text_eval_global_arith(m.group('name'), m.group('op'), m.group('imm'))
        if target is None:
            continue
        if hr_text_is_code_target(target):
            nm = hr_text_ensure_func_name(target)
            add_rep(m.start(), m.end(), hr_text_cname(nm))
        else:
            add_rep(m.start(), m.end(), hr_text_number(target))
    reps.sort(key=lambda x: x[0])
    return reps

def hr_text_patch_clean_line(clean_line, ea=BADADDR):
    reps = hr_text_find_replacements(clean_line, ea)
    if not reps:
        return (clean_line, False)
    out = []
    last = 0
    for start, end, repl in reps:
        out.append(clean_line[last:start])
        out.append(repl)
        last = end
    out.append(clean_line[last:])
    return (''.join(out), True)

def hr_text_strip_with_map(raw):
    plain = []
    mapping = []
    i = 0
    n = len(raw)
    while i < n:
        ch = raw[i]
        oc = ord(ch)
        if ch in ('\x01', '\x02'):
            i += 2
            continue
        if oc < 32 and ch not in ('\t', '\n', '\r'):
            i += 1
            continue
        plain.append(ch)
        mapping.append(i)
        i += 1
    return (''.join(plain), mapping)

def hr_text_apply_replacements_to_raw(raw, reps):
    if not reps:
        return (raw, False)
    plain, mapping = hr_text_strip_with_map(raw)
    if ida_lines.tag_remove(raw) != plain:
        patched, changed = hr_text_patch_clean_line(ida_lines.tag_remove(raw), BADADDR)
        return (patched, changed)
    pieces = []
    raw_pos = 0
    for start, end, repl in reps:
        if start >= len(mapping):
            continue
        raw_start = mapping[start]
        raw_end = mapping[end - 1] + 1 if end - 1 < len(mapping) else len(raw)
        pieces.append(raw[raw_pos:raw_start])
        pieces.append(repl)
        raw_pos = raw_end
    pieces.append(raw[raw_pos:])
    return (''.join(pieces), True)

class HexRaysTextPatchHook(ida_hexrays.Hexrays_Hooks):

    def __init__(self):
        ida_hexrays.Hexrays_Hooks.__init__(self)
        self.changed_count = 0

    def _patch_cfunc_text(self, cfunc, stage):
        try:
            sv = cfunc.get_pseudocode()
        except Exception:
            return 0
        total = 0
        try:
            ea = cfunc.entry_ea
        except Exception:
            ea = BADADDR
        for i in range(len(sv)):
            try:
                raw = sv[i].line
                clean = ida_lines.tag_remove(raw)
            except Exception:
                continue
            try:
                reps = hr_text_find_replacements(clean, ea)
            except Exception:
                reps = []
            if not reps:
                continue
            try:
                new_raw, changed = hr_text_apply_replacements_to_raw(raw, reps)
            except Exception:
                new_raw, changed = hr_text_patch_clean_line(clean, ea)
            if not changed or new_raw == raw:
                continue
            try:
                sv[i].line = new_raw
                total += 1
            except Exception:
                pass
        if total:
            self.changed_count += total
            if HR_TEXT_PATCH_VERBOSE:
                hr_text_log('patched %d pseudocode lines in %s' % (total, stage))
        return 0

    def func_printed(self, cfunc):
        return self._patch_cfunc_text(cfunc, 'func_printed')

    def text_ready(self, cfunc):
        return self._patch_cfunc_text(cfunc, 'text_ready')

def install_hexrays_text_patch_hook():
    global _HR_TEXT_PATCH_HOOK
    if not ENABLE_HEXRAYS_TEXT_PATCH_HOOK:
        return False
    try:
        if not ida_hexrays.init_hexrays_plugin():
            hr_text_log('Hex-Rays is not available')
            return False
    except Exception as ex:
        hr_text_log('Hex-Rays init failed: %s' % ex)
        return False
    if _HR_TEXT_PATCH_HOOK is not None:
        hr_text_log('text patch hook already installed')
        return True
    h = HexRaysTextPatchHook()
    try:
        ok = bool(h.hook())
    except Exception as ex:
        hr_text_log('hook failed: %s' % ex)
        return False
    if not ok:
        hr_text_log('hook returned false')
        return False
    _HR_TEXT_PATCH_HOOK = h
    try:
        ida_hexrays.clear_cached_cfuncs()
    except Exception:
        pass
    hr_text_log('installed text-only hook; plain replacements, no ctree/microcode mutation')
    return True

DEFLAT_GUI_ACTION_NAME = "deob:deflat_current_function"
DEFLAT_GUI_ACTION_LABEL = "Deobfuscation"
DEFLAT_GUI_ACTION_PATH = ""
DEFLAT_ALL_GUI_ACTION_NAME = "deob:deflat_all_functions"
DEFLAT_ALL_GUI_ACTION_LABEL = "Deobfuscation All Functions"
DEFLAT_ALL_GUI_ACTION_PATH = ""
_DEFLAT_GUI_HOOK = None
_DEFLAT_GUI_ACTION_REGISTERED = False

def gui_widget_type(widget):
    try:
        return ida_kernwin.get_widget_type(widget)
    except Exception:
        return -1

def gui_is_pseudocode_widget(widget):
    return gui_widget_type(widget) == getattr(ida_kernwin, 'BWN_PSEUDOCODE', -101)

def gui_get_pseudocode_ea(widget=None):
    try:
        if widget is None:
            widget = ida_kernwin.get_current_widget()
    except Exception:
        widget = None

    if widget is None:
        return BADADDR

    try:
        vdui = ida_hexrays.get_widget_vdui(widget)
    except Exception:
        vdui = None

    if vdui is None:
        return BADADDR

    for getter in (
        lambda: int(vdui.item.e.ea),
        lambda: int(vdui.item.it.ea),
        lambda: int(vdui.cfunc.entry_ea),
    ):
        try:
            ea = getter()
            if ea != BADADDR and ida_funcs.get_func(ea):
                return ea
        except Exception:
            pass

    try:
        if vdui.cfunc:
            ea = int(vdui.cfunc.entry_ea)
            if ea != BADADDR:
                return ea
    except Exception:
        pass

    return BADADDR

def gui_get_ctx_ea(ctx=None):
    widget = None

    if ctx is not None:
        try:
            widget = ctx.widget
        except Exception:
            widget = None

        if widget is not None and gui_is_pseudocode_widget(widget):
            ea = gui_get_pseudocode_ea(widget)
            if ea != BADADDR:
                return ea

        try:
            ea = int(ctx.cur_ea)
            if ea != BADADDR:
                return ea
        except Exception:
            pass

    try:
        widget = ida_kernwin.get_current_widget()
    except Exception:
        widget = None

    if widget is not None and gui_is_pseudocode_widget(widget):
        ea = gui_get_pseudocode_ea(widget)
        if ea != BADADDR:
            return ea

    try:
        ea = ida_kernwin.get_screen_ea()
        if ea != BADADDR:
            return int(ea)
    except Exception:
        pass

    try:
        return int(idc.here())
    except Exception:
        return BADADDR

def gui_get_func_start_from_ctx(ctx=None):
    ea = gui_get_ctx_ea(ctx)
    if ea == BADADDR:
        return BADADDR

    try:
        f = ida_funcs.get_func(ea)
        if f:
            return int(f.start_ea)
    except Exception:
        pass

    return BADADDR

def gui_get_func_start_from_widget(widget):
    if widget is not None and gui_is_pseudocode_widget(widget):
        ea = gui_get_pseudocode_ea(widget)
    else:
        try:
            ea = ida_kernwin.get_screen_ea()
        except Exception:
            ea = BADADDR

    if ea == BADADDR:
        return BADADDR

    try:
        f = ida_funcs.get_func(ea)
        if f:
            return int(f.start_ea)
    except Exception:
        pass

    return BADADDR

def deflat_current_function_at(ea=None):
    if ea is None or ea == BADADDR:
        ea = gui_get_ctx_ea(None)

    try:
        f = ida_funcs.get_func(ea)
    except Exception:
        f = None

    if not f:
        cff_log('GUI deflat: no function at %s' % ea_s(ea))
        return False

    start = int(f.start_ea)
    cff_log('GUI deflat current function: %s' % ea_s(start))

    try:
        ok, patched = analyze_flattening_function(start)
    except Exception as ex:
        cff_log('GUI deflat error at %s: %s' % (ea_s(start), ex))
        return False

    cff_log('GUI deflat done: function=%s matched=%s patched_edges=%d' % (ea_s(start), str(ok), int(patched)))

    if patched:
        try:
            ida_auto.plan_range(int(f.start_ea), int(f.end_ea))
        except Exception:
            pass
        try:
            ida_auto.auto_wait()
        except Exception:
            pass
        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass
        try:
            ida_hexrays.clear_cached_cfuncs()
        except Exception:
            pass

    return bool(ok)

deflat_all_functions_running = False

def deflat_all_functions_in_first_segment():
    global deflat_all_functions_running
    global CFF_SCAN_ALL_FUNCTIONS_IN_FIRST_SEGMENT

    if deflat_all_functions_running:
        cff_log('GUI deflat all: already running')
        return False

    old_scan_all = CFF_SCAN_ALL_FUNCTIONS_IN_FIRST_SEGMENT
    deflat_all_functions_running = True

    try:
        CFF_SCAN_ALL_FUNCTIONS_IN_FIRST_SEGMENT = True
        cff_log('GUI deflat all functions started')
        run_flattening_analyzer()
        cff_log('GUI deflat all functions done')

        try:
            ida_auto.auto_wait()
        except Exception:
            pass

        try:
            ida_kernwin.refresh_idaview_anyway()
        except Exception:
            pass

        try:
            ida_hexrays.clear_cached_cfuncs()
        except Exception:
            pass

        return True

    except Exception as ex:
        cff_log('GUI deflat all functions error: %s' % ex)
        return False

    finally:
        CFF_SCAN_ALL_FUNCTIONS_IN_FIRST_SEGMENT = old_scan_all
        deflat_all_functions_running = False

class DeflatCurrentFunctionActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        ea = gui_get_ctx_ea(ctx)
        deflat_current_function_at(ea)
        return 1

    def update(self, ctx):
        start = gui_get_func_start_from_ctx(ctx)
        if start != BADADDR:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class DeflatAllFunctionsActionHandler(ida_kernwin.action_handler_t):
    def __init__(self):
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        deflat_all_functions_in_first_segment()
        return 1

    def update(self, ctx):
        if get_first_target_segment() is not None:
            return ida_kernwin.AST_ENABLE_FOR_WIDGET
        return ida_kernwin.AST_DISABLE_FOR_WIDGET

class DeflatPopupHooks(ida_kernwin.UI_Hooks):
    def finish_populating_widget_popup(self, widget, popup):
        try:
            wt = gui_widget_type(widget)
            if wt not in (
                getattr(ida_kernwin, 'BWN_DISASM', -100),
                getattr(ida_kernwin, 'BWN_PSEUDOCODE', -101),
            ):
                return 0
        except Exception:
            return 0

        if gui_get_func_start_from_widget(widget) == BADADDR:
            return 0

        try:
            ida_kernwin.attach_action_to_popup(widget, popup, DEFLAT_GUI_ACTION_NAME, DEFLAT_GUI_ACTION_PATH)
            ida_kernwin.attach_action_to_popup(widget, popup, DEFLAT_ALL_GUI_ACTION_NAME, DEFLAT_ALL_GUI_ACTION_PATH)
        except Exception as ex:
            cff_log('GUI deflat attach popup failed: %s' % ex)
        return 0

def install_deflat_gui_action():
    global _DEFLAT_GUI_HOOK, _DEFLAT_GUI_ACTION_REGISTERED

    if _DEFLAT_GUI_ACTION_REGISTERED:
        cff_log('GUI deflat actions already installed')
        return True

    desc_current = ida_kernwin.action_desc_t(
        DEFLAT_GUI_ACTION_NAME,
        DEFLAT_GUI_ACTION_LABEL,
        DeflatCurrentFunctionActionHandler(),
        None,
        'Run CFF deflat for the current function',
        -1,
    )

    desc_all = ida_kernwin.action_desc_t(
        DEFLAT_ALL_GUI_ACTION_NAME,
        DEFLAT_ALL_GUI_ACTION_LABEL,
        DeflatAllFunctionsActionHandler(),
        None,
        'Run CFF deflat for all functions in the first executable segment',
        -1,
    )

    for action_name, desc in (
        (DEFLAT_GUI_ACTION_NAME, desc_current),
        (DEFLAT_ALL_GUI_ACTION_NAME, desc_all),
    ):
        try:
            ok = ida_kernwin.register_action(desc)
        except Exception as ex:
            cff_log('GUI deflat register_action failed for %s: %s' % (action_name, ex))
            ok = False

        if not ok:
            try:
                ida_kernwin.unregister_action(action_name)
                ok = ida_kernwin.register_action(desc)
            except Exception as ex:
                cff_log('GUI deflat re-register failed for %s: %s' % (action_name, ex))
                ok = False

        if not ok:
            for cleanup_name in (DEFLAT_GUI_ACTION_NAME, DEFLAT_ALL_GUI_ACTION_NAME):
                try:
                    ida_kernwin.unregister_action(cleanup_name)
                except Exception:
                    pass
            return False

    _DEFLAT_GUI_HOOK = DeflatPopupHooks()
    try:
        _DEFLAT_GUI_HOOK.hook()
    except Exception as ex:
        cff_log('GUI deflat UI hook failed: %s' % ex)
        for cleanup_name in (DEFLAT_GUI_ACTION_NAME, DEFLAT_ALL_GUI_ACTION_NAME):
            try:
                ida_kernwin.unregister_action(cleanup_name)
            except Exception:
                pass
        _DEFLAT_GUI_HOOK = None
        return False

    _DEFLAT_GUI_ACTION_REGISTERED = True
    cff_log('GUI deflat actions installed: right click -> Deobfuscation / Deobfuscation All Functions')
    return True

if __name__ == "__main__":
    
    run_makecode_first()
    patch_jmp_rax_only()
    run_makecode_first()
    run_flattening_analyzer()
    run_makecode_first()
    patch_global_qword_rebase_refs()
    install_hexrays_text_patch_hook()
    install_deflat_gui_action()
    run_flattening_analyzer()
