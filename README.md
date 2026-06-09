# earth-lamia

<img width="918" height="186" alt="ảnh" src="https://github.com/user-attachments/assets/ef350c46-49a9-458f-bbc9-3df0dc24ae1a" />

<img width="848" height="792" alt="ảnh" src="https://github.com/user-attachments/assets/803e8f44-5d99-49ac-84e5-393e3e51d4fc" />

<img width="843" height="784" alt="ảnh" src="https://github.com/user-attachments/assets/36d55ce6-2789-458f-9d00-5ada24ed2ea0" />

<img width="845" height="794" alt="ảnh" src="https://github.com/user-attachments/assets/6740ad0c-ea99-4afa-87eb-cb244b7f062c" />

Bài cho 1 file exe, 1 file dll fake userenv.dll bị pack bằng themida và 1 file dll đã bị mã hóa

debug chương trình:

<img width="1919" height="859" alt="ảnh" src="https://github.com/user-attachments/assets/84cfc484-439f-47b7-a9f4-9d9b6b19e6fa" />

Chương trình phát hiện debugger do có cơ chế antidebug của themida sau khi load USERENV.DLL

để bypass antidebug 1 cách nhanh nhất thì ta sử dụng scyllahide

<img width="1915" height="733" alt="ảnh" src="https://github.com/user-attachments/assets/8192edb4-e516-42fc-b6f7-1e894c81744d" />

<img width="1919" height="857" alt="ảnh" src="https://github.com/user-attachments/assets/07ddd5b3-8b89-4bd7-b6d1-d933389bf8d9" />

Bây giờ chương trình đã bypass antidebug và có thể debug bình thường

Để phân tích chương trình thì ta cần unpack themida

Tìm OEP: 

Ta đã biết rằng USERENV.DLL là file pe tự compile nên ta có thể đặt breakpoint ở `GetSystemTimeAsFileTime` để tìm oep

<img width="1328" height="366" alt="ảnh" src="https://github.com/user-attachments/assets/c8c03a10-f197-4905-822e-e3da117dd09a" />

Vậy oep nằm ở `USERENV.DLL + 0x2671c`

Fix Imports:

mở scylla:

<img width="1919" height="861" alt="ảnh" src="https://github.com/user-attachments/assets/6a26ac46-7c9f-4b63-8a75-04ed737d83b6" />

Phần lớn import đều là invalid scylla không parse được

Tìm đến IAT:

<img width="1321" height="320" alt="ảnh" src="https://github.com/user-attachments/assets/868d0752-0c6d-40f5-847f-8fe08fa660ab" />

<img width="1339" height="365" alt="ảnh" src="https://github.com/user-attachments/assets/7e8af3ab-1492-443d-a5a9-94003a10de29" />

<img width="1334" height="318" alt="ảnh" src="https://github.com/user-attachments/assets/1e3195ec-ecce-4509-a068-da8ae900fc64" />


các hàm tại IAT không trực tiếp trỏ đến API mà qua 1 trampoline rồi mới ret về API

Ý tưởng:
- đặt breakpoint tại oep
- mở scylla quét tìm IAT và size IAT
- viết script IDAPython quét IAT, những địa chỉ nào đã trỏ tới dll sẵn thì bỏ qua
- những địa chỉ nào tại trampoline thì dùng unicorn map lên mem 1 page tại địa chỉ đó và thực thi, hook mem ivalid khi thực thi đến vùng chưa map
- nếu thực thi đến vùng ngoài module đang xét và có .dll thì lấy địa chỉ api và patch lại vào iat để scylla có thể parse

script:

```python
import os
import struct

import idaapi
import ida_bytes
import ida_dbg
import ida_idd
import idc

from unicorn import *
from unicorn.x86_const import *


IAT_START = 0x7FFFBF38AC78
IAT_SIZE  = 0x508

PTR_SIZE = 8
PAGE_SIZE = 0x1000
MAX_INSNS = 8000

STACK_BASE = 0x700000000000
STACK_SIZE = 0x200000

REQUIRE_DLL = True


REGS = {
    "RAX": UC_X86_REG_RAX,
    "RBX": UC_X86_REG_RBX,
    "RCX": UC_X86_REG_RCX,
    "RDX": UC_X86_REG_RDX,
    "RSI": UC_X86_REG_RSI,
    "RDI": UC_X86_REG_RDI,
    "RBP": UC_X86_REG_RBP,
    "RSP": UC_X86_REG_RSP,
    "R8":  UC_X86_REG_R8,
    "R9":  UC_X86_REG_R9,
    "R10": UC_X86_REG_R10,
    "R11": UC_X86_REG_R11,
    "R12": UC_X86_REG_R12,
    "R13": UC_X86_REG_R13,
    "R14": UC_X86_REG_R14,
    "R15": UC_X86_REG_R15,
    "EFLAGS": UC_X86_REG_EFLAGS,
}


def u64(x):
    try:
        return int(x) & 0xFFFFFFFFFFFFFFFF
    except Exception:
        return None


def hx(x):
    x = u64(x)
    return "None" if x is None else "0x%X" % x


def valid(x):
    x = u64(x)
    return x not in (None, 0, u64(idaapi.BADADDR), 0xFFFFFFFFFFFFFFFF)


def page(x):
    return u64(x) & ~(PAGE_SIZE - 1)


def read_dbg(ea, size):
    ea = u64(ea)
    if ea is None:
        return None

    try:
        buf = bytearray(size)
        if ida_dbg.read_dbg_memory(ea, buf, size):
            return bytes(buf)
    except Exception:
        pass

    try:
        data = ida_dbg.read_dbg_memory(ea, size)
        if data:
            return bytes(data)
    except Exception:
        pass

    try:
        return ida_bytes.get_bytes(ea, size)
    except Exception:
        return None


def write_dbg(ea, data):
    ea = u64(ea)
    if ea is None:
        return False

    try:
        if ida_dbg.write_dbg_memory(ea, data):
            return True
    except Exception:
        pass

    try:
        if ida_dbg.write_dbg_memory(ea, data, len(data)):
            return True
    except Exception:
        pass

    return False


def read_qword(ea):
    data = read_dbg(ea, 8)
    if data and len(data) == 8:
        return u64(struct.unpack("<Q", data)[0])

    try:
        return u64(ida_bytes.get_qword(u64(ea)))
    except Exception:
        return None


def write_qword(ea, value):
    ea = u64(ea)
    value = u64(value)

    if ea is None or value is None:
        return False

    ida_bytes.patch_qword(ea, value)
    return write_dbg(ea, struct.pack("<Q", value))


def get_mod(ea):
    ea = u64(ea)
    if not valid(ea):
        return None

    for cls in (getattr(ida_idd, "modinfo_t", None), getattr(ida_dbg, "modinfo_t", None)):
        if cls is None:
            continue

        try:
            m = cls()
            if not ida_dbg.get_module_info(ea, m):
                continue

            name = getattr(m, "name", "") or ""

            base = None
            end = None
            size = None

            for attr in ("base", "start_ea", "start", "modbase"):
                if hasattr(m, attr):
                    base = u64(getattr(m, attr))
                    if valid(base):
                        break

            for attr in ("end_ea", "end"):
                if hasattr(m, attr):
                    end = u64(getattr(m, attr))
                    if valid(end):
                        break

            for attr in ("size", "modsize"):
                if hasattr(m, attr):
                    size = u64(getattr(m, attr))
                    if valid(size):
                        break

            if valid(base) and valid(size):
                return {"base": base, "end": base + size, "name": name}

            if valid(base) and valid(end) and end > base:
                return {"base": base, "end": end, "name": name}

        except Exception:
            pass

    return None


CUR_MOD = get_mod(IAT_START)

if not CUR_MOD:
    raise RuntimeError("Cannot get module containing IAT_START")

CUR_BASE = CUR_MOD["base"]
CUR_END = CUR_MOD["end"]
CUR_NAME = CUR_MOD["name"]


def in_current(ea):
    ea = u64(ea)
    return valid(ea) and CUR_BASE <= ea < CUR_END


def out_current(ea):
    ea = u64(ea)
    return valid(ea) and not in_current(ea)


def module_name(ea):
    m = get_mod(ea)
    return m["name"] if m else ""


def is_dll(ea):
    name = module_name(ea).lower()
    return name.endswith(".dll") or ".dll" in name


def good_api(ea):
    ea = u64(ea)

    if not valid(ea):
        return False

    if not out_current(ea):
        return False

    if REQUIRE_DLL and not is_dll(ea):
        return False

    return True


def short_mod(name):
    if not name:
        return ""
    return os.path.basename(name.replace("\\", "/"))


def api_name(ea):
    ea = u64(ea)

    name = ""

    try:
        name = idc.get_name(ea, idc.GN_VISIBLE) or ""
    except Exception:
        pass

    if not name:
        try:
            name = idc.get_func_name(ea) or ""
        except Exception:
            pass

    mod = module_name(ea)
    smod = short_mod(mod)

    if smod and name:
        return "%s!%s" % (smod, name)

    m = get_mod(ea)
    if smod and m:
        return "%s+0x%X" % (smod, ea - m["base"])

    return hx(ea)


def ida_reg(name):
    for n in (name, name.lower()):
        try:
            return u64(idc.get_reg_value(n))
        except Exception:
            pass
    return 0


def first_insn_is_jmp(ea):
    ea = u64(ea)
    if not valid(ea):
        return False

    try:
        mnem = (idc.print_insn_mnem(ea) or "").lower()
        if mnem == "jmp":
            return True
    except Exception:
        pass

    data = read_dbg(ea, 8)
    if not data:
        return False

    b0 = data[0]

    if b0 in (0xE9, 0xEB):
        return True

    if len(data) >= 2 and b0 == 0xFF:
        modrm = data[1]
        reg = (modrm >> 3) & 7
        if reg == 4:
            return True

    return False


mu = Uc(UC_ARCH_X86, UC_MODE_64)
mapped_pages = set()
cache = {}


try:
    mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
except UcError:
    pass


def map_page(ea):
    ea = u64(ea)
    if ea is None:
        return False

    base = page(ea)

    if base in mapped_pages:
        return True

    data = read_dbg(base, PAGE_SIZE)
    if not data:
        return False

    if len(data) < PAGE_SIZE:
        data += b"\x00" * (PAGE_SIZE - len(data))

    try:
        mu.mem_map(base, PAGE_SIZE, UC_PROT_ALL)
    except UcError:
        pass

    try:
        mu.mem_write(base, data[:PAGE_SIZE])
        mapped_pages.add(base)
        return True
    except UcError:
        return False


class State:
    target = None
    reason = ""


state = State()


def stop(target, reason):
    state.target = u64(target)
    state.reason = reason

    try:
        mu.emu_stop()
    except Exception:
        pass


def hook_block(mu, address, size, user_data):
    address = u64(address)

    if good_api(address):
        stop(address, "block_api")
        return

    if out_current(address):
        stop(None, "block_outside:%s:%s" % (hx(address), module_name(address)))
        return


def hook_invalid(mu, access, address, size, value, user_data):
    address = u64(address)

    if access in (UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT):
        if good_api(address):
            stop(address, "fetch_api")
            return False

        if out_current(address):
            stop(None, "fetch_outside:%s:%s" % (hx(address), module_name(address)))
            return False

    if map_page(address):
        return True

    state.reason = "unmapped access=%d addr=%s" % (access, hx(address))
    return False


mu.hook_add(UC_HOOK_BLOCK, hook_block)
mu.hook_add(UC_HOOK_MEM_INVALID, hook_invalid)


def reset_emulator(tramp):
    for name, reg in REGS.items():
        if name == "RSP":
            mu.reg_write(reg, STACK_BASE + STACK_SIZE - 0x100)
        else:
            mu.reg_write(reg, ida_reg(name))

    mu.reg_write(UC_X86_REG_RIP, u64(tramp))

    try:
        mu.mem_write(STACK_BASE + STACK_SIZE - 0x4000, b"\x00" * 0x4000)
    except UcError:
        pass


def resolve(tramp):
    tramp = u64(tramp)

    if good_api(tramp):
        return tramp, "already_api"

    if tramp in cache:
        return cache[tramp], "cache"

    if not map_page(tramp):
        return None, "cannot_map:%s" % hx(tramp)

    state.target = None
    state.reason = ""

    reset_emulator(tramp)

    try:
        mu.emu_start(tramp, 0, timeout=0, count=MAX_INSNS)
    except UcError:
        pass

    rip = u64(mu.reg_read(UC_X86_REG_RIP))

    if good_api(state.target):
        cache[tramp] = state.target
        return state.target, state.reason

    if good_api(rip):
        cache[tramp] = rip
        return rip, "final_rip"

    return None, state.reason or "no_target rip=%s mod=%s" % (hx(rip), module_name(rip))


def patch_iat(slot, api):
    ok = write_qword(slot, api)

    if page(slot) in mapped_pages:
        try:
            mu.mem_write(u64(slot), struct.pack("<Q", u64(api)))
        except UcError:
            pass

    return ok


def main():
    fixed = 0
    skipped = 0
    skipped_nonjmp = 0
    failed = 0
    fixed_list = []

    print("module=%s-%s %s" % (hx(CUR_BASE), hx(CUR_END), CUR_NAME))
    print("iat=%s-%s" % (hx(IAT_START), hx(IAT_START + IAT_SIZE)))

    for off in range(0, IAT_SIZE, PTR_SIZE):
        slot = IAT_START + off
        ptr = read_qword(slot)

        if not valid(ptr):
            skipped += 1
            continue

        if good_api(ptr):
            skipped += 1
            continue

        if not in_current(ptr):
            skipped += 1
            continue

        if not first_insn_is_jmp(ptr):
            skipped_nonjmp += 1
            continue

        api, reason = resolve(ptr)

        if good_api(api):
            patch_iat(slot, api)
            name = api_name(api)

            print("[+] %s: %s -> %s  %s  %s" % (
                hx(slot),
                hx(ptr),
                hx(api),
                name,
                reason
            ))

            fixed_list.append((slot, ptr, api, name, reason))
            fixed += 1
        else:
            print("[-] %s: failed %s reason=%s" % (hx(slot), hx(ptr), reason))
            failed += 1

    print("")
    print("fixed api list:")

    for slot, tramp, api, name, reason in fixed_list:
        print("%s | %s | %s | %s | %s" % (
            hx(slot),
            hx(tramp),
            hx(api),
            name,
            reason
        ))

    print("done fixed=%d skipped=%d skipped_nonjmp=%d failed=%d cache=%d mapped_pages=%d" % (
        fixed,
        skipped,
        skipped_nonjmp,
        failed,
        len(cache),
        len(mapped_pages)
    ))


main()
```

<img width="1322" height="320" alt="ảnh" src="https://github.com/user-attachments/assets/21c3b1b3-c4f3-4659-9589-9a49904b5db5" />

<img width="733" height="801" alt="ảnh" src="https://github.com/user-attachments/assets/2ad4db7c-5923-42a9-a273-fb4ef8b7beb5" />

Ta thấy đã resolve được hết các imports, 13 apis lỗi trên là do scylla parse sai, ta sẽ bỏ nó đi

Dump:

dùng ollydumpex để dump dll ra:

<img width="1919" height="855" alt="ảnh" src="https://github.com/user-attachments/assets/06ac9f41-12de-40e3-855e-26406aedfd5e" />

fix imports bằng scylla:

<img width="723" height="800" alt="ảnh" src="https://github.com/user-attachments/assets/d4ed8673-2d7b-4972-9806-fae6c906c4c2" />

kết quả:

<img width="1919" height="855" alt="ảnh" src="https://github.com/user-attachments/assets/102482f9-66fd-49ca-952a-baa1f6ada379" />

<img width="1919" height="853" alt="ảnh" src="https://github.com/user-attachments/assets/79193008-9fc9-4c28-87e3-05ec0ce9a061" />

<img width="1919" height="854" alt="ảnh" src="https://github.com/user-attachments/assets/387047d6-7abc-4513-9531-6da1670be30b" />

<img width="1919" height="856" alt="ảnh" src="https://github.com/user-attachments/assets/86af47cd-0f38-44a7-822d-5de38c49dc34" />

DLL đã được unpack thành công

tuy nhiên chương trình đã bị obfuscate



