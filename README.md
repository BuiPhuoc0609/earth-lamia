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

obfuscate1:

<img width="926" height="482" alt="ảnh" src="https://github.com/user-attachments/assets/a923f8c2-78f2-41cc-8125-dd757f3a449e" />

<img width="903" height="462" alt="ảnh" src="https://github.com/user-attachments/assets/2e37a702-ba7a-444e-9090-6218bc36e9fb" />

<img width="579" height="335" alt="ảnh" src="https://github.com/user-attachments/assets/23c8ba51-4fee-4423-9d11-6c196be8e938" />

ta thấy rằng chương trình sử dụng instruction `sub` để lấy flag nhằm thay đổi giá trị đầu ra của `jmp rax` để điều luồng chương trình 

tuy thanh ghi có thể nhận các giá trị khác nhau nhưng kết quả của `sub` chỉ có một vài trường hợp cụ thể

Ý tưởng:
- tìm các lệnh `jmp rax`
- lùi ngược lên cho đến khi gặp `sub reg_64, reg_64` hoặc `sub reg64, imm`
- emulate và thử các trường hợp của `sub` (ví dụ > < =, âm,...) để lấy các giá trị đầu ra của `jmp rax`
- căn cứ vào kết quả của các trường hợp ta nop hết các ins cũ và patch thành conditional jmp

sau khi patch:

<img width="1288" height="504" alt="ảnh" src="https://github.com/user-attachments/assets/9f170aa8-148a-40d8-b77b-4e54cc78fde5" />

<img width="1148" height="511" alt="ảnh" src="https://github.com/user-attachments/assets/a8ae5b1c-75f9-4997-a4a7-dc4640898f0c" />


obfuscate2:

ở đây ta thấy dạng này khá quen:

<img width="1919" height="859" alt="ảnh" src="https://github.com/user-attachments/assets/dc437bed-bb15-4ff7-a5ba-6ce5299e7b40" />

<img width="1919" height="850" alt="ảnh" src="https://github.com/user-attachments/assets/093113b4-e047-4f17-8e6e-11a449597f80" />

bên trái là chương trình ta vừa deobfuscate và bên phải là chương trình tự compile bằng ollvm

dựa vào cách điều hướng luồng ta có thể thấy ta đã đưa được về dạng ollvm thông thường

có thể dựa trên các script unflatening sẵn trên mạng để deob dạng này

cơ chế là sắp xếp lại thứ tự thực thi của các block trong hàm

kết quả:

<img width="1522" height="490" alt="ảnh" src="https://github.com/user-attachments/assets/6d2b72c7-a7ce-4b23-b9c4-ea43f0525485" />

obfuscate3:

<img width="661" height="235" alt="ảnh" src="https://github.com/user-attachments/assets/7d287fa8-ac7a-4e57-86ac-f514c8053dce" />

<img width="1100" height="246" alt="ảnh" src="https://github.com/user-attachments/assets/84fae7c3-566b-4f4d-88a2-0e8f6cae9ce1" />

<img width="606" height="487" alt="ảnh" src="https://github.com/user-attachments/assets/6dc257b6-fe1e-480a-8a91-223dfcc4e1a9" />

<img width="1515" height="477" alt="ảnh" src="https://github.com/user-attachments/assets/691c46cb-c252-4384-a576-258f6b9b44bc" />

ta thấy rằng các ins như `mov reg_64, ptr [imm]`, `add reg_64, ptr [imm]`,... gây ida tạo mã giả không tự optimize và tính toán được địa chỉ đích do các biến global nằm ở section có quyền write -> tức ida cho rằng giá trị ở biến đó có thể bị thay đổi chứ không cố định nên không gom vào tính được

Ý tưởng:
- tạo 1 section mới không có quyền write
- tìm tất cả các ins `mov reg_64, ptr [imm]`, `add reg_64, ptr [imm]`,...
- xref các biến global đó xem có ins nào khác ngoài `mov reg_64, ptr [imm]`, `add reg_64, ptr [imm]`,... tác động tới nó không (tránh các ins write vào biến), nếu có thì bỏ qua
- lấy giá trị tại biến đó và ghi vào section mới, đổi ins thành biến mới

kết quả:

<img width="1497" height="492" alt="ảnh" src="https://github.com/user-attachments/assets/bfdaebe1-a785-4387-84a7-d356360eb91d" />

<img width="1254" height="491" alt="ảnh" src="https://github.com/user-attachments/assets/ca478878-773a-48c6-a11b-c3c9aaca7f3b" />

obfuscate4:

<img width="1531" height="474" alt="ảnh" src="https://github.com/user-attachments/assets/7e7893fa-d9ae-42c1-b3b7-68c0b5a2f3a4" />

<img width="1534" height="502" alt="ảnh" src="https://github.com/user-attachments/assets/6ca53de6-931f-44bd-84c7-3f6ad01a5cb8" />

ta đã biết rằng các biến unk trên xuất hiện sau khi ida đã tính toán giá trị nên nó không được sử dụng trực tiếp trên ins nên ta không thể dùng cách vừa rồi được

Ý tưởng:
- parse pseudocode tìm các dạng `unk_x + imm`, `unk_x - imm`
- kiểm tra xem `unk_x` là biến đã khởi tạo và có giá trị chưa (tránh các biến chỉ có trên mem)
- hook text pseudo code patch lại thành giá trị sau khi tính toán

kết quả:

<img width="1532" height="504" alt="ảnh" src="https://github.com/user-attachments/assets/35f95f68-e888-4170-a538-1d9cb839e900" />

<img width="1527" height="508" alt="ảnh" src="https://github.com/user-attachments/assets/f69351f4-a274-4f3d-a8f7-34e079b86608" />

như vậy cơ bản chương trình đã deob được khá ổn và có thể đọc được

Phân tích hành vi chương trình:

ngoài DLLEntrypoint được gọi lúc load thư viện là malicious ra thì các exports khác hầu hết là forward  về userenv.dll gốc trong system32:

<img width="1532" height="505" alt="ảnh" src="https://github.com/user-attachments/assets/ab638526-9ff3-4647-9f53-192d666d5b44" />

<img width="1520" height="448" alt="ảnh" src="https://github.com/user-attachments/assets/38be7772-159d-4ce6-a620-7550d7c94e01" />


DllEntrypoint:

<img width="1342" height="436" alt="ảnh" src="https://github.com/user-attachments/assets/a19b2aa7-33f8-4a2b-8754-2556ac42703d" />

DLLMain:

<img width="1022" height="493" alt="ảnh" src="https://github.com/user-attachments/assets/3bfa238d-bec7-48c2-b5dd-bed93533c5b2" />

<img width="1341" height="442" alt="ảnh" src="https://github.com/user-attachments/assets/ed9f8e70-5f27-4a70-afee-7e8e05155709" />

hàm `install_veh` đăng ký 1 hàm handler với `AddVectoredExceptionHandler` rồi sau đó đặt Protection Constants `PAGE_EXECUTE_READ | PAGE_GUARD` cho entrypoint của `spoolsv.exe`

sau khi các dll được load, `spoolsv.exe` vào entrypoint và bị dính exception page guard -> fallback về hàm đã đăng ký VEH

<img width="1076" height="207" alt="ảnh" src="https://github.com/user-attachments/assets/9366e4e6-590e-4da6-9726-1f11a791ed9c" />

<img width="1345" height="412" alt="ảnh" src="https://github.com/user-attachments/assets/2ae88d64-6a63-4fa3-8a53-06b44621b7f9" />

hàm này xác định nếu là exception page guard thì sẽ trả lại protect cũ và đặt context rip vào hàm `loader` để tiếp tục thực thi

loader:

```c
void loader()
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  v13 = -2LL;
  v11[0] = 0LL;
  v11[1] = v12;
  v11[2] = 0x104LL;
  decode_str_kernel32_dll(
    kernel32_dll,                               // "kernel32.dll"
    0x7FFFECD283B2LL);
  decode_str_getmodulefilenamea(
    (CHAR *)GetModuleFileNameA,                 // "GetModuleFileNameA"
    0x7FFFECD284AELL);
  v10 = threadpool_work(
          kernel32_dll,                         // "kernel32.dll"
          (const CHAR *)GetModuleFileNameA,     // "GetModuleFileNameA"
          (__int64)v11,
          3u,
          0);
  sub_7FFFECD02DB0((__int64)v9, (__int64)v12);
  decode_str_backslash((__int64)&unk_7FFFECD326F0, 0x7FFFECD284E6LL);
  v0 = ((__int64 (__fastcall *)(_BYTE *, void *, __int64))sub_7FFFECD14030)(v9, &unk_7FFFECD326F0, -1LL);
  build_string_slice((__int64)v9, (__int64)v8, 0LL, v0);
  decode_str_vcruntime141_path_suffix(
    aVcruntime141Dl,                            // "\\vcruntime141.dll"
    0x7FFFECD2851DLL);
  append_string_to_buffer(path_string, (__int64)v8, 0x7FFFECD326F8LL);
  restore_all_loaded_module_text_sections();
  initialize_hashed_api_resolvers();
  dword_7FFFECD32020 = 0;
  v6 = 0LL;
  v5 = xmmword_7FFFECD28300;
  decode_str_kernel32_dll(
    kernel32_dll,                               // "kernel32.dll"
    0x7FFFECD283B2LL);
  decode_str_heapcreate(
    (CHAR *)HeapCreate,                         // "HeapCreate"
    0x7FFFECD28558LL);
  payload_private_heap = (void *)threadpool_work(
                                   kernel32_dll,// "kernel32.dll"
                                   (const CHAR *)HeapCreate,// "HeapCreate"
                                   (__int64)&v5,
                                   3u,
                                   0);
  ::payload_private_heap = payload_private_heap;
  sub_7FFFECD03090(vector_object, 0x84A44F320A974C2LL);
  load_and_decrypt_payload_file(output_vector, path_string);
  sub_7FFFECD143B0(vector_object, output_vector);
  sub_7FFFECD031D0(output_vector);
  v1[0] = 0LL;
  v1[1] = sub_7FFFECD14510(vector_object);
  v1[2] = 0x3000LL;
  v1[3] = 64LL;
  decode_str_kernel32_dll(
    kernel32_dll,                               // "kernel32.dll"
    0x7FFFECD283B2LL);
  decode_str_virtualalloc(
    (CHAR *)VirtualAlloc_0,                     // "VirtualAlloc"
    0x7FFFECD283F1LL);
  decrypted_payload_rwx = (void *)threadpool_work(
                                    kernel32_dll,// "kernel32.dll"
                                    (const CHAR *)VirtualAlloc_0,// "VirtualAlloc"
                                    (__int64)v1,
                                    4u,
                                    0);
  __asm { jmp     rax }
}
```

hàm này resolve các api cần thiết, lấy path và decrypt `vcruntime141.dll`, ngoài ra còn có hàm `restore_all_loaded_module_text_sections` tự map và ghi đè lại các modules để gỡ hook 


```c
void __fastcall __noreturn loader_0()
{
  __int64 v0; // rbp
  size_t byte_vector_size; // rax
  HANDLE CurrentThread; // rax

  *(v0 - 80) = lpAddress_1;
  *(v0 - 72) = get_byte_vector_data((v0 + 128));
  byte_vector_size = sub_7FFFECD14510((v0 + 128));
  memcpy(*(v0 - 80), *(v0 - 72), byte_vector_size);
  DetourTransactionBegin();
  CurrentThread = GetCurrentThread();
  DetourUpdateThread(CurrentThread);
  DetourAttach(&pCreateProcessA, pDetour);
  DetourTransactionCommit();
}
```

phần này là phần tiếp tục của hàm `loader`, có chức năng copy phần code đã decrypt vào phần mem r-w-x, cài Detours hook lên CreateProcessA để mọi lần tạo process sau đó bị ép policy block non-Microsoft binaries và cuối cùng là execute shellcode dã decrypt

<img width="1317" height="455" alt="ảnh" src="https://github.com/user-attachments/assets/edbc699a-b06b-40e7-abe4-9c86c17bb3c7" />

shellcode:

```c
__int64 shellcode()
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS NUMPAD "+" TO EXPAND]

  v83 = 0LL;
  VirtualAlloc = 0LL;
  v122 = 0LL;
  v82 = 0LL;
  v117 = NtCurrentPeb();
  Ldr = v117->Ldr;
  Flink = Ldr->InMemoryOrderModuleList.Flink;
  v123 = Flink[5].Flink;
  Flink_1 = Flink->Flink;
  v124 = Flink_1[5].Flink;
  Flink_2 = Flink_1->Flink;
  v125 = Flink_2[5].Flink;
  v52 = Flink_2[2].Flink;
  v119 = v52;
  v100 = v52 + SHIDWORD(v52[3].Blink);
  v77 = v100 + 136;
  v60 = (v52 + *(v100 + 136));
  v104 = v60[3];
  m_1 = v60[5];
  n_1 = v60[6];
  v78 = v52 + v60[7];
  v102 = v52 + v60[8];
  v101 = v52 + v60[9];
  n87 = 87;
  n117 = 117;
  v30 = -124;
  n96 = 96;
  v32 = -126;
  n127 = 127;
  n115 = 115;
  n81 = 81;
  n116 = 116;
  n116_1 = 116;
  v38 = -126;
  n117_1 = 117;
  v40 = -125;
  v41 = -125;
  v42 = 0;
  for ( i = 0; i < 0xE; ++i )
    *(&n87 + i) -= 16;                          // GetProcAddress
  n92 = 92;
  n127_1 = 127;
  n113 = 113;
  n116_2 = 116;
  n92_1 = 92;
  n121 = 121;
  n114 = 114;
  v12 = -126;
  n113_1 = 113;
  v14 = -126;
  v15 = -119;
  n81_1 = 81;
  v17 = 0;
  for ( j = 0; j < 0xC; ++j )
    *(&n92 + j) -= 16;                          // LoadLibraryA
  n102 = 102;
  n121_1 = 121;
  v20 = -126;
  v21 = -124;
  v22 = -123;
  qmemcpy(q_Q__, "q|Q||", sizeof(q_Q__));
  n127_2 = 127;
  n115_1 = 115;
  v26 = 0;
  for ( k = 0; k < 0xC; ++k )
    *(&n102 + k) -= 16;                         // VirtualAlloc
  for ( m = 1; m <= m_1; ++m )
  {
    for ( n = 0; n < n_1; ++n )
    {
      if ( *(v101 + 2LL * n) == m )
      {
        v90 = *(v102 + 4LL * n);
        v3 = v52 + v90;
        if ( *v3 == n87
          && v3[1] == n117
          && v3[2] == v30
          && v3[3] == n96
          && v3[4] == v32
          && v3[5] == n127
          && v3[6] == n115
          && v3[7] == n81
          && v3[8] == n116
          && v3[9] == n116_1
          && v3[10] == v38
          && v3[11] == n117_1
          && v3[12] == v40
          && v3[13] == v41 )
        {
          v69 = *(v78 + 4LL * m);
          v83 = (v52 + v69);
        }
        if ( *v3 == n92
          && v3[1] == n127_1
          && v3[2] == n113
          && v3[3] == n116_2
          && v3[4] == n92_1
          && v3[5] == n121
          && v3[6] == n114
          && v3[7] == v12
          && v3[8] == n113_1
          && v3[9] == v14
          && v3[10] == v15
          && v3[11] == n81_1
          && v3[12] == v17 )
        {
          v70 = *(v78 + 4LL * m);
          v82 = (v52 + v70);
        }
        if ( *v3 == n102
          && v3[1] == n121_1
          && v3[2] == v20
          && v3[3] == v21
          && v3[4] == v22
          && v3[5] == q_Q__[0]
          && v3[6] == q_Q__[1]
          && v3[7] == q_Q__[2]
          && v3[8] == q_Q__[3]
          && v3[9] == q_Q__[4]
          && v3[10] == n127_2
          && v3[11] == n115_1
          && v3[12] == v26 )
        {
          v71 = *(v78 + 4LL * m);
          VirtualAlloc = (v52 + v71);
        }
      }
    }
  }
  v54[0] = -24;
  v54[1] = 0;
  v54[2] = 0;
  v54[3] = 0;
  v54[4] = 0;
  v54[5] = 88;
  v54[6] = 88;
  v54[7] = 80;
  v54[8] = -61;
  n4096 = 4096;
  n0x2000 = 0x2000;
  flProtect = 64;
  v91 = (VirtualAlloc)(0LL, 9LL, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  for ( ii = 0; ii < 9; ++ii )
    *(v91 + ii) = v54[ii];
  v56 = v91();
  v64 = 0LL;
  for ( jj = 0; jj < &unk_9C4000; ++jj )
  {
    if ( *(v56 + jj) == 0x4D
      && *(v56 + jj + 1) == 90
      && *(v56 + jj + 2) == 144
      && !*(v56 + jj + 3)
      && *(v56 + jj + 4) == 3
      && !*(v56 + jj + 5) )
    {
      v64 = jj + v56;
      break;
    }
  }
  lpAddress = 0LL;
  v92 = v64;
  v75 = *(v64 + 60);
  v53 = v75 + v64;
  lpAddress = *(v53 + 48);
  v27 = 0LL;
  v27 = (VirtualAlloc)(lpAddress, *(v53 + 80), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
  v61 = 0;
  if ( !v27 )
  {
    v27 = (VirtualAlloc)(0LL, *(v53 + 80), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    v61 = 1;
  }
  *(v53 + 48) = v27;
  for ( kk = 0; kk < *(v53 + 84); ++kk )
    *(v27 + kk) = *(v64 + kk);
  v79 = v53 + 264;
  for ( mm = 0; mm < *(v53 + 6); ++mm )
  {
    for ( nn = 0; nn < *(v79 + 40LL * mm + 16); ++nn )
      *(*(v79 + 40LL * mm + 12) + v27 + nn) = *(*(v79 + 40LL * mm + 20) + v64 + nn);
  }
  v103 = v27;
  v76 = *(v92 + 60);
  v115 = v76 + v27;
  v94 = v115;
  v80 = v115 + 144;
  i1_1 = *(v115 + 148);
  v106 = *(v115 + 144);
  v57 = 0LL;
  for ( i1 = 0LL; i1 < i1_1; i1 += 20LL )
  {
    v57 = (v27 + i1 + v106);
    if ( !*v57 && !v57[4] )
      break;
    v93 = v57[3] + v27;
    v107 = v57[4];
    v81 = *v57;
    if ( !v81 )
      v81 = v57[4];
    v84 = 0LL;
    for ( i2 = 0LL; ; i2 += 8LL )
    {
      v68 = (v107 + v84 + v27);
      v65 = (v81 + i2 + v27);
      if ( (*v65 & 0x80000000LL) != 0 || *v65 < 0 )
      {
        v108 = *v65;
        v0 = v82(v93);
        v109 = (v83)(v0, v108);
        *v68 = v109;
      }
      if ( !*v68 )
        break;
      if ( *v68 == *v65 )
      {
        v110 = *v65 + v27;
        v111 = v110 + 2;
        v1 = v82(v93);
        v112 = (v83)(v1, v111);
        *v68 = v112;
      }
      v84 += 8LL;
    }
  }
  if ( v61 )
  {
    v113 = lpAddress;
    v114 = v27;
    v116 = v27 - lpAddress;
    v95 = v94 + 176;
    v121 = *(v94 + 180);
    v120 = *(v94 + 176);
    v58 = (v120 + v27);
    i3_1 = *(v120 + v27 + 4) - 8;
    v59 = (v120 + v27 + 8);
    v87 = v59;
    v62 = 0;
    while ( 1 )
    {
      ++v62;
      for ( i3 = 0; i3 < i3_1; i3 += 2 )
      {
        v87 = v59;
        v96 = ((*v59 & 0xFFFu) + *v58 + v27);
        *v96 += v116;
        ++v59;
      }
      v58 = v59;
      if ( !*v59 )
        break;
      v59 = v58 + 2;
      i3_1 = v58[1] - 8;
      v87 = v58 + 2;
    }
  }
  return ((*(v53 + 40) + v27))();
}
```

shellcode là một refective loader có chức năng tìm và map file pe lên mem và thực thi lại entrypoint

oep:

<img width="1328" height="451" alt="ảnh" src="https://github.com/user-attachments/assets/62e58b27-c589-40ff-9702-20c22d40486c" />

dump ra file a.out.exe

<img width="1034" height="530" alt="ảnh" src="https://github.com/user-attachments/assets/6b6eb4da-f4be-491c-a9d6-cf90094f64f0" />

<img width="771" height="505" alt="ảnh" src="https://github.com/user-attachments/assets/10737170-c6b8-4232-8b72-71550fe2ea06" />

đây là 1 file pe được build bằng golang nhưng đã bị stripped hết symbols và phiên bản

ta sẽ dùng tính năng load flirt signature file để lấy một phần symbol các hàm của go từ 1 file pe golang ta tự build

sau khi load sig:

<img width="1919" height="833" alt="ảnh" src="https://github.com/user-attachments/assets/47c0c6a8-3941-4f80-9f98-a850bb678b21" />

từ đây ta tìm đc main của chương trình:

<img width="1529" height="521" alt="ảnh" src="https://github.com/user-attachments/assets/25fbd924-840e-445e-b7ab-0ce7e0076a31" />

<img width="759" height="491" alt="ảnh" src="https://github.com/user-attachments/assets/20b7cb67-d786-4a34-be2b-4b7457c88ed3" />

phân tích:

<img width="772" height="296" alt="ảnh" src="https://github.com/user-attachments/assets/45c5d8d5-8832-48bd-b164-a668ccb4003b" />

tại hàm `call_c_function` có hàm `runtime_cgocall` để gọi hàm C trong Go:

<img width="1340" height="347" alt="ảnh" src="https://github.com/user-attachments/assets/90bb7fb3-9bcd-4cd7-8cb6-8ac20359387f" />

args của hàm trỏ đến 1 reflective loader và 1 pe file:

rax:

<img width="1336" height="422" alt="ảnh" src="https://github.com/user-attachments/assets/071ca3d5-b746-4511-b93e-f779944f1f28" />

rbx:

<img width="1213" height="372" alt="ảnh" src="https://github.com/user-attachments/assets/77b1251d-8313-4d5e-912d-0d22f9b4fe01" />

ta dump file pe ra bằng ollydumpex với option raw vì đây là file pe chưa map

<img width="825" height="767" alt="ảnh" src="https://github.com/user-attachments/assets/b46a42a8-e0b5-4a7e-a1ef-2eb7a14da177" />

dll ta cũng lấy lại symbols go bằng cách load sig như trên

<img width="1917" height="817" alt="ảnh" src="https://github.com/user-attachments/assets/88996409-ea76-4ca2-a254-5b0e643bb7b3" />


thực tế DLLEntrypoint không có gì cả

ta quay trở lại a.out.exe:

<img width="1139" height="392" alt="ảnh" src="https://github.com/user-attachments/assets/0ee11d4c-e6a9-4ca5-88e9-acff80d9c2e6" />

sau khi gọi xong `call_c_function` tức đã load pe và gọi DLLEntrypoint, ta break on access tại code section của dll đã load lên mem:

<img width="1400" height="616" alt="ảnh" src="https://github.com/user-attachments/assets/3527c7bd-adfa-4c48-b847-bec76e0c3068" />

resume:

<img width="1331" height="461" alt="ảnh" src="https://github.com/user-attachments/assets/96ee7d55-ba7c-4a01-b564-4ee6dcc3152b" />

<img width="1919" height="817" alt="ảnh" src="https://github.com/user-attachments/assets/ea895850-9fd9-49ec-8f5a-68a9be810560" />

đây chính là hàm `_rt0_amd64_windows_lib_go` trong dll

<img width="945" height="476" alt="ảnh" src="https://github.com/user-attachments/assets/83cd3235-8706-404c-a986-9b541824a5fa" />

logic chính của chương trình nằm trong `runtime_mstart`

<img width="928" height="503" alt="ảnh" src="https://github.com/user-attachments/assets/5265508d-487e-423e-a772-fb4291badd05" />

ta sẽ debug và trỏ vào `v7` để xem chương trình gọi các hàm nào

chương trình gọi các hàm tại các offset: `0x3dea0`, `0x37be0`, `0x379c0`, 







