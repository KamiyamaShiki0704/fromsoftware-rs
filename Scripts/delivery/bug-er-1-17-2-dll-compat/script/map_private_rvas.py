"""Offline, read-only function comparison. Mask only x64 PC-relative operands.

This emits candidates/evidence, never patches executables or source. A unique
prefix is not an ABI proof; full_equal records whether the entire function has
the same instructions and non-PC-relative operands. Object offsets stay exact.
"""
import argparse
import bisect
import json
import re
import struct
from functools import lru_cache
from pathlib import Path

import capstone as cs
import pefile
import numpy as np

OLD = Path(r"F:\GoldenAge\Transplantation\ToER\BB\KnowledgeBase\Topics\MapPort\sys-bb-map-to-er\experiments\technical-chain-20261012-001\nav\runtime\eldenring.exe")
NEW = Path(r"F:\SteamLibrary\steamapps\common\ELDEN RING\Game\eldenring.exe")


class Image:
    def __init__(self, path):
        self.pe = pefile.PE(str(path))
        self.base = self.pe.OPTIONAL_HEADER.ImageBase
        self.text = next(s for s in self.pe.sections if s.Name.startswith(b'.text'))
        self.lo = self.text.VirtualAddress
        self.code = self.text.get_data()[:self.text.Misc_VirtualSize]
        d = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        raw = self.pe.get_data(d.VirtualAddress, d.Size)
        self.functions = {a: b for a, b, _ in struct.iter_unpack('<III', raw[:len(raw)//12*12]) if a < b}
        self.starts = sorted(self.functions)

    def function(self, rva):
        idx = bisect.bisect_right(self.starts, rva)-1
        if idx >= 0 and rva < self.functions[self.starts[idx]]:
            return self.starts[idx], self.functions[self.starts[idx]]
        return None

    def data(self, rva, size):
        return self.pe.get_data(rva, size)


DECODER = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
DECODER.detail = True


def neutral(data, rva):
    result = bytearray(data)
    mask = bytearray(b'\xff' * len(data))
    end = 0
    for ins in DECODER.disasm(data, rva):
        off = ins.address-rva
        end = off+ins.size
        if any(o.type == cs.x86.X86_OP_MEM and o.mem.base == cs.x86.X86_REG_RIP for o in ins.operands):
            mask[off+ins.disp_offset:off+ins.disp_offset+ins.disp_size] = bytes(ins.disp_size)
        if (ins.group(cs.CS_GRP_CALL) or ins.group(cs.CS_GRP_JUMP)) and ins.imm_size:
            mask[off+ins.imm_offset:off+ins.imm_offset+ins.imm_size] = bytes(ins.imm_size)
    return bytes(a & b for a, b in zip(result, mask)), bytes(mask), end


def find_masked(haystack, expected, mask):
    chunks = [(m.start(), m.group()) for m in re.finditer(b'\xff+', mask)]
    offset, anchor = max(((i, expected[i:i+len(c)]) for i, c in chunks), key=lambda t: len(t[1]))
    cursor = 0
    matches = []
    while True:
        hit = haystack.find(anchor, cursor)
        if hit < 0:
            break
        cursor = hit+1
        start = hit-offset
        if start >= 0 and start+len(mask) <= len(haystack):
            candidate = haystack[start:start+len(mask)]
            if all((a & m) == b for a, b, m in zip(candidate, expected, mask)):
                matches.append(start)
    return matches


@lru_cache(maxsize=None)
def map_code(old, new, rva):
    bounds = old.function(rva)
    if not bounds:
        return map_window(old,new,rva)
    start, end = bounds
    raw = old.data(start, end-start)
    canonical, mask, decoded = neutral(raw, start)
    attempts = sorted(set([min(len(raw), n) for n in (256, 128, 64, 48)]), reverse=True)
    for length in attempts:
        hits = find_masked(new.code, canonical[:length], mask[:length])
        hits = [new.lo+h for h in hits if new.lo+h in new.functions]
        if len(hits) == 1:
            target = hits[0]
            target_raw = new.data(target, new.functions[target]-target)
            other, _, other_decoded = neutral(target_raw, target)
            equal = canonical == other and decoded == len(raw) and other_decoded == len(target_raw)
            return {'old': hex(rva), 'new': hex(target+rva-start), 'function_old': hex(start), 'function_new': hex(target),
                    'old_length': len(raw), 'new_length': len(target_raw), 'full_equal': equal, 'prefix': length}
    return map_window(old,new,rva)


def map_window(old,new,rva):
    for size in (1024,512,384,256,128,96,64,48):
        raw=old.data(rva,size)
        canonical,mask,_=neutral(raw,rva)
        hits=find_masked(new.code,canonical,mask)
        if len(hits)==1:
            return {'old':hex(rva),'new':hex(new.lo+hits[0]),'full_equal':False,'local_equal':True,'prefix':size}
    return {'old':hex(rva),'error':'no unique native window'}


def map_data(old, new, rva):
    """Resolve global/table through actual RIP-relative consumers, no section delta."""
    sites = []
    for residue in range(4):
        count = (len(old.code)-residue)//4
        values = np.frombuffer(old.code, dtype='<i4', count=count, offset=residue).astype(np.int64)
        positions = np.arange(count, dtype=np.int64)*4+residue
        hits = positions[values+positions+old.lo+4 == rva]
        for pos in hits:
            pos = int(pos)
            for back in range(1, 12):
                start = pos-back
                if start < 0:
                    continue
                ins = next(DECODER.disasm(old.code[start:pos+12], old.lo+start, 1), None)
                if ins is None or ins.address+ins.size != old.lo+pos+4 or ins.disp_offset != back:
                    continue
                if not any(o.type == cs.x86.X86_OP_MEM and o.mem.base == cs.x86.X86_REG_RIP for o in ins.operands):
                    continue
                mapped = map_code(old, new, ins.address)
                if 'new' not in mapped:
                    continue
                at = int(mapped['new'],16)
                after = next(DECODER.disasm(new.data(at, 16), at, 1), None)
                if after and after.mnemonic == ins.mnemonic and after.size == ins.size:
                    before_neutral = neutral(ins.bytes, ins.address)[0]
                    after_neutral = neutral(after.bytes, after.address)[0]
                    if before_neutral == after_neutral:
                        sites.append({'old_site':hex(ins.address),'new_site':hex(at),'target':hex(at+after.size+after.disp),
                                      'instruction':f'{ins.mnemonic} {ins.op_str}'})
                        if len(sites) >= 8:
                            targets = sorted({s['target'] for s in sites})
                            return {'old':hex(rva),'new':targets[0] if len(targets)==1 else None,'targets':targets,'references':sites}
    targets = sorted({s['target'] for s in sites})
    return {'old':hex(rva),'new':targets[0] if len(targets)==1 else None,'targets':targets,'references':sites}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rvas', nargs='*', default=[])
    parser.add_argument('--source', nargs='*', default=[])
    parser.add_argument('--data-rvas', nargs='*', default=[])
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    old, new = Image(OLD), Image(NEW)
    rvas = {int(x, 16) for x in args.rvas}
    for source in args.source:
        root = Path(source)
        files = root.rglob('*.rs') if root.is_dir() else [root]
        for path in files:
            for match in re.finditer(r'0x[0-9a-fA-F_]+', path.read_text(encoding='utf-8-sig')):
                value = int(match.group().replace('_', ''), 16)
                if old.lo <= value < old.lo+len(old.code):
                    rvas.add(value)
    results = [map_code(old, new, rva) for rva in sorted(rvas)]
    data = [map_data(old,new,int(s,16)) for s in args.data_rvas]
    Path(args.output).write_text(json.dumps({'new_entrypoint':hex(new.pe.OPTIONAL_HEADER.AddressOfEntryPoint),'results':results,'data':data}, indent=2), encoding='utf-8')
    print(f'{len(results)} code values; {sum(r.get("full_equal",False) for r in results)} complete functions equal')


if __name__ == '__main__':
    main()
