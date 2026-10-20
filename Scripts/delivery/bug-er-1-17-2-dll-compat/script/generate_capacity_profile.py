"""Generate exact WW272 CapacityExpansion preimages from verified native windows."""
import re,json
from pathlib import Path
from map_private_rvas import Image,OLD,NEW,neutral,find_masked,DECODER

old,new=Image(OLD),Image(NEW)
root=Path(r'D:\_Ugit\FSTool\_Mod\_Project\weapon-animation-hotreload\src\capacity')
patch=(root/'patch.rs').read_text()
clip=(root/'clip_index.rs').read_text()
arrays={}
for source in (clip,patch):
    for m in re.finditer(r'const\s+(\w+):\s*&\[u8\]\s*=\s*&\[([^\]]*)\]',source,re.S):
        arrays[m[1]]=bytes(int(x.strip(),0) for x in m[2].split(',') if x.strip())
start=patch.index('const GUARDS:')
body=patch[start:patch.index('\n];',start)]
pattern=r'\(\s*(0x[0-9a-fA-F]+|WINDOW_RVA)\s*,\s*(clip_index::TEARDOWN|WINDOW|&\[[^\]]*\])\s*,?\s*\)'
guards=[]
mapping=json.loads(Path(r'D:\_Ugit\FSTool\_Mod\Topics\Gameplay\bug-er-1-17-2-dll-compat\lifecycle-hud-capacity-mapping.json').read_text())['results']
known={int(r['old'],16):int(r['new'],16) for r in mapping if r.get('full_equal')}
# Short shared leaf accessors cannot be identified by a unique byte signature.
# Their exact complete bodies are guards, never patch/call targets. The fixed
# executable identity and independent patch-site functions remain mandatory.
known.update({0x1462320:0x1463a10,0x1461a90:0x1463180,0x1f35530:0x1f36c20})
proof=[]
for match in re.finditer(pattern,body,re.S):
    a=0xe83e13 if match[1]=='WINDOW_RVA' else int(match[1],16)
    token=match[2]
    if token.startswith('&['): before=bytes(int(x.strip(),0) for x in token[2:-1].split(',') if x.strip())
    else: before=arrays[token.split('::')[-1]]
    assert old.data(a,len(before))==before,hex(a)
    b=known.get(a)
    if b is None:
        # Standalone leaves have no useful unwind boundary. Require a unique
        # 128-byte neighborhood match, masking only PC-relative operands.
        expected,mask,_=neutral(old.data(a,128),a)
        hits=[new.lo+h for h in find_masked(new.code,expected,mask)]
        if not hits:
            # MSVC changed unreachable alignment padding (INT3 -> NOP). Only
            # decoded single-byte INT3 instructions are masked, never operands.
            mask=bytearray(mask)
            for ins in DECODER.disasm(old.data(a,128),a):
                if ins.mnemonic=='int3':mask[ins.address-a]=0
            expected=bytes(v&m for v,m in zip(old.data(a,128),mask))
            hits=[new.lo+h for h in find_masked(new.code,expected,bytes(mask))]
        assert len(hits)==1,(hex(a),[hex(v) for v in hits])
        b=hits[0]
    after=new.data(b,len(before))
    assert neutral(before,a)[0]==neutral(after,b)[0],hex(a)
    guards.append((b,after))
    proof.append({'old':hex(a),'new':hex(b),'length':len(before),'non_address_bytes_equal':True})
assert len(guards)==18,len(guards)
fmt=lambda b:'&['+','.join(hex(v) for v in b)+']'
lines=['// Generated from exact known EXEs; see generate_capacity_profile.py.',
       'use super::{Profile,clip_index};',
       'const GUARDS: &[(usize,&[u8])] = &[']
lines += [f'    (0x{a:x},{fmt(b)}),' for a,b in guards]
lines += ['];','const EDITS: &[clip_index::Edit] = &[',
          '    clip_index::Edit { rva:0xe8550f, original:&[2], replacement:&[0x10] },']
for idx,(a,b,size) in enumerate([(0x14608e7,0x1461fd7,58),(0x15351c0,0x15368b0,29),(0x151524b,0x151693b,5),(0x1515274,0x1516964,10)]):
    # Production edit constant lengths, not guessed instruction sizes.
    name=['ACTIVATE','SELECT','NAME_DEFAULT','NAME_COMPARE'][idx]
    size=len(arrays[name])
    assert old.data(a,size)==new.data(b,size),(name,hex(b))
    lines.append(f'    clip_index::Edit {{ rva:0x{b:x}, ..clip_index::EDITS[{idx}] }},')
lines += ['];','pub(super) const PROFILE: Profile = Profile { timestamp:0x6aabf7e7, image_length:0x5dfd600, text_length:0x29a6400,',
          f'    world_rva:0x3d6d018, window_rva:0xe85503, window:{fmt(new.data(0xe85503,len(arrays["WINDOW"])))}, guards:GUARDS, edits:EDITS }};']
(root/'profile272.rs').write_text('\n'.join(lines)+'\n')
Path(r'D:\_Ugit\FSTool\_Mod\Topics\Gameplay\bug-er-1-17-2-dll-compat\capacity-guard-proof.json').write_text(json.dumps(proof,indent=2))
print('WW272 capacity profile: 18 instruction guards, 5 unchanged-behavior edits')
