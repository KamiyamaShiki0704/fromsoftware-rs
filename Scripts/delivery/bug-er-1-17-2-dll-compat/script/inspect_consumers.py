"""Consumer-specific offline evidence; never executes game code."""
import json
import struct
import difflib
from pathlib import Path
from map_private_rvas import Image, OLD, NEW, neutral, find_masked, DECODER

old, new = Image(OLD), Image(NEW)
result = {'sound': [], 'torrent': {}, 'covenant': {}, 'time_changes': {}}
for name, a, b, size in [
    ('path_acquire',0xd90d60,0xd92450,0x208),('release_cap',0xd91090,0xd92780,0x56),
    ('ffxbnd_factory',0x1f1d10,0x1f1d10,0x123),('collector',0xd93230,0xd94920,0x298),
    ('csfile_release',0x26541e0,0x2655910,0x94),('reference_release',0x2654280,0x26559b0,0x76),
    ('increment_use',0x20f2b0,0x20f2b0,7),('decrement_use',0x20f320,0x20f320,0x1e)]:
    before, after = old.data(a,size), new.data(b,size)
    assert neutral(before,a)[0] == neutral(after,b)[0], name
    h=0xcbf29ce484222325
    for byte in after:
        h=((h ^ byte)*0x100000001b3)&0xffffffffffffffff
    result['sound'].append({'name':name,'old':hex(a),'new':hex(b),'size':size,'fnv64':hex(h),'non_address_bytes_equal':True})

for a, size in [(0x3e5ea0,25),(0xd42420,23),(0xd43120,40)]:
    code=old.data(a,size)
    canonical,mask,_=neutral(code,a)
    matches=[new.lo+h for h in find_masked(new.code,canonical,mask)]
    assert len(matches)==1,(hex(a),matches)
    b=matches[0]
    result['torrent'][hex(a)]=hex(b)
    if a==0xd42420:
        ins=next(i for i in DECODER.disasm(new.data(b,size),b) if i.mnemonic=='lea')
        table=ins.address+ins.size+ins.disp
        assert old.data(0x2bb5028,16)==new.data(table,16)
        result['torrent']['official_table']=hex(table)

# Hook signature contains a direct call: resolve its target rather than guessing a shift.
hook=0x8585c9
call=hook+14
assert new.data(call,1)==b'\xe8'
target=call+5+struct.unpack('<i',new.data(call+1,4))[0]
result['covenant']['hook_match']=hex(hook)
result['covenant']['hook_target']=hex(target)
result['covenant']['old_hook_prefix']=old.data(0x8505c0,64).hex()
result['covenant']['new_hook_prefix']=new.data(target,64).hex()
for a in (0x3b35008,0x3b35010):
    context=old.data(a-24,64)
    hits=[]; pos=0
    raw=new.pe.__data__
    while True:
        at=raw.find(context,pos)
        if at<0:break
        pos=at+1
        hits.append(hex(new.pe.get_rva_from_offset(at)+24))
    result['covenant'][hex(a)]=hits
for a in (0x3b39020,):
    result['covenant']['dispatch_old_context']=old.data(a-16,48).hex()
    result['covenant']['dispatch_new_same_section_context']=new.data(a+0x3000-16,48).hex()

for label,a,b in [('world_update',0x510ee0,0x511160),('flipper',0xe84830,0xe85f20),('torrent_local',0x50d640,0x50d8c0)]:
    size=old.functions[a]-a
    x,y=list(DECODER.disasm(old.data(a,size),a)),list(DECODER.disasm(new.data(b,size),b))
    changes=[]
    aa=[neutral(i.bytes,i.address)[0] for i in x]
    bb=[neutral(i.bytes,i.address)[0] for i in y]
    for tag,i,j,k,l in difflib.SequenceMatcher(None,aa,bb,autojunk=False).get_opcodes():
        if tag!='equal':
            changes.append({'kind':tag,'before':[hex(v.address)+': '+v.mnemonic+' '+v.op_str for v in x[i:j]],
                            'after':[hex(v.address)+': '+v.mnemonic+' '+v.op_str for v in y[k:l]]})
    result['time_changes'][label]=changes

out=Path(r'D:\_Ugit\FSTool\_Mod\Topics\Gameplay\bug-er-1-17-2-dll-compat\consumer-native-evidence.json')
out.write_text(json.dumps(result,indent=2),encoding='utf-8')
print(json.dumps(result,indent=2))
