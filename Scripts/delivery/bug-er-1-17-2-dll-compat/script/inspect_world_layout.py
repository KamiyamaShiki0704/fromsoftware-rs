"""Trace specific WorldChrMan tail fields through matched native consumers."""
import struct,json,difflib
from pathlib import Path
from map_private_rvas import Image,OLD,NEW,DECODER,neutral,map_code
old,new=Image(OLD),Image(NEW)
fields=[0x1e508,0x1e538,0x1e5e0,0x1e610,0x1e648,0x1e688,0x1e6a8,0x1ece0,0x1f1b0,0x1f1d0,0x1f200,0x1f220]
functions=set()
for field in fields:
    pattern=struct.pack('<I',field);cursor=0
    while True:
        hit=old.code.find(pattern,cursor)
        if hit<0:break
        cursor=hit+1
        bounds=old.function(old.lo+hit)
        if bounds:functions.add(bounds[0])

def key(ins):
    data,mask,_=neutral(ins.bytes,ins.address)
    value=bytearray(data)
    if 0x1e500<=ins.disp<0x1f800 and ins.disp_size==4:
        value[ins.disp_offset:ins.disp_offset+4]=b'\xaa'*4
    return bytes(value)

results=[]
for start in sorted(functions):
    mapping=map_code(old,new,start)
    if 'new' not in mapping:continue
    at=int(mapping['new'],16)
    x=list(DECODER.disasm(old.data(start,old.functions[start]-start),start))
    y=list(DECODER.disasm(new.data(at,new.functions[at]-at),at))
    for tag,i,j,k,l in difflib.SequenceMatcher(None,[key(v) for v in x],[key(v) for v in y],autojunk=False).get_opcodes():
        if tag=='equal':
            for a,b in zip(x[i:j],y[k:l]):
                if a.disp in fields:
                    results.append({'field_old':hex(a.disp),'field_new':hex(b.disp),'old':hex(a.address),'new':hex(b.address),'before':a.mnemonic+' '+a.op_str,'after':b.mnemonic+' '+b.op_str})
out=Path(r'D:\_Ugit\FSTool\_Mod\Topics\Gameplay\bug-er-1-17-2-dll-compat\world-tail-field-evidence.json')
out.write_text(json.dumps(results,indent=2),encoding='utf-8')
for field in fields:
    matches=[r for r in results if int(r['field_old'],16)==field]
    print(hex(field),sorted({r['field_new'] for r in matches}),'consumers',len(matches))
