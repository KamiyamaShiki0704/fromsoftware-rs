"""Map ERCharacterScale vtables by MSVC type identity, then verified RIP consumers."""
import json,struct
from pathlib import Path
from map_private_rvas import Image,OLD,NEW,map_data
old,new=Image(OLD),Image(NEW)
uses=json.loads(Path(r'D:\_Ugit\FSTool\_Mod\Topics\Gameplay\bug-er-1-17-2-dll-compat\scale-data-rva-uses.json').read_text())

def occurrences(raw, needle):
    pos=0
    while True:
        at=raw.find(needle,pos)
        if at<0:return
        yield at
        pos=at+1

def rtti(a):
    raw=old.data(a-8,8)
    if len(raw)!=8:return None
    col=struct.unpack('<Q',raw)[0]-old.base
    if not 0x29b2000<=col<0x3b15000:return None
    words=struct.unpack('<6I',old.data(col,24))
    if words[0]!=1 or words[5]!=col:return None
    name=old.data(words[3]+16,512).split(b'\0')[0]
    if not name.startswith(b'.?A'):return None
    candidates=[]
    for noff in occurrences(new.pe.__data__,name+b'\0'):
        td=new.pe.get_rva_from_offset(noff)-16
        for coff in occurrences(new.pe.__data__,struct.pack('<I',td)):
            try:
                crva=new.pe.get_rva_from_offset(coff)-12
                other=struct.unpack('<6I',new.data(crva,24))
                if other[:3]!=words[:3] or other[5]!=crva:continue
                for voff in occurrences(new.pe.__data__,struct.pack('<Q',new.base+crva)):
                    vrva=new.pe.get_rva_from_offset(voff)+8
                    if 0x29b4000<=vrva<0x3b18000:candidates.append(vrva)
            except Exception:continue
    return {'old':hex(a),'new':hex(candidates[0]) if len(candidates)==1 else None,'type':name.decode(),
            'col_offset':words[1],'candidates':[hex(v) for v in candidates],'method':'RTTI type + subobject offset + COL self identity'}

out=Path(r'D:\_Ugit\FSTool\_Mod\Topics\Gameplay\bug-er-1-17-2-dll-compat\scale-type-mapping.json')
results=json.loads(out.read_text()) if out.exists() else []
done={r['old'] for r in results}
for key,refs in uses.items():
    if all(ref.startswith('nr_probe.rs:') for ref in refs) or key=='0x3300000':continue
    a=int(key,16)
    if key in done:continue
    item=rtti(a)
    if not item or not item.get('new'):
        item=map_data(old,new,a)
        item['method']='RIP consumers'
    results.append(item)
    print(key,'->',item.get('new'),item['method'],flush=True)
    out.write_text(json.dumps(results,indent=2))
