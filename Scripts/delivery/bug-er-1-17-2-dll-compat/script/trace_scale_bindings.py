"""Trace paired reachable instructions, vtable slots, calls and jumps.

Protected EXE alignment bytes contain opaque/randomized data. Never compare or
disassemble across an unconditional jump/return as if that data were code.
This follows actual CFG edges instead. Non-address operands must stay exact.
"""
import json,struct
from collections import deque
from pathlib import Path
import capstone as cs
from map_private_rvas import Image,OLD,NEW,DECODER,neutral
old,new=Image(OLD),Image(NEW)
root=Path(r'D:\_Ugit\FSTool\_Mod\Topics\Gameplay\bug-er-1-17-2-dll-compat')
code=json.loads((root/'scale-code-mapping.json').read_text())['results']
code += json.loads((root/'scale-code-supplement.json').read_text())['results']
wanted={int(v['old'],16) for v in code}
types=json.loads((root/'scale-type-mapping.json').read_text())
bindings={int(v['old'],16):int(v['new'],16) for v in types if v.get('new')}
queue=deque()
origins={}
conflicts=[]

def in_code(image,a):return image.lo<=a<image.lo+len(image.code)

def seed(a,b,origin,follow=True):
    if not in_code(old,a) or not in_code(new,b):return
    if a in bindings and bindings[a]!=b:
        conflicts.append({'old':hex(a),'first':hex(bindings[a]),'other':hex(b),'origin':origin})
        return
    bindings[a]=b
    origins.setdefault(a,origin)
    if follow:queue.append((a,b))

for item in types:
    if not item.get('new') or not item.get('type'):continue
    a,b=int(item['old'],16),int(item['new'],16)
    for slot in range(8):
        x=struct.unpack('<Q',old.data(a+slot*8,8))[0]-old.base
        y=struct.unpack('<Q',new.data(b+slot*8,8))[0]-new.base
        if not in_code(old,x) or not in_code(new,y):break
        seed(x,y,f'RTTI {item["type"]} slot {slot}')

discarded=[]
for record in code:
    a=int(record['old'],16)
    if a>0x3b0000 and record.get('new'):
        b=int(record['new'],16)
        if a in bindings and bindings[a]!=b:
            discarded.append({'old':hex(a),'candidate':hex(b),'verified':hex(bindings[a]),'reason':'RTTI slot identity overrides anonymous function prefix'})
            continue
        seed(a,b,'unique native function/window')

visited={}
fixups={}
stops=[]
edges=[]
budget=300000
while queue and len(visited)<budget:
    a,b=queue.popleft()
    for _ in range(15000):
        if a in visited:
            if visited[a]!=b:conflicts.append({'old':hex(a),'first':hex(visited[a]),'other':hex(b)})
            break
        if not in_code(old,a) or not in_code(new,b):break
        x=next(DECODER.disasm(old.data(a,16),a,1),None)
        y=next(DECODER.disasm(new.data(b,16),b,1),None)
        if not x or not y:break
        if x.size!=y.size or neutral(x.bytes,a)[0]!=neutral(y.bytes,b)[0]:
            stops.append({'old':hex(a),'new':hex(b),'before':x.mnemonic+' '+x.op_str,'after':y.mnemonic+' '+y.op_str})
            break
        visited[a]=b
        bindings.setdefault(a,b)
        for i,(v,w) in enumerate(zip(x.bytes,y.bytes)):
            if v!=w:fixups[a+i]=(v,w)
        # Every RIP reference provides another independently inspected binding.
        if any(o.type==cs.x86.X86_OP_MEM and o.mem.base==cs.x86.X86_REG_RIP for o in x.operands):
            left=a+x.size+x.disp;right=b+y.size+y.disp
            if left in bindings and bindings[left]!=right:
                conflicts.append({'old':hex(left),'first':hex(bindings[left]),'other':hex(right),'origin':'RIP target'})
            else:bindings[left]=right
        immediate=x.operands and x.operands[0].type==cs.x86.X86_OP_IMM
        if (x.group(cs.CS_GRP_JUMP) or x.group(cs.CS_GRP_CALL)) and immediate:
            left,right=x.operands[0].imm,y.operands[0].imm
            if in_code(old,left) and in_code(new,right):
                edges.append({'from_old':hex(a),'from_new':hex(b),'old_target':hex(left),'new_target':hex(right),'kind':x.mnemonic})
                seed(left,right,'paired reachable '+x.mnemonic)
            if x.mnemonic=='jmp':break
        elif x.mnemonic=='jmp' or x.group(cs.CS_GRP_RET) or x.mnemonic in ('int3','ud2'):
            break
        a+=x.size;b+=y.size

assert len(visited)<budget,'CFG budget exhausted'
result={'instruction_count':len(visited),'discarded_prefix_candidates':discarded,'bindings':{hex(a):hex(b) for a,b in sorted(bindings.items())},
        'origins':{hex(a):v for a,v in origins.items()},'byte_fixups':[[hex(a),v,w] for a,(v,w) in sorted(fixups.items())],
        'conflicts':conflicts,'stopped_at_changed_instruction':stops,'edges':edges}
(root/'scale-reachable-binding-proof.json').write_text(json.dumps(result,indent=2))
missing=[r['old'] for r in code if int(r['old'],16)>0x3b0000 and 'new' not in r and int(r['old'],16) not in bindings]
print('instructions',len(visited),'bindings',len(bindings),'fixups',len(fixups),'conflicts',len(conflicts),'missing private windows',missing)
for v in conflicts[:10]:print(v)
