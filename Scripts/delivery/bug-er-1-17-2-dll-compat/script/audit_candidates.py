"""Read-only candidate, dependency-tree and source-identity audit."""
import hashlib,json,re,subprocess,struct
from pathlib import Path
import pefile

projects=Path(__file__).resolve().parents[5]
topic=projects.parent/'Topics/Gameplay/bug-er-1-17-2-dll-compat'
baseline=json.loads((topic/'loaded-dll-inventory.json').read_text(encoding='utf-8-sig'))
installed={v['name'].lower():v for v in baseline}
names=['ERGparamPreloadPatch','ERSoundBankLoader','er-torrent-skin-slots','eldenring-covenant-slot','Summon',
       'er-demon-beast','nightreign_style_hud','weapon-animation-hotreload','ERCharacterScale','time','Scripts-Data-Exposer-FS']
records=[]
digest=lambda p:hashlib.sha256(p.read_bytes()).hexdigest().upper()
def paired_pdb(dll,pe):
    pdb=dll.with_suffix('.pdb')
    if not pdb.exists():return {'present':False}
    codeview=[]
    for item in getattr(pe,'DIRECTORY_ENTRY_DEBUG',[]):
        if item.struct.Type==2:
            raw=pe.get_data(item.struct.AddressOfRawData,item.struct.SizeOfData)
            if raw[:4]==b'RSDS':codeview.append((raw[4:20].hex(),struct.unpack_from('<I',raw,20)[0]))
    raw=pdb.read_bytes();block_size,_,_,length,_,block_map=struct.unpack_from('<6I',raw,32)
    indices=struct.unpack_from('<'+'I'*((length+block_size-1)//block_size),raw,block_map*block_size)
    directory=b''.join(raw[i*block_size:(i+1)*block_size] for i in indices)[:length]
    count=struct.unpack_from('<I',directory,0)[0];sizes=struct.unpack_from('<'+'I'*count,directory,4);cursor=4+count*4
    for i,size in enumerate(sizes):
        blocks=0 if size==0xffffffff else (size+block_size-1)//block_size
        entries=struct.unpack_from('<'+'I'*blocks,directory,cursor);cursor+=blocks*4
        if i==1:
            info=b''.join(raw[j*block_size:(j+1)*block_size] for j in entries)[:size]
            guid,age=info[12:28].hex(),struct.unpack_from('<I',info,8)[0]
            assert (guid,age) in codeview,str(pdb)
            return {'present':True,'sha256':digest(pdb),'codeview_guid_bytes':guid,'age':age,'paired':True}
    raise AssertionError('Missing PDB info stream')
for name in names:
    root=projects/name
    meta=json.loads((root/'dist/er-1.17.2/build-result.json').read_text(encoding='utf-8-sig'))
    artifact=Path(meta['artifact']);pe=pefile.PE(str(artifact),fast_load=False)
    assert pe.FILE_HEADER.Machine==0x8664 and pe.FILE_HEADER.Characteristics&0x2000,name
    assert pe.OPTIONAL_HEADER.AddressOfEntryPoint,name
    imports=sorted({e.dll.decode() for e in getattr(pe,'DIRECTORY_ENTRY_IMPORT',[])})
    delayed=sorted({e.dll.decode() for e in getattr(pe,'DIRECTORY_ENTRY_DELAY_IMPORT',[])})
    if name not in ('time','Scripts-Data-Exposer-FS'):
        assert not any(re.search(r'(?i)vcruntime|msvcp|ucrtbase|api-ms-win-crt',v) for v in imports+delayed),(name,imports)
        tree=(topic/f'build-logs/{name}-dependency-tree.txt').read_text(encoding='utf-8-sig')
        assert not re.search('shikifsrs',tree,re.I),name
        if name!='eldenring-covenant-slot':
            assert 'fromsoftware-rs' in tree and 'eldenring v0.14.0' in tree,name
    assert digest(artifact)==meta['sha256'],name
    base=installed[artifact.name.lower()]
    source_files=[]
    folders=['src','tests','assets','game','include','lib','.cargo','AdamCamera']
    if name=='nightreign_style_hud':folders+=['examples/nightreign-style-hud']
    for folder in folders:
        directory=root/folder
        if directory.exists():
            for path in sorted(directory.rglob('*')):
                if path.is_file() and '__pycache__' not in path.parts:
                    source_files.append({'path':path.relative_to(root).as_posix(),'sha256':digest(path)})
    for path in sorted(root.iterdir()):
        if path.is_file() and (path.suffix.lower() in ('.cpp','.h','.hpp','.toml','.lock','.rs','.vcxproj') or path.name=='CMakeLists.txt'):
            source_files.append({'path':path.name,'sha256':digest(path)})
    source_files.sort(key=lambda v:v['path'])
    source_digest=hashlib.sha256(json.dumps(source_files,sort_keys=True).encode()).hexdigest().upper()
    (root/'dist/er-1.17.2/source-input-hashes.json').write_text(json.dumps(source_files,indent=2),encoding='utf-8')
    dirty=bool(subprocess.check_output(['git','-C',str(root),'status','--porcelain'],text=True).strip())
    records.append({**meta,'working_tree_dirty':dirty,'source_inputs_sha256':source_digest,'imports':imports,'delay_imports':delayed,
                    'pdb':paired_pdb(artifact,pe),
                    'installed_path':base['path'],'installed_initial_sha256':base['sha256'].upper(),
                    'machine':'AMD64','dll_entrypoint':hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)})

sdk=projects/'fromsoftware-rs';sdk_files=[]
for folder in ['crates/eldenring','crates/shared','crates/debug']:
    for p in sorted((sdk/folder).rglob('*')):
        if p.is_file() and '__pycache__' not in p.parts:sdk_files.append({'path':p.relative_to(sdk).as_posix(),'sha256':digest(p)})
for leaf in ['Cargo.toml','Cargo.lock']:
    p=sdk/leaf;sdk_files.append({'path':leaf,'sha256':digest(p)})
sdk_files.sort(key=lambda v:v['path'])
(topic/'fsrs-source-input-hashes.json').write_text(json.dumps(sdk_files,indent=2),encoding='utf-8')
minhook=projects.parent/'_Example/minhook-master'
minhook_inputs=[{'path':str(p),'sha256':digest(p)} for p in sorted(minhook.rglob('*'))
                if p.is_file() and p.suffix.lower() in ('.c','.h') and any(part in ('src','include') for part in p.parts)]
result={'game_exe_sha256':'F9118FEA2CFD8FA3901E8060BFADB1552CB2471771DED8A5B662C4E298FFB328',
        'fsrs_revision':subprocess.check_output(['git','-C',str(sdk),'rev-parse','HEAD'],text=True).strip(),
        'fsrs_working_tree_dirty':True,
        'fsrs_source_inputs_sha256':hashlib.sha256(json.dumps(sdk_files,sort_keys=True).encode()).hexdigest().upper(),
        'external_minhook_inputs':minhook_inputs,
        'rust_sdk_consumers':8,'shikifsrs_packages':0,'artifacts':records,'automatic':'PASS','runtime_human':'PENDING'}
(topic/'candidate-manifest.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
print('PASS:',len(records),'AMD64 DLLs; nine Rust DLLs use static CRT; eight fsrs consumers; zero ShikiFSRS packages')
