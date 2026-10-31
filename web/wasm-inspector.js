const decoder = new TextDecoder("utf-8", { fatal: false });
const SECTION_NAMES = ["custom","type","import","function","table","memory","global","export","start","element","code","data","data-count","tag"];
const VALUE_TYPES = new Map([[0x7f,"i32"],[0x7e,"i64"],[0x7d,"f32"],[0x7c,"f64"],[0x7b,"v128"],[0x70,"funcref"],[0x6f,"externref"]]);
function parser(bytes) {
  let p=0;
  const need=n=>{if(!Number.isSafeInteger(n)||n<0||p+n>bytes.length)throw new Error("Malformed WASM: section extends beyond file bounds.");};
  const u8=()=>{need(1);return bytes[p++];};
  const u32=()=>{let v=0,shift=0;for(let i=0;i<5;i++){const b=u8();v|=(b&127)<<shift;if(!(b&128))return v>>>0;shift+=7;}throw new Error("Malformed WASM: invalid 32-bit LEB128 integer.");};
  const name=()=>{const n=u32();need(n);const s=decoder.decode(bytes.subarray(p,p+n));p+=n;return s;};
  const skip=n=>{need(n);p+=n;};
  const limits=()=>{const flags=u32(),min=u32();let max=null;if(flags&1)max=u32();return {min,max,shared:!!(flags&2),memory64:!!(flags&4)};};
  return {get pos(){return p},set pos(v){p=v},u8,u32,name,skip,limits,need};
}
function hex(bytes){return [...bytes].map(x=>x.toString(16).padStart(2,"0")).join("");}
export async function inspectWasm(input) {
  const bytes=input instanceof Uint8Array?input:new Uint8Array(input);
  if(bytes.length<8)throw new Error("File is too short to be a WebAssembly module.");
  if(hex(bytes.subarray(0,4))!=="0061736d")throw new Error("Invalid WebAssembly magic header.");
  const version=[...bytes.subarray(4,8)];
  if(version[0]!==1||version[1]!==0||version[2]!==0||version[3]!==0)throw new Error("Unsupported WebAssembly binary version: "+version.join("."));
  const r=parser(bytes);r.pos=8;
  const sections=[],imports=[],exports=[],types=[],functionTypeIndices=[];
  while(r.pos<bytes.length){
    const start=r.pos,id=r.u8(),size=r.u32(),payloadStart=r.pos,end=payloadStart+size;
    if(end>bytes.length)throw new Error("Malformed WASM: section "+id+" exceeds the file boundary.");
    const sub=parser(bytes);sub.pos=payloadStart;
    let sectionName=SECTION_NAMES[id]||("section-"+id),customName=null,count=null;
    if(id===0){customName=sub.name();sectionName="custom";}
    else if(id===1){count=sub.u32();for(let i=0;i<count;i++){const form=sub.u8();if(form!==0x60)throw new Error("Unsupported WASM type form 0x"+form.toString(16));const params=Array.from({length:sub.u32()},()=>VALUE_TYPES.get(sub.u8())||"unknown");const results=Array.from({length:sub.u32()},()=>VALUE_TYPES.get(sub.u8())||"unknown");types.push({params,results});}}
    else if(id===2){count=sub.u32();for(let i=0;i<count;i++){const module=sub.name(),field=sub.name(),kind=sub.u8();let detail={};if(kind===0)detail.typeIndex=sub.u32();else if(kind===1){detail.elementType=VALUE_TYPES.get(sub.u8())||"unknown";detail.limits=sub.limits();}else if(kind===2)detail.limits=sub.limits();else if(kind===3)detail.global={type:VALUE_TYPES.get(sub.u8())||"unknown",mutable:!!sub.u8()};else if(kind===4){detail.attribute=sub.u8();detail.typeIndex=sub.u32();}else throw new Error("Unknown WASM import kind "+kind);imports.push({module,field,kind:["function","table","memory","global","tag"][kind]||"unknown",...detail});}}
    else if(id===3){count=sub.u32();for(let i=0;i<count;i++)functionTypeIndices.push(sub.u32());}
    else if(id===7){count=sub.u32();for(let i=0;i<count;i++){const name=sub.name(),kind=sub.u8(),index=sub.u32();exports.push({name,kind:["function","table","memory","global","tag"][kind]||"unknown",index});}}
    else if(id===10||id===11||id===4||id===5||id===6||id===9||id===11||id===12||id===13){try{count=sub.u32()}catch{}}
    sections.push({id,name:sectionName,customName,offset:start,size,payloadSize:size,count});
    r.pos=end;
  }
  const functionImports=imports.filter(x=>x.kind==="function").length;
  const functionExports=exports.filter(x=>x.kind==="function").map(x=>{const idx=x.index;const typeIndex=idx<functionImports?imports.filter(i=>i.kind==="function")[idx]?.typeIndex:functionTypeIndices[idx-functionImports];return {...x,type:typeIndex===undefined?null:(types[typeIndex]||null)};});
  const digest=hex(new Uint8Array(await crypto.subtle.digest("SHA-256",bytes)));
  return {size:bytes.length,version:version.join("."),sha256:digest,sections,imports,exports,functionExports,types:functionsCount(types),functionCount:functionImports+functionTypeIndices.length};
}
function functionsCount(types){return types.length;}
