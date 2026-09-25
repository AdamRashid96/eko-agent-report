const $ = id => document.getElementById(id);
const base = new URL('.', import.meta.url);
const storageKey = `eve-report-key:${base.pathname}`;
const encoder = new TextEncoder(), decoder = new TextDecoder();
const from64 = value => Uint8Array.from(atob(value), char => char.charCodeAt(0));
const to64 = value => btoa(String.fromCharCode(...value));
const manifestPromise = fetch(new URL('manifest.json', base)).then(response => {
  if (!response.ok) throw new Error('The report is not available. Please try again.');
  return response.json();
});
let manifest, key;
const objectURLs = new Map();
const worldNames = {
  coop_freight_yard:'Freight Yard', coop_unfinished_route:'Unfinished Route',
  coop_assembly_bay:'Shared Assembly Bay', coop_runway_workshop:'Runway Workshop',
  coop_room_tidy:'Room Tidy', coop_shared_house:'Shared House',
  coop_courtyard_cafe:'Courtyard Café', coop_library_move:'Library Move',
  coop_greenhouse_market:'Greenhouse Market', coop_canal_outpost:'Canal Outpost',
};
function resolveFile(raw, relativeTo='index.html') {
  const url = new URL(raw, `https://report.invalid/${relativeTo}`);
  if (url.origin !== 'https://report.invalid') return null;
  let file = decodeURIComponent(url.pathname).replace(/^\/+/, '');
  if (!file || file.endsWith('/')) file += 'index.html';
  if (!manifest.files[file]) return null;
  if (/^coop_[^/]+\/index\.html$/.test(file)) file = file.replace(/index\.html$/, 'report.html');
  return {file, fragment:url.hash.slice(1)};
}
function requestedFile() {
  const raw = new URLSearchParams(location.search).get('path')
    || document.querySelector('meta[name="report-page"]')?.content || 'analysis/index.html';
  return resolveFile(raw + location.hash) || {file:'analysis/index.html',fragment:''};
}
async function importKey(raw) {
  return crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},true,['decrypt']);
}
async function verifyKey(candidate) {
  const clear = await crypto.subtle.decrypt({name:'AES-GCM',iv:from64(manifest.check.iv)},candidate,from64(manifest.check.data));
  if (decoder.decode(clear)!=='EVE report package v1') throw new Error('Invalid password');
}
async function unlock(password) {
  manifest = await manifestPromise;
  const material = await crypto.subtle.importKey('raw',encoder.encode(password),'PBKDF2',false,['deriveBits']);
  const raw = new Uint8Array(await crypto.subtle.deriveBits({name:'PBKDF2',hash:manifest.kdf.hash,
    salt:from64(manifest.kdf.salt),iterations:manifest.kdf.iterations},material,256));
  const candidate = await importKey(raw); await verifyKey(candidate); key=candidate;
  try { sessionStorage.setItem(storageKey,JSON.stringify({salt:manifest.kdf.salt,key:to64(raw)})); } catch {}
  raw.fill(0);
}
async function decryptFile(file, progress) {
  const record=manifest.files[file];
  const size=record.parts.reduce((total,part)=>total+part.bytes,0);
  const encrypted=new Uint8Array(size+16); let offset=0;
  for (const part of record.parts) {
    const response=await fetch(new URL(part.url,base));
    if (!response.ok) throw new Error(`A report file could not be loaded (${response.status}).`);
    const reader=response.body.getReader();let received=0;
    while(true){const {value,done}=await reader.read();if(done)break;
      if(received+value.length>part.bytes)throw new Error('Unexpected report file size.');
      encrypted.set(value,offset);offset+=value.length;received+=value.length;progress?.(offset,size);}
    if(received!==part.bytes)throw new Error('The download was interrupted. Please try again.');
  }
  encrypted.set(from64(record.tag),size);
  const compressed=await crypto.subtle.decrypt({name:'AES-GCM',iv:from64(record.iv)},key,encrypted);
  const blob=await new Response(new Blob([compressed]).stream().pipeThrough(new DecompressionStream('gzip'))).blob();
  if(blob.size!==record.bytes)throw new Error('The report could not be unpacked.');
  return new Blob([blob],{type:record.type});
}
async function assetURL(file){
  if(!objectURLs.has(file))objectURLs.set(file,URL.createObjectURL(await decryptFile(file)));
  return objectURLs.get(file);
}
function signOut(){
  try{sessionStorage.removeItem(storageKey);}catch{}
  key=null;location.reload();
}
function addReportControls(route){
  const button=document.createElement('button');button.textContent='Sign out';button.id='eve-sign-out';
  button.style.cssText='position:fixed;bottom:12px;right:16px;padding:7px 12px;border:1px solid #d4ddd2;border-radius:8px;background:#fffdf7ed;color:#315e49;font:12px system-ui;z-index:999;cursor:pointer';
  button.onclick=signOut;document.body.append(button);
  document.addEventListener('click',async event=>{
    const link=event.target.closest?.('a[href]');if(!link||event.defaultPrevented)return;
    const raw=link.getAttribute('href');if(!raw||raw.startsWith('#')||/^(https?:|mailto:|data:|blob:)/i.test(raw))return;
    const target=resolveFile(raw,route.file);if(!target)return;
    if(link.hasAttribute('download')){
      event.preventDefault();try{const anchor=document.createElement('a');anchor.href=await assetURL(target.file);
        anchor.download=target.file.split('/').at(-1);anchor.click();}catch(error){alert(error.message);}
    }else if(manifest.files[target.file].type!=='text/html'){
      event.preventDefault();location.href=new URL('file.html?path='+encodeURIComponent(target.file),base).href;
    }
  });
}
async function openReport(route){
  $('login').hidden=true;$('loading').hidden=false;$('load-error').hidden=true;$('retry').hidden=true;$('back').hidden=true;
  $('loading-title').textContent=worldNames[route.file.split('/')[0]]||'Opening report';
  try{
    const blob=await decryptFile(route.file,(done,total)=>{
      $('progress').value=done/total*100;$('loading-note').textContent=total>5e6?`${(done/1e6).toFixed(0)} of ${(total/1e6).toFixed(0)} MB`:'Opening…';
    });
    $('loading-note').textContent='Preparing the page…';let text;
    if(blob.type==='text/html'){
      text=await blob.text();
      if(!route.file.startsWith('coop_')){
        const parsed=new DOMParser().parseFromString(text,'text/html');
        for(const element of parsed.querySelectorAll('[src]')){
          const raw=element.getAttribute('src');if(!raw||/^(data:|blob:|https?:)/i.test(raw))continue;
          const target=resolveFile(raw,route.file);if(!target)throw new Error('A report image is missing.');
          element.setAttribute('src',await assetURL(target.file));
        }
        text='<!doctype html>'+parsed.documentElement.outerHTML;
      }
      const url=new URL(route.file,base);url.hash=route.fragment;history.replaceState(null,'',url);
    }else if(blob.type.startsWith('image/')){
      const image=URL.createObjectURL(blob);objectURLs.set(route.file,image);
      text=`<!doctype html><meta name="viewport" content="width=device-width"><title>Report image</title><body style="margin:0;background:#f5f4ed"><img style="max-width:100%;display:block;margin:auto" src="${image}"></body>`;
    }else{
      const pre=document.createElement('pre');pre.textContent=await blob.text();
      text='<!doctype html><meta charset="utf-8"><title>Report evidence</title><style>body{background:#f5f4ed;color:#213e37;padding:24px}pre{white-space:pre-wrap;overflow-wrap:anywhere}</style>'+pre.outerHTML;
    }
    // Render in the normal document, preserving the original scripts and ordinary links.
    // Unlike an iframe, this also works in browsers that block embedded blob documents.
    document.open();document.write(text);document.close();text=null;
    addReportControls(route);
  }catch(error){
    if(!$('load-error')){console.error(error);return;}
    $('loading-note').textContent='';$('load-error').textContent=error.message;$('load-error').hidden=false;
    $('retry').hidden=false;$('back').hidden=false;
  }
}
$('unlock-form').addEventListener('submit',async event=>{
  event.preventDefault();$('unlock').disabled=true;$('unlock').textContent='Opening…';$('login-error').hidden=true;
  try{await unlock($('password').value);$('password').value='';await openReport(requestedFile());}
  catch{if($('login-error')){$('login-error').textContent='That password wasn’t accepted. Please try again.';$('login-error').hidden=false;$('password').focus();}}
  finally{if($('unlock')){$('unlock').disabled=false;$('unlock').textContent='Open report';}}
});
$('retry').onclick=()=>openReport(requestedFile());
$('back').onclick=()=>{location.href=new URL('analysis/',base).href;};
try{
  manifest=await manifestPromise;const saved=JSON.parse(sessionStorage.getItem(storageKey)||'null');
  if(saved?.salt===manifest.kdf.salt){const candidate=await importKey(from64(saved.key));await verifyKey(candidate);key=candidate;await openReport(requestedFile());}
}catch{try{sessionStorage.removeItem(storageKey);}catch{}}
