import "jsr:@supabase/functions-js/edge-runtime.d.ts";

const PORTAL_ORIGIN="https://xmod-store-mohammed.moha702m.chatgpt.site";
const PORTAL_PUBLIC_KEY_SPKI_B64="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEG9EXwi03lBl3xZNX53VzVdPh5UGjACVeyPXkraL+dty6T22N0l40fMHEAJwiLrGB72HOKnI3qT4TZigIYwDzkg==";
const SETUP_TOKEN = Deno.env.get("XSIGN_SETUP_TOKEN") || "";
const SUPABASE_URL=Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY=Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const enc=new TextEncoder(),dec=new TextDecoder();

const b64=(s:string)=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
const b64u=(s:string)=>{s=s.replace(/-/g,"+").replace(/_/g,"/");while(s.length%4)s+="=";return b64(s)};
const toB64u=(v:Uint8Array|string)=>{const x=typeof v==="string"?enc.encode(v):v;let s="";for(const n of x)s+=String.fromCharCode(n);return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"")};
const hex=(s:string)=>Uint8Array.from((s.match(/.{2}/g)||[]),x=>parseInt(x,16));
const json=(d:unknown,s=200)=>new Response(JSON.stringify(d),{status:s,headers:{"content-type":"application/json; charset=utf-8","cache-control":"no-store"}});
const err=(m:string,s=400)=>json({error:m},s);
class AppleActionError extends Error {
  constructor(public message:string, public status:number, public code:string, public retryAfterSeconds?:number){super(message)}
}
const cleanUdid=(v:unknown)=>String(v??"").trim().toUpperCase();
const validUdid=(v:string)=>/^[A-F0-9-]{20,50}$/.test(v);

function validPortalUrl(v:string,k:"source"|"callback",id:string){try{const u=new URL(v);return u.origin===PORTAL_ORIGIN&&u.pathname===`/api/signing/${k}/${id}`&&!u.search&&!u.hash}catch{return false}}

async function rpc(name:string,body:Record<string,unknown>={}){
  const r=await fetch(`${SUPABASE_URL}/rest/v1/rpc/${name}`,{method:"POST",headers:{apikey:SERVICE_KEY,authorization:`Bearer ${SERVICE_KEY}`,"content-type":"application/json"},body:JSON.stringify(body)});
  const raw=await r.text();
  if(!r.ok)throw new Error(`${name} ${r.status}: ${raw.slice(0,300)}`);
  return raw?JSON.parse(raw):null;
}

async function verifyPortal(req:Request,raw:string){
  try{
    const ts=req.headers.get("x-portal-timestamp")||"",sig=req.headers.get("x-portal-signature")||"",n=Number(ts);
    if(!/^\d{10}$/.test(ts)||!Number.isFinite(n)||Math.abs(Math.floor(Date.now()/1000)-n)>300||!/^[a-f0-9]{128}$/i.test(sig))return false;
    const key=await crypto.subtle.importKey("spki",b64(PORTAL_PUBLIC_KEY_SPKI_B64),{name:"ECDSA",namedCurve:"P-256"},false,["verify"]);
    return await crypto.subtle.verify({name:"ECDSA",hash:"SHA-256"},key,hex(sig),enc.encode(`${ts}.${raw}`));
  }catch{return false}
}

let jwks:{keys:any[],expires:number}|null=null;
async function verifyGithub(req:Request){
  try{
    const a=req.headers.get("authorization")||"";
    if(!a.startsWith("Bearer "))return false;
    const p=a.slice(7).split(".");
    if(p.length!==3)return false;
    const h=JSON.parse(dec.decode(b64u(p[0]))),c=JSON.parse(dec.decode(b64u(p[1]))),now=Math.floor(Date.now()/1000);
    const aud=c.aud,ok=aud==="xsign-worker"||(Array.isArray(aud)&&aud.includes("xsign-worker"));
    if(h.alg!=="RS256"||!h.kid||c.iss!=="https://token.actions.githubusercontent.com"||!ok||c.repository!=="moha700m/modx-signer-ci"||c.ref!=="refs/heads/main"||c.workflow_ref!=="moha700m/modx-signer-ci/.github/workflows/xsign-worker.yml@refs/heads/main"||!c.exp||c.exp<now-30||(c.nbf&&c.nbf>now+30))return false;
    if(!jwks||jwks.expires<Date.now()){const r=await fetch("https://token.actions.githubusercontent.com/.well-known/jwks");if(!r.ok)return false;const j=await r.json();jwks={keys:j.keys||[],expires:Date.now()+3600000}}
    const k=jwks.keys.find((x:any)=>x.kid===h.kid);if(!k)return false;
    const key=await crypto.subtle.importKey("jwk",k,{name:"RSASSA-PKCS1-v1_5",hash:"SHA-256"},false,["verify"]);
    return await crypto.subtle.verify("RSASSA-PKCS1-v1_5",key,b64u(p[2]),enc.encode(`${p[0]}.${p[1]}`));
  }catch{return false}
}

async function readBody(req:Request){const raw=await req.text();try{return{raw,data:raw?JSON.parse(raw):{}}}catch{return{raw,data:{}}}}

async function appleSecrets(){
  const s=await rpc("xsign_apple_secrets_get");
  if(!s?.issuer||!s?.keyId||!s?.privateKey)throw new Error("Apple credentials are not configured.");
  return s as {issuer:string,keyId:string,privateKey:string};
}
async function appleJwt(){
  const s=await appleSecrets();
  let pem=String(s.privateKey).trim();
  if(!pem.includes("BEGIN PRIVATE KEY")){try{pem=dec.decode(b64(pem)).trim()}catch{}}
  if(!pem.includes("BEGIN PRIVATE KEY"))throw new Error("Apple P8 secret is not a valid private key.");
  const der=b64(pem.replace(/-----BEGIN PRIVATE KEY-----/g,"").replace(/-----END PRIVATE KEY-----/g,"").replace(/\s+/g,""));
  const key=await crypto.subtle.importKey("pkcs8",der,{name:"ECDSA",namedCurve:"P-256"},false,["sign"]);
  const now=Math.floor(Date.now()/1000);
  const h=toB64u(JSON.stringify({alg:"ES256",kid:s.keyId,typ:"JWT"}));
  const p=toB64u(JSON.stringify({iss:s.issuer,iat:now,exp:now+900,aud:"appstoreconnect-v1"}));
  const input=`${h}.${p}`;
  const sig=new Uint8Array(await crypto.subtle.sign({name:"ECDSA",hash:"SHA-256"},key,enc.encode(input)));
  return `${input}.${toB64u(sig)}`;
}
async function appleApi(method:string,path:string,params?:Record<string,string>,payload?:unknown){
  const u=new URL(`https://api.appstoreconnect.apple.com${path}`);
  for(const [k,v] of Object.entries(params||{}))u.searchParams.set(k,v);
  const token=await appleJwt();
  const r=await fetch(u,{method,headers:{authorization:`Bearer ${token}`,"content-type":"application/json"},body:payload===undefined?undefined:JSON.stringify(payload)});
  const data=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(`Apple API ${method} ${path} failed (${r.status}): ${JSON.stringify(data).slice(0,1000)}`);
  return data as any;
}
async function appleAction(body:Record<string,unknown>){
  const action=String(body.action??"");
  if(action==="ping"){const d=await appleApi("GET","/v1/certificates",{limit:"1"});return{ok:true,certificateCount:Array.isArray(d.data)?d.data.length:0}}
  if(action==="certificate.create"){
    const csr=String(body.csrContent??"").trim();
    if(!csr.includes("BEGIN CERTIFICATE REQUEST")||csr.length>20000)throw new Error("Invalid certificate signing request.");
    const createOnce=async()=>{
      const d=await appleApi("POST","/v1/certificates",undefined,{data:{type:"certificates",attributes:{certificateType:"IOS_DEVELOPMENT",csrContent:csr}}});
      const a=d.data?.attributes||{};if(!d.data?.id||!a.certificateContent)throw new Error("Apple did not return an iOS Development certificate.");
      return{id:d.data.id,certificateContent:a.certificateContent,serialNumber:a.serialNumber??null,expirationDate:a.expirationDate??null};
    };
    try{return await createOnce()}catch(e){
      const msg=e instanceof Error?e.message:String(e);
      if(msg.includes("(409)")){
        throw new AppleActionError(
          "Apple rejected certificate creation (conflict); review the Apple Developer account details. Existing certificates were not changed.",
          409,
          "APPLE_CERTIFICATE_CREATE_CONFLICT",
        );
      }
      throw e;
    }
  }
  if(action==="certificate.lookup"){
    const raw=String(body.serial??"").trim().toUpperCase();if(!raw)throw new Error("Certificate serial is required.");
    for(const serial of Array.from(new Set([raw.replace(/^0+/,""),raw]))){const d=await appleApi("GET","/v1/certificates",{"filter[serialNumber]":serial,limit:"10"});const item=(d.data||[]).find((x:any)=>x?.attributes?.activated!==false);if(item)return{id:item.id}}
    throw new Error("Apple iOS certificate was not found in this developer team.");
  }
  if(action==="device.ensure"){
    const udid=cleanUdid(body.udid),name=String(body.name??"XSign iPhone").trim().slice(0,50)||"XSign iPhone";
    if(!validUdid(udid))throw new Error("Invalid UDID.");
    const f=await appleApi("GET","/v1/devices",{"filter[udid]":udid,limit:"50"});
    const validateDevice=(record:any)=>{
      const id=String(record?.id??"").trim(),a=record?.attributes||{},status=String(a.status??""),platform=String(a.platform??"");
      if(id&&status==="ENABLED"&&platform==="IOS")return{id,status,platform};
      if(id&&status==="PROCESSING"&&platform==="IOS"){
        throw new AppleActionError("Apple device registration is still processing; retry this job later.",409,"APPLE_DEVICE_PROCESSING",900);
      }
      throw new AppleActionError(`Apple device is not an enabled iOS device (status=${status||"unknown"}, platform=${platform||"unknown"}).`,422,"APPLE_DEVICE_INVALID");
    };
    const records=Array.isArray(f.data)?f.data:[];
    const enabled=records.find((record:any)=>record?.id&&record?.attributes?.status==="ENABLED"&&record?.attributes?.platform==="IOS");
    if(enabled)return validateDevice(enabled);
    const processing=records.find((record:any)=>record?.id&&record?.attributes?.status==="PROCESSING"&&record?.attributes?.platform==="IOS");
    if(processing)return validateDevice(processing);
    const existing=records[0];
    if(existing)return validateDevice(existing);
    const d=await appleApi("POST","/v1/devices",undefined,{data:{type:"devices",attributes:{name,platform:"IOS",udid}}});
    return validateDevice(d.data);
  }
  if(action==="bundle.ensure"){
    const identifier=String(body.identifier??"").trim(),displayName=String(body.name??"XSign App").trim();
    if(!/^[A-Za-z0-9.-]{3,200}$/.test(identifier))throw new Error("Invalid bundle identifier.");
    const f=await appleApi("GET","/v1/bundleIds",{"filter[identifier]":identifier,limit:"10"});if(f.data?.length)return{id:f.data[0].id};
    const safe=displayName.replace(/[^A-Za-z0-9 ._-]+/g,"-").trim()||"XSign App";
    const d=await appleApi("POST","/v1/bundleIds",undefined,{data:{type:"bundleIds",attributes:{identifier,name:(`XSign ${safe}`).slice(0,100),platform:"IOS"}}});return{id:d.data.id};
  }
  if(action==="capability.ensure"){
    const bundleId=String(body.bundleId??"").trim(),cap=String(body.capabilityType??"").trim();
    if(!bundleId||cap!=="PUSH_NOTIFICATIONS")throw new Error("Unsupported capability request.");
    const f=await appleApi("GET",`/v1/bundleIds/${encodeURIComponent(bundleId)}/bundleIdCapabilities`);
    if((f.data||[]).some((x:any)=>x?.attributes?.capabilityType===cap))return{ok:true};
    await appleApi("POST","/v1/bundleIdCapabilities",undefined,{data:{type:"bundleIdCapabilities",attributes:{capabilityType:cap},relationships:{bundleId:{data:{type:"bundleIds",id:bundleId}}}}});return{ok:true};
  }
  if(action==="profile.ensure"){
    const name=String(body.name??"").trim().slice(0,100),bundleId=String(body.bundleId??"").trim(),deviceId=String(body.deviceId??"").trim(),certificateId=String(body.certificateId??"").trim();
    if(!name||!bundleId||!deviceId||!certificateId)throw new Error("Profile request is incomplete.");
    const f=await appleApi("GET","/v1/profiles",{"filter[name]":name,"fields[profiles]":"name,profileState,profileContent,expirationDate",limit:"10"});
    for(const item of f.data||[]){const a=item.attributes||{};if(a.profileContent&&a.profileState!=="INVALID")return{profileContent:a.profileContent,expirationDate:a.expirationDate??null}}
    const d=await appleApi("POST","/v1/profiles",undefined,{data:{type:"profiles",attributes:{name,profileType:"IOS_APP_DEVELOPMENT"},relationships:{bundleId:{data:{type:"bundleIds",id:bundleId}},devices:{data:[{type:"devices",id:deviceId}]},certificates:{data:[{type:"certificates",id:certificateId}]}}}});
    return{profileContent:d.data.attributes.profileContent,expirationDate:d.data.attributes.expirationDate??null};
  }
  throw new Error("Unsupported Apple worker action.");
}

function setupHtml(){
return `<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>XSign Apple Setup</title><style>body{font-family:system-ui;background:#0b0d10;color:#fff;margin:0;padding:20px}main{max-width:680px;margin:5vh auto;background:#151922;border:1px solid #2a3140;border-radius:18px;padding:24px}input,textarea,button{width:100%;box-sizing:border-box;padding:13px;border-radius:10px;margin:8px 0;font-size:15px}input,textarea{background:#0e1117;color:#fff;border:1px solid #394253}textarea{min-height:180px}button{border:0;background:#fff;color:#111;font-weight:700}p{color:#cbd5e1;line-height:1.7}#s{white-space:pre-wrap}</style></head><body><main><h2>إعداد Apple لـ XSign</h2><p>أدخل القيم الثلاث. سيتم تخزينها مشفّرة داخل Supabase Vault ولن تُعرض بعد الحفظ.</p><input id="issuer" placeholder="APPLE_ISSUER_ID"><input id="kid" placeholder="APPLE_KEY_ID"><textarea id="p8" placeholder="الصق محتوى AuthKey_XXXX.p8 أو Base64"></textarea><button id="go">حفظ واختبار Apple</button><p id="s"></p><script>go.onclick=async()=>{go.disabled=true;s.textContent='جاري الحفظ والاختبار...';try{const r=await fetch(location.href,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({issuer:issuer.value.trim(),keyId:kid.value.trim(),privateKey:p8.value.trim()})});const d=await r.json();if(r.ok&&d.ok){issuer.value='';kid.value='';p8.value='';s.textContent='تم بنجاح. Apple API متصل والشهادة جاهزة للاستخدام.'}else{s.textContent='فشل: '+(d.error||d.detail||'unknown')}}catch(e){s.textContent='تعذر الاتصال'}finally{go.disabled=false}}</script></main></body></html>`;
}

Deno.serve(async(req)=>{
 try{
  const u=new URL(req.url);
    if(SETUP_TOKEN&&u.searchParams.get("setup")===SETUP_TOKEN){
    if(req.method==="GET")return new Response(setupHtml(),{headers:{"content-type":"text/html; charset=utf-8","cache-control":"no-store"}});
    if(req.method==="POST"){
      const d=(await readBody(req)).data,issuer=String(d.issuer??"").trim(),keyId=String(d.keyId??"").trim(),privateKey=String(d.privateKey??"").trim();
      if(issuer.length<10||issuer.length>100||!/^[A-Za-z0-9-]+$/.test(issuer))return err("Invalid issuer.",400);
      if(keyId.length<5||keyId.length>40||!/^[A-Za-z0-9]+$/.test(keyId))return err("Invalid key id.",400);
      if(privateKey.length<100||privateKey.length>20000)return err("Invalid private key.",400);
      await rpc("xsign_apple_secrets_set",{p_issuer:issuer,p_key_id:keyId,p_private_key:privateKey});
      const test=await appleAction({action:"ping"});
      return json({ok:true,apple:test});
    }
    return err("Method not allowed.",405);
  }

  let path=u.searchParams.get("path")||u.pathname.replace(/^\/functions\/v1\/xsign2/,"")||"/";
  if(req.method==="GET"&&(path==="/"||path==="/api/_healthcheck")){const st=await rpc("xsign_setup_status").catch(()=>({configured:false}));return json({message:"Success",backend:"supabase",version:"2.0.0",appleConfigured:Boolean(st?.configured)})}

  if(req.method==="POST"&&path==="/api/portal/jobs"){
    const b=await readBody(req);if(!await verifyPortal(req,b.raw))return err("Portal unauthorized.",401);
    const d=b.data,id=String(d.orderId??"").trim(),udid=cleanUdid(d.udid),name=String(d.deviceName??"XMOD iPhone").trim().slice(0,80)||"XMOD iPhone",fn=String(d.filename??"").trim().slice(0,180),size=Number(d.size),src=String(d.sourceUrl??"").trim(),cb=String(d.callbackUrl??"").trim(),tok=String(d.signingToken??"").trim();
    if(!/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(id))return err("Invalid order id.");
    if(!validUdid(udid))return err("Invalid UDID.");
    if(!fn.toLowerCase().endsWith(".ipa")||!Number.isFinite(size)||size<1||size>209715200)return err("Invalid IPA metadata.");
    if(!/^[a-f0-9]{64}$/i.test(tok))return err("Invalid signing token.");
    if(!validPortalUrl(src,"source",id)||!validPortalUrl(cb,"callback",id))return err("Invalid portal callback.");
    return json(await rpc("xsign_portal_enqueue",{p_order_id:id,p_udid:udid,p_device_name:name,p_filename:fn,p_size:size,p_source_url:src,p_callback_url:cb,p_signing_token:tok}),201);
  }

  if(path.startsWith("/api/worker/")){
    if(!await verifyGithub(req))return err("Worker OIDC unauthorized.",401);
    if(req.method==="POST"&&path==="/api/worker/heartbeat"){const d=(await readBody(req)).data;return json(await rpc("xsign_worker_beat",{p_worker_id:String(d.workerId??"github-macos"),p_version:String(d.version??"")}))}
    if(req.method==="POST"&&path==="/api/worker/claim")return json(await rpc("xsign_claim_job",{p_worker_id:"github-macos"}));
    if(req.method==="POST"&&path==="/api/worker/apple"){
      const d=(await readBody(req)).data;
      try{return json(await appleAction(d))}
      catch(e){
        if(e instanceof AppleActionError){
          const body:{error:string;code:string;retryAfterSeconds?:number}={error:e.message,code:e.code};
          if(e.retryAfterSeconds)body.retryAfterSeconds=e.retryAfterSeconds;
          return json(body,e.status);
        }
        const message=e instanceof Error?e.message:"Apple worker operation failed.";
        return err(message,502);
      }
    }
    if(req.method==="GET"&&path==="/api/worker/signing-identity"){const v=await rpc("xsign_identity_get");return v?json(v):err("Signing identity not found.",404)}
    if(req.method==="POST"&&path==="/api/worker/signing-identity"){const d=(await readBody(req)).data,p=String(d.p12B64??"").trim(),pw=String(d.password??"");if(!p||p.length>200000||pw.length>512)return err("Invalid signing identity payload.");return json(await rpc("xsign_identity_set",{p_p12_b64:p,p_password:pw}))}
    let m=path.match(/^\/api\/worker\/jobs\/([0-9a-f-]{36})\/status$/i);if(req.method==="POST"&&m){const d=(await readBody(req)).data;return json(await rpc("xsign_job_status",{p_id:m[1],p_status:String(d.status??""),p_message:String(d.message??"")}))}
    m=path.match(/^\/api\/worker\/jobs\/([0-9a-f-]{36})\/defer$/i);if(req.method==="POST"&&m){const d=(await readBody(req)).data;return json(await rpc("xsign_job_defer",{p_id:m[1],p_message:String(d.message??"بانتظار إعادة المحاولة")}))}
    m=path.match(/^\/api\/worker\/jobs\/([0-9a-f-]{36})\/portal-complete$/i);if(req.method==="POST"&&m){const d=(await readBody(req)).data,fn=String(d.filename??""),ex=String(d.expirationDate??"");if(!fn.toLowerCase().endsWith(".ipa")||!Number.isFinite(Date.parse(ex)))return err("Invalid signed IPA metadata.");return json(await rpc("xsign_portal_complete",{p_id:m[1],p_filename:fn,p_expiration:ex}))}
    m=path.match(/^\/api\/worker\/jobs\/([0-9a-f-]{36})\/fail$/i);if(req.method==="POST"&&m){const d=(await readBody(req)).data;return json(await rpc("xsign_job_fail",{p_id:m[1],p_message:String(d.message??"Signing failed")}))}
  }
  return err("Not found.",404);
 }catch(e){console.error("xsign2",e);return err(e instanceof Error?e.message:"Internal error.",500)}
});
