import crypto from "node:crypto";
const COOKIE="er_unit_session",MAX=8*60*60;
const json=(data,status=200,headers={})=>new Response(JSON.stringify(data),{status,headers:{"content-type":"application/json; charset=utf-8",...headers}});
const secret=()=>Netlify.env.get("ER_SESSION_SECRET")||"";
const expected=()=>Netlify.env.get("ER_UNIT_PASSWORD_HASH")||"";
const salt=()=>Netlify.env.get("ER_UNIT_PASSWORD_SALT")||"";
const hash=p=>crypto.pbkdf2Sync(String(p||""),salt(),210000,32,"sha256").toString("hex");
const sign=v=>crypto.createHmac("sha256",secret()).update(v).digest("hex");
const cookie=req=>{const m=(req.headers.get("cookie")||"").match(/(?:^|;\\s*)er_unit_session=([^;]+)/);return m?decodeURIComponent(m[1]):""};
const valid=req=>{const v=cookie(req),[exp,sig]=v.split(".");if(!exp||!sig||Number(exp)<Math.floor(Date.now()/1000))return false;const s=sign(exp);try{return crypto.timingSafeEqual(Buffer.from(sig),Buffer.from(s))}catch{return false}};
export default async(req)=>{
 const path=new URL(req.url).pathname;
 if(path==="/api/unit-session") return json({authenticated:valid(req)});
 if(path==="/api/unit-logout") return json({ok:true},200,{"set-cookie":COOKIE+"=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict"});
 if(path==="/api/unit-login"){if(req.method!=="POST")return json({error:"Method not allowed"},405);let b={};try{b=await req.json()}catch{};const got=hash(b.password);let ok=false;try{ok=!!expected()&&crypto.timingSafeEqual(Buffer.from(got),Buffer.from(expected()))}catch{};if(!ok)return json({ok:false,error:"รหัสส่วนกลางไม่ถูกต้อง"},401);const exp=String(Math.floor(Date.now()/1000)+MAX),value=exp+"."+sign(exp);return json({ok:true},200,{"set-cookie":COOKIE+"="+encodeURIComponent(value)+"; Max-Age="+MAX+"; Path=/; HttpOnly; Secure; SameSite=Strict"});}
 if(!valid(req))return json({error:"กรุณาเข้าสู่ระบบด้วยรหัสส่วนกลางของหน่วยงาน"},401);
 if(path==="/api/dashboard"){const base=Netlify.env.get("ER_APPS_SCRIPT_URL");if(!base)return json({error:"ยังไม่ได้ตั้งค่าแหล่งข้อมูล"},503);const u=new URL(base),q=new URL(req.url);for(const k of ["startDate","endDate","month","year","sex","age","respondent"]){const v=q.searchParams.get(k);if(v)u.searchParams.set(k,v.slice(0,120));}try{const r=await fetch(u);if(!r.ok)throw 0;const d=await r.json(),safe={};for(const k of ["respondentCount","kpi","satisfactionByItem","dissatisfactionByItem","monthlyTrend","demographics","confidence","diseaseGroups","improvementOpportunities","staffRecognition","filters","suppressed"])if(Object.hasOwn(d,k))safe[k]=d[k];safe.source="aggregate";safe.updatedAt=new Date().toISOString();return json(safe)}catch{return json({error:"ไม่สามารถโหลดข้อมูลสรุปได้ในขณะนี้"},502)}}
 return json({error:"Not found"},404);
};
export const config={path:["/api/unit-login","/api/unit-session","/api/unit-logout","/api/dashboard"]};