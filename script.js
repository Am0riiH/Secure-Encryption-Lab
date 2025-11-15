const FIXED_MASTER_KEY = "omar-secure-key-3166238";

const tabs = document.querySelectorAll(".tab");
const contents = document.querySelectorAll(".tab-content");

tabs.forEach(t=>{
    t.addEventListener("click",()=>{
        document.querySelector(".tab.active").classList.remove("active");
        t.classList.add("active");
        contents.forEach(c=>c.classList.remove("active"));
        document.getElementById(t.dataset.tab).classList.add("active");
    });
});

const enc = new TextEncoder();
const dec = new TextDecoder();

function strToUint8(s){return enc.encode(s);}
function uint8ToStr(b){return dec.decode(b);}

function bufToBase64(b){
    const bytes=new Uint8Array(b);let bin="";
    bytes.forEach(x=>bin+=String.fromCharCode(x));
    return btoa(bin);
}

function base64ToBuf(b){
    const clean=b.replace(/\s+/g,"");
    const bin=atob(clean);
    const arr=new Uint8Array(bin.length);
    for(let i=0;i<bin.length;i++)arr[i]=bin.charCodeAt(i);
    return arr.buffer;
}

async function deriveAesKey(p,a="AES-GCM"){
    const base=await crypto.subtle.importKey("raw",enc.encode(p),"PBKDF2",false,["deriveKey"]);
    return crypto.subtle.deriveKey(
        {name:"PBKDF2",salt:enc.encode("static-salt-demo"),iterations:100000,hash:"SHA-256"},
        base,{name:a,length:256},false,["encrypt","decrypt"]
    );
}

async function encryptAESGCM(t){
    const k=await deriveAesKey(FIXED_MASTER_KEY,"AES-GCM");
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const e=await crypto.subtle.encrypt({name:"AES-GCM",iv},k,strToUint8(t));
    const out=new Uint8Array(iv.length+e.byteLength);
    out.set(iv);out.set(new Uint8Array(e),iv.length);
    return bufToBase64(out.buffer);
}

async function decryptAESGCM(b){
    const bytes=new Uint8Array(base64ToBuf(b));
    const iv=bytes.slice(0,12);
    const data=bytes.slice(12);
    const k=await deriveAesKey(FIXED_MASTER_KEY,"AES-GCM");
    const d=await crypto.subtle.decrypt({name:"AES-GCM",iv},k,data);
    return uint8ToStr(d);
}

function pkcs7Pad(b){
    const bs=16;const pad=bs-(b.length%bs||bs);
    const out=new Uint8Array(b.length+pad);
    out.set(b);out.fill(pad,b.length);
    return out;
}

function pkcs7Unpad(b){
    const p=b[b.length-1];
    return b.slice(0,b.length-p);
}

async function encryptAESCBC(t){
    const k=await deriveAesKey(FIXED_MASTER_KEY,"AES-CBC");
    const iv=crypto.getRandomValues(new Uint8Array(16));
    const padded=pkcs7Pad(strToUint8(t));
    const e=await crypto.subtle.encrypt({name:"AES-CBC",iv},k,padded);
    const out=new Uint8Array(iv.length+e.byteLength);
    out.set(iv);out.set(new Uint8Array(e),iv.length);
    return bufToBase64(out.buffer);
}

async function decryptAESCBC(b){
    const bytes=new Uint8Array(base64ToBuf(b));
    const iv=bytes.slice(0,16);
    const data=bytes.slice(16);
    const k=await deriveAesKey(FIXED_MASTER_KEY,"AES-CBC");
    const d=await crypto.subtle.decrypt({name:"AES-CBC",iv},k,data);
    return uint8ToStr(pkcs7Unpad(new Uint8Array(d)));
}

function base64Encode(t){return btoa(unescape(encodeURIComponent(t)));}
function base64Decode(t){return decodeURIComponent(escape(atob(t)));}

function rot13(t){
    return t.replace(/[A-Za-z]/g,c=>{
        const b=c<="Z"?65:97;
        return String.fromCharCode(((c.charCodeAt(0)-b+13)%26)+b);
    });
}

const urlEncode=encodeURIComponent;
const urlDecode=decodeURIComponent;

function xorEncrypt(t){
    const k=strToUint8(FIXED_MASTER_KEY);
    const d=strToUint8(t);
    const out=new Uint8Array(d.length);
    for(let i=0;i<d.length;i++)out[i]=d[i]^k[i%k.length];
    return bufToBase64(out);
}

function xorDecrypt(b){
    const data=new Uint8Array(base64ToBuf(b));
    const k=strToUint8(FIXED_MASTER_KEY);
    const out=new Uint8Array(data.length);
    for(let i=0;i<data.length;i++)out[i]=data[i]^k[i%k.length];
    return uint8ToStr(out);
}

function caesarEncrypt(t){
    const s=5;
    return t.replace(/[A-Za-z]/g,c=>{
        const b=c<="Z"?65:97;
        return String.fromCharCode(((c.charCodeAt(0)-b+s)%26)+b);
    });
}

function caesarDecrypt(t){
    const s=5;
    return t.replace(/[A-Za-z]/g,c=>{
        const b=c<="Z"?65:97;
        return String.fromCharCode(((c.charCodeAt(0)-b-s+260)%26)+b);
    });
}

async function sha256(t){
    const buf=await crypto.subtle.digest("SHA-256",strToUint8(t));
    return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,"0")).join("");
}

document.getElementById("encrypt-btn").addEventListener("click",async()=>{
    const text=document.getElementById("enc-input").value.trim();
    const type=document.getElementById("enc-type").value;
    const out=document.getElementById("enc-output");
    if(!text){out.value="Please enter text.";return;}
    try{
        let r="";
        if(type==="aes-gcm")r=await encryptAESGCM(text);
        else if(type==="aes-cbc")r=await encryptAESCBC(text);
        else if(type==="base64-enc")r=base64Encode(text);
        else if(type==="rot13-enc")r=rot13(text);
        else if(type==="url-enc")r=urlEncode(text);
        else if(type==="xor")r=xorEncrypt(text);
        else if(type==="caesar")r=caesarEncrypt(text);
        else if(type==="sha256")r=await sha256(text);
        out.value=r;
    }catch(e){out.value="Error: "+e;}
});

document.getElementById("copy-enc-output").addEventListener("click",async()=>{
        const t = document.getElementById("enc-output").value;
    if (t) {
        await navigator.clipboard.writeText(t);
        showToast("Encrypted text copied ✓");
    }
});

document.getElementById("decrypt-btn").addEventListener("click",async()=>{
    const text=document.getElementById("dec-input").value.trim();
    const type=document.getElementById("dec-type").value;
    const out=document.getElementById("dec-output");
    const st=document.getElementById("dec-status");
    if(!text){out.value="Paste encrypted text.";return;}
    try{
        let r="";
        if(type==="aes-gcm")r=await decryptAESGCM(text);
        else if(type==="aes-cbc")r=await decryptAESCBC(text);
        else if(type==="base64-dec")r=base64Decode(text);
        else if(type==="rot13-dec")r=rot13(text);
        else if(type==="url-dec")r=urlDecode(text);
        else if(type==="xor")r=xorDecrypt(text);
        else if(type==="caesar")r=caesarDecrypt(text);
        out.value=r;
        st.textContent="Successfully decrypted.";
        st.className="status-success status-msg";
    }catch(e){
        st.textContent="Failed: wrong key or corrupted data.";
        st.className="status-error status-msg";
        out.value="";
    }
});

function showToast(msg) {
    const toast = document.getElementById("toast");
    toast.textContent = msg;
    toast.classList.add("show");

    setTimeout(() => {
        toast.classList.remove("show");
    }, 1800);
}

function looksBase64(str){
    const s=str.replace(/\s+/g,"");
    if(/^[A-Fa-f0-9]+$/.test(s))return false;
    if(s.length===0||s.length%4!==0)return false;
    if(!/^[A-Za-z0-9+/]+={0,2}$/.test(s))return false;
    try{atob(s);return true;}catch{return false;}
}

function isHex32(s){return /^[A-Fa-f0-9]{32}$/.test(s);}
function isHex64(s){return /^[A-Fa-f0-9]{64}$/.test(s);}
function isJwt(s){return /^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+$/.test(s);}

function isLikelyText(s){
    if(!s)return false;
    let c=0;
    for(let i=0;i<s.length;i++){
        const code=s.charCodeAt(i);
        if(code===9||code===10||code===13){c++;continue;}
        if(code>=32&&code<=126)c++;
    }
    return c/s.length>0.85;
}

function detectAES_GCM(str){
    if(!looksBase64(str))return false;
    try{
        const bytes=new Uint8Array(base64ToBuf(str));
        const ivLen=12,tagLen=16;
        if(bytes.length<=ivLen+tagLen)return false;
        const cipherLen=bytes.length-ivLen-tagLen;
        if(cipherLen<=0)return false;
        return true;
    }catch{return false;}
}

function detectAES_CBC(str){
    if(!looksBase64(str))return false;
    try{
        const bytes=new Uint8Array(base64ToBuf(str));
        const ivLen=16;
        if(bytes.length<=ivLen)return false;
        const cipherLen=bytes.length-ivLen;
        if(cipherLen<=0||cipherLen%16!==0)return false;
        if(detectAES_GCM(str))return false;
        return true;
    }catch{return false;}
}

function detectBase64Layers(str){
    let s=str.trim();
    let layers=0;
    for(let i=0;i<3;i++){
        if(!looksBase64(s))break;
        try{
            s=atob(s.replace(/\s+/g,""));
            layers++;
        }catch{break;}
    }
    return layers;
}

function detectXOR(str){
    if(!looksBase64(str))return false;
    try{
        const plain=xorDecrypt(str);
        return isLikelyText(plain);
    }catch{return false;}
}

function detectROT13(str){
    if(!/^[A-Za-z\s]+$/.test(str))return false;
    const decText=rot13(str);
    return isLikelyText(decText);
}

document.getElementById("analyze-btn").addEventListener("click",()=>{
    const x=document.getElementById("analyze-input").value.trim();
    const box=document.getElementById("analysis-result");
    if(!x){box.textContent="Please enter a value.";return;}
    let r=[];
    const layers=detectBase64Layers(x);
    if(layers===1)r.push("• Base64 detected (single layer).");
    else if(layers>1)r.push("• Base64 detected ("+layers+" layers).");
    if(detectAES_GCM(x))r.push("• AES-GCM encrypted data detected.");
    if(detectAES_CBC(x))r.push("• AES-CBC encrypted data detected.");
    if(/%[0-9A-F]{2}/i.test(x))r.push("• URL encoding detected.");
    if(isHex32(x))r.push("• MD5 hash detected.");
    if(isHex64(x))r.push("• SHA-256 hash detected.");
    if(isJwt(x))r.push("• JWT token detected.");
    if(detectXOR(x))r.push("• XOR-encrypted data detected (using fixed key).");
    if(detectROT13(x))r.push("• ROT13-encoded text detected.");
    if(/token=|key=|signature=|auth=/i.test(x))r.push("• Sensitive parameter detected (token/key/auth).");
    if(r.length===0)r.push("• No known encryption or encoding patterns detected.");
    box.textContent=r.join(" ");
});

/* omar rashied */
