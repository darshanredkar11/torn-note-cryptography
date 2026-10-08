import crypto from 'node:crypto';
const H=(...xs)=>crypto.createHash('sha256').update(Buffer.concat(xs.map(x=>Buffer.isBuffer(x)?x:Buffer.from(String(x))))).digest();
const LEAF=Buffer.from('TORN-NOTE/leaf/v1'),TX=Buffer.from('TORN-NOTE/tx/v1');
export function keyPair(c='ed25519'){if(c==='ed25519')return crypto.generateKeyPairSync('ed25519');if(c==='p256')return crypto.generateKeyPairSync('ec',{namedCurve:'prime256v1'});throw Error('curve must be ed25519 or p256')}
export const publicKeyBytes=k=>k.export({type:'spki',format:'der'});
export const leaf=(id,a,b)=>H(LEAF,id,a,b);
export function merkleRoot(ls){if(!ls.length)throw Error('empty tree');let l=ls.slice();while(l.length>1){const n=[];for(let i=0;i<l.length;i+=2)n.push(l[i+1]?H(l[i],l[i+1]):H(l[i],l[i]));l=n}return l[0]}
export function merkleProof(ls,index){let l=ls.slice(),i=index,p=[];while(l.length>1){const q=i^1;p.push({side:q<l.length?(q<i?'L':'R'):'R',hash:l[q]??l[i]});const n=[];for(let j=0;j<l.length;j+=2)n.push(l[j+1]?H(l[j],l[j+1]):H(l[j],l[j]));i=Math.floor(i/2);l=n}return p}
export function verifyMerkle(x,p,r){for(const q of p)x=q.side==='L'?H(q.hash,x):H(x,q.hash);return x.equals(r)}
export const txDigest=(r,id,a,b,p)=>H(TX,r,id,a,b,Buffer.from(JSON.stringify(p)));
export const sign=(k,d)=>crypto.sign(null,d,k);
export const verify=(k,d,s)=>crypto.verify(null,d,k,s);
export function authorize({master,noteA,noteB,root,noteId,pubA,pubB,payload,proof}){if(!verifyMerkle(leaf(noteId,pubA,pubB),proof,root))return{ok:false,reason:'invalid-note-membership'};const d=txDigest(root,noteId,pubA,pubB,payload);return{ok:true,digest:d,signatures:{master:sign(master.privateKey,d),a:sign(noteA.privateKey,d),b:sign(noteB.privateKey,d)}}}
export function verifyAuthorization({masterPublicKey,pubAKey,pubBKey,root,noteId,pubA,pubB,payload,proof,signatures,spent=false}){if(spent||!verifyMerkle(leaf(noteId,pubA,pubB),proof,root))return false;const d=txDigest(root,noteId,pubA,pubB,payload);return verify(masterPublicKey,d,signatures.master)&&verify(pubAKey,d,signatures.a)&&verify(pubBKey,d,signatures.b)}