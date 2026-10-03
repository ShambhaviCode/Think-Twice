/* ==================================================================
   DETECTION ENGINE — pure functions, no DOM.
   Each rule belongs to a stage of the scam pattern:
     hook (bait) → pressure (urgency/fear) → ask (money, codes, clicks)
     plus "disguise" (impersonation signals, often in links).
   Score: each distinct flag has a weight w. Risk = 1 − Π(1 − w), so
   flags add up with diminishing returns and no single weak sign
   dominates. Pressure + request together adds a combination flag,
   because that pairing is the core of nearly every scam.
   Protective phrases ("never share this code") reduce risk.
   ================================================================== */
const Engine = (() => {
  const RULES = [
    {id:'urgent', cat:'pressure', w:.25, title:'Rushing you',
      re:/\b(urgent(ly)?|immediately|right away|asap|within \d+ ?(hours?|hrs|minutes|mins)|today only|act now|last (chance|warning|reminder)|expires? (today|soon|tonight)|final (notice|warning)|before it expires)\b/gi,
      why:'Scammers set a deadline so you act before you think. Real companies give you time to check.'},
    {id:'threat', cat:'pressure', w:.3, title:'Threatening a loss',
      re:/\b(will be (disconnected|blocked|suspended|cancell?ed|deactivated|closed|frozen|terminated)|(is|has been) (blocked|suspended|disconnected|deactivated|frozen|on hold|compromised|infected)|legal action|arrest(ed)?|warrant|police case|penalty)\b/gi,
      why:'Fear of losing your power, account or money makes people panic. Real providers send formal notices, not texts warning you about tonight.'},
    {id:'secret', cat:'pressure', w:.25, title:'Asking for secrecy',
      re:/\b(don'?t tell|do not tell|keep (this|it) (a )?(secret|confidential|between us))\b/gi,
      why:'Keeping it secret cuts you off from the people who would spot the scam. Always tell someone you trust.'},
    {id:'prize', cat:'hook', w:.3, title:'Too good to be true',
      re:/\b(congratulations|you('ve| have)? won|winner|lottery|lucky draw|prize|free gift|gift card|been selected|claim (now|your))\b/gi,
      why:'You can\'t win a contest you never entered. Prizes are bait to get your details or a "small fee".'},
    {id:'job', cat:'hook', w:.4, title:'Easy money job',
      re:/\b(work from home|part[- ]time (work|job)|earn \$?\d[\d,]*\s*(per|a|\/)\s*(day|hour)|daily income|liking (youtube )?videos|like (youtube )?videos|simple tasks?)\b/gi,
      why:'Real jobs don\'t pay big money for liking videos. These start with small payouts and end with you paying them.'},
    {id:'verify', cat:'hook', w:.25, title:'Fake account problem',
      re:/\b(update your (details|information|account|address|kyc)|verify your (account|identity|details)|confirm your (account|identity|details)|unusual (sign-?in|activity|login)|kyc)\b/gi,
      why:'Banks and stores don\'t ask you to fix your account through a link or reply in a text. Open the official app yourself.'},
    {id:'delivery', cat:'hook', w:.2, title:'Parcel problem',
      re:/\b(parcel|package|shipment|delivery)\b[^.\n]{0,50}\b(held|pending|failed|on hold|unable|incomplete|customs|fee)\b/gi,
      why:'Fake "your package is on hold" texts are among the most common scams. Check the delivery company\'s official app instead.'},
    {id:'family', cat:'hook', w:.3, title:'"New number" story',
      re:/\b(hi (mum|mom|dad|grandma|grandpa)[,!]? (it'?s|this is) (me|my new number)|this is my new number|my new number|lost my phone|dropped my phone|phone (is )?broken)\b/gi,
      why:'Scammers pretend to be a son or daughter on a new number. Call their old number before doing anything.'},
    {id:'code', cat:'ask', w:.6, title:'Asking for a secret code',
      re:/\b(share|send|tell|forward|give|provide|reply with|read out)\b[^.\n]{0,30}\b(otp|one[- ]time (password|code)|verification code|\d-digit code|code|pin|cvv|password)\b/gi,
      guard:(t,i)=>!/(not|never|n'?t|dont)\s+$/i.test(t.slice(Math.max(0,i-12),i)),
      why:'No real bank, company or government office will ever ask for your code, PIN or password. Anyone who does is a scammer.'},
    {id:'pay', cat:'ask', w:.25, title:'Asking for money',
      re:/\b(pay|send money|transfer|processing fee|small fee|delivery fee|registration fee|gift cards?|bitcoin|crypto|wire)\b/gi,
      why:'Unexpected requests to pay, especially a fee to release a prize or parcel, are a classic sign.'},
    {id:'click', cat:'ask', w:.15, title:'Pushing you to a link',
      re:/\b(click( here| the link| below)?|tap (here|the link)|open the link|log ?in (here|now|below))\b/gi,
      why:'The message wants you to click before you check. Go to the official app or website yourself instead.'},
    {id:'call', cat:'ask', w:.2, title:'"Call this number"',
      re:/\b(call|contact|text|whatsapp|reach)\b[^.\n]{0,50}?(\+?\d[\d\s().-]{8,}\d)/gi,
      why:'A number inside a suspicious message connects you to the scammer. Use the number on your card, bill or the official website.'},
    {id:'remote', cat:'ask', w:.45, title:'Remote control app',
      re:/\b(anydesk|teamviewer|quick ?support|rustdesk|remote access|screen ?share)\b/gi,
      why:'These apps let a stranger control your phone or computer. Never install one because a message told you to.'},
    {id:'greeting', cat:'disguise', w:.1, title:'Generic greeting',
      re:/\b(dear (customer|user|sir|madam|valued customer|account ?holder|client))\b/gi,
      why:'Your bank knows your name. "Dear customer" usually means the same text went to thousands of people.'},
  ];
  const PROTECT = [
    {id:'protect', title:'Warns you to keep codes private', w:.35,
      re:/\b(do not|don'?t|never)\s+share\b[^.\n]{0,25}\b(otp|code|pin|password)\b|\bwill never (call|text|email|ask)\b/gi,
      why:'Real code messages tell you not to share the code. That lowers the risk, though scammers sometimes copy this line too.'},
  ];
  const BRANDS = {usps:['usps.com'],chase:['chase.com'],amazon:['amazon.com','amazon.in'],paypal:['paypal.com'],apple:['apple.com'],
    microsoft:['microsoft.com'],google:['google.com'],netflix:['netflix.com'],walmart:['walmart.com'],fedex:['fedex.com'],
    ups:['ups.com'],dhl:['dhl.com'],irs:['irs.gov'],wellsfargo:['wellsfargo.com'],bankofamerica:['bankofamerica.com'],
    costco:['costco.com'],venmo:['venmo.com'],zelle:['zellepay.com'],att:['att.com'],verizon:['verizon.com']};
  const SHORT = new Set(['bit.ly','tinyurl.com','t.co','cutt.ly','is.gd','rb.gy','shorturl.at','ow.ly','tiny.cc','goo.gl','buff.ly','t.ly']);
  const RISKY_TLD = new Set(['xyz','top','click','link','info','online','site','live','shop','icu','buzz','rest','cc','tk','ml','ga','cf','support','vip']);
  const URL_RE = /\b(?:https?:\/\/)?(?:www\.)?((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|gov|edu|us|uk|in|co|io|ly|me|app|info|biz|xyz|top|click|link|online|site|live|shop|icu|buzz|rest|cc|tk|ml|ga|cf|gl|at|support|vip))\b(\/[^\s]*)?/gi;

  const registrable = h => { const p=h.split('.'); if(p.length>=3 && ['co','com','gov','org','net','ac'].includes(p[p.length-2]) && p[p.length-1].length===2) return p.slice(-3).join('.'); return p.slice(-2).join('.'); };
  const unleet = s => s.replace(/0/g,'o').replace(/1/g,'l').replace(/3/g,'e').replace(/5/g,'s').replace(/-/g,'');

  function checkLinks(text){
    const out=[]; let m; const re=new RegExp(URL_RE.source,URL_RE.flags);
    while((m=re.exec(text))){
      let full=m[0].replace(/[.,;:!?)\]]+$/,''); const s=m.index, e=s+full.length;
      const host=m[1].toLowerCase(), reg=registrable(host), tld=host.split('.').pop();
      const isHttp=/^http:\/\//i.test(full);
      const add=(id,w,title,why)=>out.push({id,cat:'disguise',w,title,why,s,e,txt:full});
      if(SHORT.has(reg)||SHORT.has(host)) add('short',.3,'Hidden link destination','Short links hide where they really go. Scammers use them so you can\'t see the fake website address.');
      if(RISKY_TLD.has(tld)) add('tld',.3,`Unusual web address ending (.${tld})`,`Big companies use addresses like .com or .gov. Endings like .${tld} are cheap and popular with scam sites.`);
      const flat=unleet(host);
      for(const [b,official] of Object.entries(BRANDS)){
        if(flat.includes(b) && !official.includes(reg)){
          add('lookalike',.45,`Pretends to be ${b.toUpperCase()==='UPS'||b==='usps'||b==='irs'?b.toUpperCase():b[0].toUpperCase()+b.slice(1)}`,
            `The link uses the name "${b}" but the real website is ${official[0]}. This address belongs to someone else.`); break; }
      }
      if(/^\d+\.\d+\.\d+\.\d+$/.test(host)) add('ip',.4,'Link is a bare number address','Real companies use names, not number addresses, for their websites.');
      out.push({id:'link',cat:'ask',w:.1,title:'Wants you to open a link',why:'Almost every scam text includes a link. Even when the rest looks fine, open the company\'s app or type its address yourself.',s,e,txt:full});
      if(isHttp) add('http',.1,'Unsecured link (http)','The link doesn\'t use a secure connection. Real login and payment pages always use https.');
    }
    return out;
  }

  function analyze(text){
    const hits=[];
    for(const r of RULES){
      const re=new RegExp(r.re.source,r.re.flags); let m;
      while((m=re.exec(text))){ if(!m[0]){re.lastIndex++;continue;} if(r.guard&&!r.guard(text,m.index)) continue;
        hits.push({id:r.id,cat:r.cat,w:r.w,title:r.title,why:r.why,s:m.index,e:m.index+m[0].length,txt:m[0]}); }
    }
    hits.push(...checkLinks(text));
    const prot=[];
    for(const r of PROTECT){ const re=new RegExp(r.re.source,r.re.flags); let m; while((m=re.exec(text))) prot.push({...r,cat:'good',s:m.index,e:m.index+m[0].length,txt:m[0]}); }
    // group hits into distinct flags (one per rule id), keep every matched span
    const flags=[]; const byId={};
    for(const h of hits){ if(!byId[h.id]){ byId[h.id]={id:h.id,cat:h.cat,w:h.w,title:h.title,why:h.why,spans:[]}; flags.push(byId[h.id]); } byId[h.id].spans.push({s:h.s,e:h.e,txt:h.txt}); }
    const has=c=>flags.some(f=>f.cat===c);
    const combos=[];
    if(has('pressure')&&has('ask')) combos.push({id:'combo1',cat:'combo',w:.25,title:'Pressure plus a request',why:'Rushing you and asking for something in the same message is the core of almost every scam.',spans:[]});
    if(has('hook')&&has('ask')&&!has('pressure')) combos.push({id:'combo2',cat:'combo',w:.2,title:'Bait plus a request',why:'An offer or problem followed by a request for money, codes or a click.',spans:[]});
    const all=[...flags,...combos];
    let keep=1; for(const f of all) keep*=1-f.w;
    let risk=1-keep;
    const protW=prot.length?PROTECT[0].w:0;
    risk*=1-protW;
    risk=Math.max(0,Math.min(.99,risk));
    // proportional share of the score per flag, for the breakdown
    const sumW=all.reduce((a,f)=>a+f.w,0)||1;
    for(const f of all) f.share=risk*f.w/sumW;
    flags.sort((a,b)=>a.spans[0].s-b.spans[0].s);
    const verdict = !text.trim()? 'none' : risk>=.6?'scam' : risk>=.3?'careful' : 'safe';
    return {text,flags,combos,prot,risk,verdict,stages:{hook:has('hook'),pressure:has('pressure'),ask:has('ask'),disguise:has('disguise')}};
  }
  return {analyze};
})();

/* ======================= CONTENT ======================= */
const SAMPLES = [
  {name:'Power cut threat', scam:true, text:'Dear Customer, your electricity will be disconnected tonight at 9:30 PM because your last bill payment was not updated. Please call our electricity officer immediately at (555) 014-2237.'},
  {name:'Parcel on hold', scam:true, text:'USPS: Your package is on hold due to an incomplete address. Update your details within 24 hours to avoid return: https://usps-redelivery.top/track'},
  {name:'Bank code request', scam:true, text:'Chase Alert: Unusual sign-in detected on your account. To secure it, reply with the 6-digit code we just sent you. If you ignore this, your account will be suspended.'},
  {name:'"Hi Mom"', scam:true, text:'Hi Mom, this is my new number, I dropped my phone in the sink. Can you do me a favor? I need to pay a bill today and my bank app isn\'t working. Don\'t tell Dad yet.'},
  {name:'Gift card prize', scam:true, text:'Congratulations! You have been selected to receive a $1,000 Walmart gift card. Claim now at bit.ly/wm-claim before it expires today. A small processing fee applies.'},
  {name:'Easy job', scam:true, text:'Hello! We are hiring for part-time work from home. Earn $300 per day by liking YouTube videos. Simple tasks, daily income. Contact us on WhatsApp +1 555 019 4482.'},
  {name:'Virus warning', scam:true, text:'Microsoft Security: Your computer is infected. Call support immediately at 1-555-010-7731 and install AnyDesk so our technician can fix it.'},
  {name:'Real code message', scam:false, text:'Your Chase verification code is 482913. Don\'t share this code with anyone. Chase will never call or text to ask for it.'},
  {name:'Real delivery update', scam:false, text:'Your Amazon order has shipped and will arrive Thursday. You can follow it in the Amazon app.'},
  {name:'Grandkid text', scam:false, text:'Hi Grandma! Practice ran late, I\'ll be home around 7. Can you save me some dinner? Love you'},
];
const CATS = {hook:{label:'Bait',c:'var(--hook)'},pressure:{label:'Pressure',c:'var(--pressure)'},ask:{label:'Request',c:'var(--ask)'},disguise:{label:'Disguise',c:'var(--disguise)'},combo:{label:'Pattern',c:'var(--ink)'},good:{label:'Good sign',c:'var(--good)'}};
const VERDICTS = {
  none:{word:'Paste a message',sub:'We\'ll check it for the tricks scammers use most.',c:'var(--muted)'},
  safe:{word:'No red flags found',sub:'This doesn\'t match common scam patterns. Still, never share codes or pay anyone you weren\'t expecting.',c:'var(--safe)'},
  careful:{word:'Be careful',sub:'Some warning signs. Don\'t click or reply until you\'ve checked with the company directly.',c:'var(--careful)'},
  scam:{word:'Likely a scam',sub:'This message uses several tricks scammers rely on. Don\'t click, reply, pay or call back.',c:'var(--scam)'},
};
function todoFor(a){
  const s=[];
  if(a.verdict==='safe') return ['Reply or act as normal if you were expecting this message.','If it later asks for a code, money or a link, check it again.'];
  s.push('Don\'t click links, call numbers or reply to this message.');
  if(a.flags.some(f=>f.id==='code')) s.push('Never share the code. If you already did, call your bank right away using the number on your card.');
  if(a.flags.some(f=>f.id==='pay')) s.push('Don\'t send money or gift cards. Real companies don\'t ask for payment this way.');
  if(a.flags.some(f=>f.id==='family')) s.push('Call your family member on the number you already have for them.');
  if(a.flags.some(f=>f.id==='remote')) s.push('Don\'t install any app. If you already did, turn off the internet and ask someone you trust for help.');
  s.push('Check by opening the company\'s official app or website yourself, not through this message.');
  s.push('Send this result to a family member, then delete the message and block the sender.');
  return s;
}

/* ======================= CHECK VIEW ======================= */
const $=id=>document.getElementById(id);
const esc=s=>s.replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
let current=null, openFlag=null;

function markup(a){
  // Collect spans; on overlap the higher-weight flag wins.
  const spans=[];
  a.flags.forEach((f,i)=>f.spans.forEach(sp=>spans.push({...sp,n:i+1,id:f.id,cat:f.cat,w:f.w})));
  a.prot.forEach(p=>spans.push({s:p.s,e:p.e,n:0,id:'protect',cat:'good',w:0}));
  spans.sort((x,y)=>y.w-x.w||x.s-y.s);
  const keep=[];
  for(const sp of spans){ const hit=keep.find(t=>sp.s<t.e&&sp.e>t.s); if(hit){ if(sp.n&&!hit.ns.includes(sp.n)) hit.ns.push(sp.n); continue; } keep.push({...sp,ns:sp.n?[sp.n]:[]}); }
  keep.sort((x,y)=>x.s-y.s);
  let h='',pos=0;
  for(const sp of keep){
    h+=esc(a.text.slice(pos,sp.s));
    const c=CATS[sp.cat].c;
    h+=`<mark class="${sp.cat==='good'?'good':''}${openFlag===sp.id?' on':''}" style="--c:${c}" data-flag="${sp.id}" tabindex="0" role="button" aria-label="${sp.cat==='good'?'Good sign':'Red flag '+sp.ns.join(' and ')}: ${esc(a.text.slice(sp.s,sp.e))}">${esc(a.text.slice(sp.s,sp.e))}${sp.ns.length?`<sup>${sp.ns.sort((x,y)=>x-y).join(',')}</sup>`:''}</mark>`;
    pos=sp.e;
  }
  return h+esc(a.text.slice(pos));
}

function render(){
  const text=$('msg').value; const a=Engine.analyze(text); current=a;
  const b=$('bubble');
  if(!text.trim()){ b.className='bubble empty'; b.textContent='Your message will appear here with the warning signs marked.'; }
  else { b.className='bubble'; b.innerHTML=markup(a); }
  const nf=a.flags.length;
  $('foundSub').textContent = !text.trim()? 'Red flags are underlined in the message. Tap one to see why.' :
    nf? `${nf} red flag${nf>1?'s':''} found. Tap one to see why it matters.` : a.prot.length? 'No red flags, and it has a good sign (green dashes).' : 'No red flags matched. Read the tips on the right before acting.';
  // flag list
  const items=[...a.flags.map((f,i)=>({f,n:i+1})),...a.combos.map(f=>({f,n:'+'})),...a.prot.slice(0,1).map(p=>({f:{...p,spans:[{txt:p.txt}]},n:'✓'}))];
  $('flags').innerHTML=items.map(({f,n})=>{ const c=CATS[f.cat].c; const ex=openFlag===f.id;
    const q=f.spans&&f.spans[0]&&f.spans[0].txt?`<span class="quote">"${esc(f.spans[0].txt)}"</span> — `:'';
    return `<li><button aria-expanded="${ex}" data-flag="${f.id}" style="--c:${c}"><span class="num">${n}</span><span><span class="t">${esc(f.title)}</span><br><span class="cat">${CATS[f.cat].label}</span></span><span aria-hidden="true">${ex?'−':'+'}</span><span class="why">${q}${esc(f.why)}</span></button></li>`; }).join('');
  // verdict
  const v=VERDICTS[a.verdict];
  $('vword').textContent=v.word; $('vword').style.color=v.c; $('vsub').textContent=v.sub;
  $('needle').style.transform=`rotate(${(-90+ (text.trim()?a.risk:0)*180).toFixed(1)}deg)`;
  $('gauge').setAttribute('aria-label',`Risk gauge: ${v.word}`);
  // anatomy
  for(const [k,id] of [['hook','stHook'],['pressure','stPressure'],['ask','stAsk']]) $(id).classList.toggle('lit',a.stages[k]);
  const lit=['hook','pressure','ask'].filter(k=>a.stages[k]).length;
  $('anatomyNote').textContent = !text.trim()? 'Most scams use all three. A message that pressures you and asks for something is the biggest warning sign.' :
    lit===3? 'This message has all three parts of a typical scam.' : lit===0? 'None of the three parts showed up.' :
    `${lit} of 3 parts found.${a.stages.pressure&&a.stages.ask?' Pressure plus a request is the strongest warning sign.':''}`;
  // breakdown
  const all=[...a.flags,...a.combos].sort((x,y)=>y.share-x.share);
  $('breakdownPanel').hidden=!all.length;
  const mx=Math.max(...all.map(f=>f.share),.01);
  $('breakdown').innerHTML=all.map(f=>`<div class="bar" style="--c:${CATS[f.cat].c}"><span>${esc(f.title)}</span><span class="tr"><i style="width:${f.share/mx*100}%"></i></span><span class="v">+${Math.round(f.share*100)}</span></div>`).join('')+
    (a.prot.length?`<div class="bar" style="--c:var(--good)"><span>Warns you to keep codes private</span><span class="tr"><i style="width:30%"></i></span><span class="v">lower</span></div>`:'')+
    `<p style="font-size:.85rem;color:var(--muted);margin:8px 0 0">Risk score ${Math.round(a.risk*100)} out of 100. Each flag adds less as more pile up, so no single weak sign decides the result.</p>`;
  // todo
  $('todoPanel').hidden=!text.trim();
  $('todoTitle').textContent= a.verdict==='safe'?'Good habits':'What to do now';
  $('todo').innerHTML=todoFor(a).map(s=>`<li>${esc(s)}</li>`).join('');
  $('status').textContent='';
}
let t=0; $('msg').addEventListener('input',()=>{ clearTimeout(t); t=setTimeout(render,150); });
$('samples').insertAdjacentHTML('beforeend',SAMPLES.map((s,i)=>`<button class="chip" data-i="${i}">${esc(s.name)}</button>`).join(''));
$('samples').onclick=e=>{ const b=e.target.closest('[data-i]'); if(!b) return; $('msg').value=SAMPLES[b.dataset.i].text; openFlag=null; render(); };
function toggleFlag(id){ openFlag = openFlag===id? null : id; render(); }
$('flags').onclick=e=>{ const b=e.target.closest('[data-flag]'); if(b) { toggleFlag(b.dataset.flag); $('flags').querySelector(`[data-flag="${b.dataset.flag}"]`)?.focus(); } };
$('bubble').onclick=e=>{ const m=e.target.closest('mark'); if(!m) return; openFlag=m.dataset.flag; render(); $('flags').querySelector(`[data-flag="${m.dataset.flag}"]`)?.scrollIntoView({block:'nearest',behavior:'smooth'}); };
$('bubble').onkeydown=e=>{ if((e.key==='Enter'||e.key===' ')&&e.target.matches('mark')){ e.preventDefault(); e.target.click(); } };
$('clearBtn').onclick=()=>{ $('msg').value=''; openFlag=null; render(); $('msg').focus(); };
$('shareBtn').onclick=async()=>{
  const a=current; const v=VERDICTS[a.verdict];
  const txt=`Think Twice check: ${v.word}.\n${a.flags.length?'Red flags: '+a.flags.map(f=>f.title).join('; ')+'.\n':''}Message: "${a.text.trim().slice(0,280)}"`;
  try{ if(navigator.share){ await navigator.share({title:'Think Twice result',text:txt}); return; } }catch(e){ if(e.name==='AbortError') return; }
  try{ await navigator.clipboard.writeText(txt); $('status').textContent='Copied. Paste it into a message to your family.'; }
  catch(e){ $('status').textContent='Copy didn\'t work here. Select the message and verdict and copy them by hand.'; }
};

/* ======================= PRACTICE VIEW ======================= */
let pIdx=0, pOrder=[], pAns=null, marked=new Set(), streak=0, done=0;
function shuffle(n){ const a=[...Array(n).keys()]; for(let i=n-1;i>0;i--){ const j=Math.floor(Math.random()*(i+1)); [a[i],a[j]]=[a[j],a[i]]; } return a; }
function tokens(text){ const out=[]; const re=/\S+/g; let m; while((m=re.exec(text))) out.push({s:m.index,e:m.index+m[0].length,w:m[0]}); return out; }
function startPractice(next){
  if(!pOrder.length||next){ if(!pOrder.length||pIdx>=pOrder.length-1){ pOrder=shuffle(SAMPLES.length); pIdx=0; } else if(next) pIdx++; }
  pAns=null; marked=new Set();
  const s=SAMPLES[pOrder[pIdx]];
  $('pq').textContent='Is this message a scam?';
  $('pbubble').innerHTML=tokens(s.text).map((tk,i)=>`<button class="tok" data-t="${i}" disabled>${esc(tk.w)}</button>`).join(' ');
  $('choice').hidden=false; $('markStep').hidden=true; $('presult').hidden=true;
  $('streak').textContent= done? `${streak} correct in a row` : '';
}
$('choice').onclick=e=>{ const b=e.target.closest('[data-ans]'); if(!b) return; pAns=b.dataset.ans;
  $('choice').hidden=true;
  if(pAns==='scam'){ $('pq').textContent='Which words gave it away?'; $('markStep').hidden=false; $('pbubble').querySelectorAll('.tok').forEach(t=>t.disabled=false); $('pbubble').querySelector('.tok')?.focus(); }
  else reveal(); };
$('pbubble').onclick=e=>{ const t=e.target.closest('.tok'); if(!t||t.disabled) return; const i=+t.dataset.t; marked.has(i)?marked.delete(i):marked.add(i); t.classList.toggle('mk'); t.setAttribute('aria-pressed',String(marked.has(i))); };
$('revealBtn').onclick=reveal;
function reveal(){
  const s=SAMPLES[pOrder[pIdx]]; const a=Engine.analyze(s.text); const tk=tokens(s.text);
  const inSpan=(t,sp)=>t.s<sp.e&&t.e>sp.s;
  const found=a.flags.filter(f=>f.spans.some(sp=>[...marked].some(i=>inSpan(tk[i],sp))));
  const missed=a.flags.filter(f=>!found.includes(f));
  const btns=$('pbubble').querySelectorAll('.tok');
  tk.forEach((t,i)=>{ const flagged=a.flags.some(f=>f.spans.some(sp=>inSpan(t,sp))); const b=btns[i]; b.disabled=true; b.classList.remove('mk');
    if(flagged&&marked.has(i)) b.classList.add('hit'); else if(flagged) b.classList.add('miss'); else if(marked.has(i)) b.classList.add('wrong'); });
  const right=(pAns==='scam')===s.scam; done++; streak=right?streak+1:0;
  $('markStep').hidden=true; $('pq').textContent= right? 'Correct.' : 'Not quite.';
  let h=`<h3>${s.scam?'This one is a scam.':'This one is real.'}</h3>`;
  if(s.scam&&pAns==='scam') h+=`<p class="score">You spotted ${found.length} of ${a.flags.length} red flags.</p><div class="legend2"><span style="--c:var(--good)">you found it</span><span style="--c:var(--careful)">you missed it</span></div>`;
  else if(s.scam) h+=`<p class="score">It has ${a.flags.length} red flags, underlined in orange above.</p>`;
  else h+=`<p class="score">${a.prot.length?'It even warns you never to share the code, which real companies do.':'It doesn\'t ask for money, codes or clicks, and there\'s no pressure.'}</p>`;
  if(marked.size&&[...marked].some(i=>!a.flags.some(f=>f.spans.some(sp=>inSpan(tk[i],sp))))) h+=`<p style="color:var(--muted);font-size:.9rem">Crossed-out words are ones you marked that aren't warning signs.</p>`;
  if(s.scam) h+=`<ul>${a.flags.map(f=>`<li><b>${esc(f.title)}${found.includes(f)?' ✓':''}</b> — ${esc(f.why)}</li>`).join('')}</ul>`;
  h+=`<div class="btnrow"><button class="btn" id="nextBtn">Next message</button><button class="btn ghost" id="checkIt">Open in checker</button></div>`;
  $('presult').innerHTML=h; $('presult').hidden=false;
  $('streak').textContent=`${streak} correct in a row`;
  $('nextBtn').onclick=()=>startPractice(true); $('nextBtn').focus();
  $('checkIt').onclick=()=>{ $('msg').value=s.text; openFlag=null; render(); setTab('check'); };
}

/* ======================= TABS & TEXT SIZE ======================= */
function setTab(t){
  const c=t==='check';
  $('tabCheck').setAttribute('aria-selected',c); $('tabPractice').setAttribute('aria-selected',!c);
  $('tabCheck').tabIndex=c?0:-1; $('tabPractice').tabIndex=c?-1:0;
  $('viewCheck').hidden=!c; $('viewPractice').hidden=c;
  if(!c&&!$('pbubble').innerHTML) startPractice();
}
$('tabCheck').onclick=()=>setTab('check'); $('tabPractice').onclick=()=>setTab('practice');
document.querySelector('.tabs').onkeydown=e=>{ if(e.key==='ArrowRight'||e.key==='ArrowLeft'){ const p=$('tabCheck').getAttribute('aria-selected')==='true'; setTab(p?'practice':'check'); (p?$('tabPractice'):$('tabCheck')).focus(); } };
function setSize(s){ document.documentElement.style.setProperty('--scale',s); document.querySelectorAll('.size button').forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.s===String(s)))); try{ localStorage.setItem('tt-size',s); }catch(e){} }
document.querySelectorAll('.size button').forEach(b=>b.onclick=()=>setSize(b.dataset.s));
try{ const s=localStorage.getItem('tt-size'); if(s) setSize(s); }catch(e){}
render();
