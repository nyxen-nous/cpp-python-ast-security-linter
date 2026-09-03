const $ = (s) => document.querySelector(s);
const state = { scan: null, selected: null, files: [] };

const severityColors = {CRITICAL:'#732b86', HIGH:'#ad3b31', MEDIUM:'#a06a08', LOW:'#4c6f87'};

function setLoading(on){ $('#loading').classList.toggle('hidden', !on); }
function resetView(){ $('#results').classList.add('hidden'); $('#statusBanner').innerHTML=''; $('#findingList').innerHTML=''; $('#findingDetail').classList.add('hidden'); $('#emptyDetail').classList.remove('hidden'); }

function setTab(name){
  document.querySelectorAll('.tab').forEach(b=>b.classList.toggle('active', b.dataset.tab===name));
  document.querySelectorAll('.tab-pane').forEach(p=>p.classList.toggle('active', p.id===`tab-${name}`));
}
document.querySelectorAll('.tab').forEach(b=>b.addEventListener('click',()=>setTab(b.dataset.tab)));

$('#chooseFiles').onclick=()=>$('#fileInput').click();
$('#chooseFolder').onclick=()=>$('#folderInput').click();
$('#fileInput').onchange=e=>handleFiles([...e.target.files]);
$('#folderInput').onchange=e=>handleFiles([...e.target.files]);

const dz=$('#dropzone');
['dragenter','dragover'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.add('drag')}));
['dragleave','drop'].forEach(ev=>dz.addEventListener(ev,e=>{e.preventDefault();dz.classList.remove('drag')}));
dz.addEventListener('drop',e=>handleFiles([...e.dataTransfer.files]));

function handleFiles(files){
  state.files=files;
  if(!files.length){$('#selection').textContent='Nothing selected yet.';$('#scanProject').disabled=true;return;}
  const supported=files.filter(f=>{const ext=f.name.toLowerCase().slice(f.name.lastIndexOf('.'));return ['.py','.pyw','.pyi','.cpp','.cc','.cxx','.c++','.c','.h','.hpp','.hh','.hxx','.zip'].includes(ext)});
  state.files=supported;
  $('#selection').textContent=`${supported.length} supported file${supported.length===1?'':'s'} selected${supported.length<files.length?` · ${files.length-supported.length} skipped`:''}`;
  $('#scanProject').disabled=!supported.length;
}

async function scanProject(){
  const fd=new FormData();
  state.files.forEach(f=>{let name=f.webkitRelativePath||f.name;fd.append('files',f,name)});
  await doScan('/api/scan',fd,'Project scan');
}
$('#scanProject').onclick=scanProject;

$('#pasteLang').onchange=()=>{
  if($('#pasteLang').value==='cpp') $('#pasteFilename').value='snippet.cpp';
  else $('#pasteFilename').value='snippet.py';
};
$('#scanPaste').onclick=async()=>{
  const code=$('#codeInput').value;
  if(!code.trim()){alert('Paste some code first.');return;}
  const fd=new FormData();
  fd.append('code',code);fd.append('language',$('#pasteLang').value);fd.append('filename',$('#pasteFilename').value);
  await doScan('/api/scan',fd,'Snippet analysis');
};

async function doScan(url,body,title){
  resetView();setLoading(true);
  try{
    const res=await fetch(url,{method:'POST',body});
    const data=await res.json();
    if(!res.ok) throw new Error(data.error||'Scan failed');
    state.scan=data;state.selected=null;renderResults(title); 
  }catch(err){alert(err.message)}finally{setLoading(false)}
}

function renderResults(title){
  $('#results').classList.remove('hidden');
  $('#scanTitle').textContent=title;
  const s=state.scan.summary;
  $('#scanMeta').textContent=`${s.files_scanned} file${s.files_scanned===1?'':'s'} scanned · ${s.duration_seconds.toFixed(2)}s · ${s.rules_available} rules loaded`;
  $('#totalCount').textContent=s.total_findings;
  $('#criticalCount').textContent=s.by_severity.CRITICAL||0;
  $('#highCount').textContent=s.by_severity.HIGH||0;
  $('#mediumCount').textContent=s.by_severity.MEDIUM||0;
  $('#lowCount').textContent=s.by_severity.LOW||0;
  const warnings=state.scan.warnings||[];
  const banner=$('#statusBanner');banner.innerHTML='';
  if(state.scan.status==='PARTIAL') banner.innerHTML=`<div class="banner warn"><b>Partial analysis.</b> ${warnings.map(escapeHtml).join(' ')}</div>`;
  else if(state.scan.status==='ERROR') banner.innerHTML=`<div class="banner error"><b>Analysis error.</b> ${warnings.map(escapeHtml).join(' ')}</div>`;
  else if(!s.total_findings) banner.innerHTML=`<div class="banner ok"><b>Clean scan.</b> Analysis completed successfully with no reported findings.</div>`;
  renderFindings();
}

function filteredFindings(){
  const sev=$('#severityFilter').value,lang=$('#languageFilter').value,cat=$('#categoryFilter').value,q=$('#searchFilter').value.trim().toLowerCase();
  return state.scan.findings.filter(f=>(sev==='ALL'||f.severity===sev)&&(lang==='ALL'||f.language===lang)&&(cat==='ALL'||f.category===cat)&&(!q||`${f.rule_id} ${f.file} ${f.message}`.toLowerCase().includes(q)));
}
['severityFilter','languageFilter','categoryFilter','searchFilter'].forEach(id=>$(('#'+id)).addEventListener('input',renderFindings));

function renderFindings(){
  const list=$('#findingList'),items=filteredFindings();$('#shownCount').textContent=`${items.length} shown`;
  if(!items.length){list.innerHTML='<div class="no-findings">No findings match the current filters.</div>';return}
  list.innerHTML=items.map((f,i)=>{
    const sel=state.selected&&sameFinding(state.selected,f)?' selected':'';
    return `<div class="finding-row${sel}" data-index="${i}">
      <div class="finding-top"><span class="severity-badge" style="background:${severityColors[f.severity]||'#64717d'}">${f.severity}</span><span class="rule-id">${escapeHtml(f.rule_id)}</span><span class="chip">${escapeHtml(f.language)}</span>${f.cwe?`<span class="chip finding-cwe">${escapeHtml(f.cwe)}</span>`:''}</div>
      <div class="finding-msg">${escapeHtml(f.message)}</div>
      <div class="finding-loc">${escapeHtml(f.file)}:${f.line}</div>
    </div>`
  }).join('');
  list.querySelectorAll('.finding-row').forEach((el)=>el.onclick=()=>selectFinding(items[Number(el.dataset.index)]));
  if(!state.selected && items[0]) selectFinding(items[0]);
}

function sameFinding(a,b){return a.rule_id===b.rule_id&&a.file===b.file&&a.line===b.line&&a.col===b.col}

async function selectFinding(f){
  state.selected=f;renderFindings();
  $('#emptyDetail').classList.add('hidden');$('#findingDetail').classList.remove('hidden');
  $('#detailSeverity').textContent=f.severity;$('#detailSeverity').style.background=severityColors[f.severity]||'#64717d';
  $('#detailRule').textContent=f.rule_id;$('#detailCwe').textContent=f.cwe||'No CWE mapping';
  $('#detailMessage').textContent=f.message;
  $('#detailLocation').textContent=`${f.file}:${f.line}`;
  $('#detailConfidence').textContent=`${f.confidence} confidence · ${f.confidence_reason||'rule match'}`;
  $('#codeBlock').textContent=f.snippet||'Code context unavailable.';
  $('#detailWhy').textContent=f.explanation||'No additional explanation provided.';
  $('#detailFix').textContent=f.remediation||'No remediation text provided.';
  const ev=$('#evidencePath'),sec=$('#evidenceSection');ev.innerHTML='';
  if(f.taint_path&&f.taint_path.length){sec.classList.remove('hidden');ev.innerHTML=f.taint_path.map((s,i)=>`<div class="evidence-step"><div class="evidence-line">${i+1}</div><div>line ${s.line} · ${escapeHtml(s.description)}</div></div>`).join('')}
  else sec.classList.add('hidden');
  const fix=$('#applyFix'),note=$('#fixNote');note.classList.add('hidden');fix.classList.toggle('hidden',!(f.fixable&&f.fix));
  if(f.fixable&&f.fix) fix.onclick=applyFix;
  try{const res=await fetch(`/api/source/${encodeURIComponent(state.scan.scan_id)}/${encodeURI(f.file)}`);if(res.ok){const src=await res.json();$('#codeBlock').textContent=src.content.split('\n').slice(Math.max(0,f.line-4),f.line+3).map((line,i)=>`${Math.max(1,f.line-3)+i}  ${line}`).join('\n')}}catch(_){ }
}

async function applyFix(){
  if(!state.selected)return;
  const fix=$('#applyFix');fix.disabled=true;fix.textContent='Applying…';
  try{
    const res=await fetch('/api/fix',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scan_id:state.scan.scan_id,rule_id:state.selected.rule_id,file:state.selected.file,line:state.selected.line})});
    const data=await res.json();if(!res.ok)throw new Error(data.error||'Fix failed');
    state.scan=data;state.selected=null;renderResults('Re-scan after fix');$('#statusBanner').innerHTML='<div class="banner ok"><b>Fix applied and verified.</b> The project was re-scanned locally.</div>';
  }catch(err){$('#fixNote').classList.remove('hidden');$('#fixNote').textContent=err.message}
  finally{fix.disabled=false;fix.textContent='Apply verified fix & rescan'}
}
$('#newScan').onclick=()=>{state.scan=null;state.selected=null;resetView();window.scrollTo({top:0,behavior:'smooth'})};
function escapeHtml(s){return String(s??'').replace(/[&<>'"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;',"\"":'&quot;'}[c]));}

(async()=>{try{await fetch('/api/health')}catch(_){}})();
