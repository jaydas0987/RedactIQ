"""
RedactIQ — Web interface for the PII redaction engine.
Run: python app.py
Open: http://localhost:5000

Default login: admin / admin123
"""

import os, sys, uuid, json, shutil, zipfile, sqlite3, threading, hashlib
from pathlib import Path
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_file, render_template_string, session, redirect

sys.path.insert(0, str(Path(__file__).parent))

app = Flask(__name__)
app.secret_key = "redactiq-secret-2024"
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024

BASE_DIR = Path(__file__).parent / "redactiq_data"
UPLOAD_DIR = BASE_DIR / "uploads"
OUTPUT_DIR = BASE_DIR / "outputs"
DB_PATH = BASE_DIR / "jobs.db"
JOBS = {}
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
ALLOWED_EXTENSIONS = {".txt", ".pdf", ".docx", ".csv", ".xlsx", ".sql"}

# ── auth helpers ───────────────────────────────────────────────

def hash_pw(pw): return hashlib.sha256(pw.encode()).hexdigest()

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "username" not in session:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated


# ── SQLite ─────────────────────────────────────────────────────

def db_init():
    con = sqlite3.connect(str(DB_PATH))
    con.execute("""CREATE TABLE IF NOT EXISTS jobs (
        job_id TEXT PRIMARY KEY, timestamp TEXT, mode TEXT,
        file_count INTEGER, total_redactions INTEGER,
        summary TEXT, files TEXT, status TEXT, error TEXT, run_by TEXT)""")
    con.execute("""CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY, password_hash TEXT,
        role TEXT DEFAULT 'analyst', created_at TEXT)""")
    if con.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
        con.execute("INSERT INTO users VALUES (?,?,?,?)",
            ("admin", hash_pw("admin123"), "admin",
             datetime.now().isoformat(timespec="seconds")))
    con.commit(); con.close()

def db_save(job_id, job):
    con = sqlite3.connect(str(DB_PATH))
    con.execute("""INSERT OR REPLACE INTO jobs VALUES (?,?,?,?,?,?,?,?,?,?)""", (
        job_id,
        job.get("timestamp", datetime.now().isoformat(timespec="seconds")),
        job.get("mode", ""), len(job.get("files", [])),
        job.get("total_redactions", 0),
        json.dumps(job.get("summary", {})),
        json.dumps(job.get("files", [])),
        job.get("status", ""), job.get("error") or "",
        job.get("run_by", "—")))
    con.commit(); con.close()

def db_all_jobs():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM jobs ORDER BY timestamp DESC").fetchall()
    con.close()
    return [dict(r) for r in rows]

def db_all_users():
    con = sqlite3.connect(str(DB_PATH))
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT username,role,created_at FROM users ORDER BY created_at").fetchall()
    con.close()
    return [dict(r) for r in rows]

db_init()


# ── HTML pages ─────────────────────────────────────────────────

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<title>RedactIQ — Login</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Mono:wght@400&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#0a0a0f;--surface:#111118;--border:#2a2a3a;--accent:#e8ff47;--text:#f0f0f8;--muted:#6b6b8a;--danger:#ff4747}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'DM Mono',monospace;min-height:100vh;display:flex;align-items:center;justify-content:center}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(232,255,71,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(232,255,71,0.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none}
.card{position:relative;z-index:1;background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:48px;width:100%;max-width:400px}
.logo{font-family:'Syne',sans-serif;font-weight:800;font-size:24px;margin-bottom:6px}.logo span{color:var(--accent)}
.sub{color:var(--muted);font-size:11px;margin-bottom:36px;letter-spacing:1px}
label{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);display:block;margin-bottom:8px}
input{width:100%;background:#0a0a0f;border:1px solid var(--border);color:var(--text);padding:12px 14px;font-family:'DM Mono',monospace;font-size:13px;border-radius:3px;margin-bottom:20px;outline:none;transition:border 0.15s}
input:focus{border-color:var(--accent)}
button{width:100%;background:var(--accent);color:#0a0a0f;border:none;padding:14px;font-family:'Syne',sans-serif;font-weight:700;font-size:13px;letter-spacing:1px;text-transform:uppercase;cursor:pointer;border-radius:3px}
button:hover{background:#f5ff80}
.error{color:var(--danger);font-size:11px;margin-bottom:16px}
</style></head><body>
<div class="card">
  <div class="logo">Redact<span>IQ</span></div>
  <div class="sub">Secure · Offline · Private</div>
  {% if error %}<div class="error">✕ {{ error }}</div>{% endif %}
  <form method="POST">
    <label>Username</label><input type="text" name="username" autocomplete="off" required/>
    <label>Password</label><input type="password" name="password" required/>
    <button type="submit">Sign In</button>
  </form>
</div></body></html>"""


MAIN_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>RedactIQ</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:wght@300;400;500&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#0a0a0f;--surface:#111118;--surface2:#1a1a24;--border:#2a2a3a;--accent:#e8ff47;--accent2:#47c8ff;--danger:#ff4747;--text:#f0f0f8;--muted:#6b6b8a;--success:#47ffb2}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'DM Mono',monospace;min-height:100vh;overflow-x:hidden}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(232,255,71,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(232,255,71,0.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}
.wrap{position:relative;z-index:1;max-width:900px;margin:0 auto;padding:48px 24px 80px}
header{display:flex;align-items:flex-end;justify-content:space-between;margin-bottom:56px;padding-bottom:24px;border-bottom:1px solid var(--border)}
.logo{font-family:'Syne',sans-serif;font-weight:800;font-size:28px;letter-spacing:-1px}.logo span{color:var(--accent)}
nav{display:flex;gap:8px;align-items:center}
.nav-link{font-size:11px;letter-spacing:2px;text-transform:uppercase;padding:8px 16px;border-radius:3px;text-decoration:none;border:1px solid var(--border);color:var(--muted);transition:all 0.15s}
.nav-link:hover{border-color:var(--text);color:var(--text)}
.nav-link.logout{border-color:var(--danger);color:var(--danger)}
.nav-link.logout:hover{background:var(--danger);color:#0a0a0f}
.section-label{font-size:10px;letter-spacing:3px;text-transform:uppercase;color:var(--muted);margin-bottom:16px}
.modes{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:32px}
.mode-card{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:20px;cursor:pointer;transition:all 0.15s;position:relative;overflow:hidden}
.mode-card::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:transparent;transition:background 0.15s}
.mode-card:hover{border-color:#3a3a4a}
.mode-card.active{border-color:var(--accent);background:#111a00}
.mode-card.active::before{background:var(--accent)}
.mode-card input[type=radio]{display:none}
.mode-name{font-family:'Syne',sans-serif;font-weight:700;font-size:14px;margin-bottom:8px}
.mode-card.active .mode-name{color:var(--accent)}
.mode-desc{font-size:11px;color:var(--muted);line-height:1.6}
.mode-tag{display:inline-block;font-size:9px;letter-spacing:1px;text-transform:uppercase;padding:2px 6px;border-radius:2px;margin-top:10px;background:#1a1a24;color:var(--muted);border:1px solid var(--border)}
.mode-card.active .mode-tag{background:#2a3300;color:var(--accent);border-color:var(--accent)}
.dropzone{border:1px dashed var(--border);border-radius:4px;padding:48px 24px;text-align:center;cursor:pointer;transition:all 0.15s;background:var(--surface);margin-bottom:32px}
.dropzone:hover,.dropzone.drag-over{border-color:var(--accent);background:#111a00}
.dropzone input{display:none}
.drop-icon{font-size:32px;margin-bottom:16px;opacity:0.4}
.drop-title{font-family:'Syne',sans-serif;font-weight:600;font-size:16px;margin-bottom:8px}
.drop-sub{font-size:11px;color:var(--muted)}.drop-sub span{color:var(--accent)}
#file-list{margin-bottom:24px;display:flex;flex-direction:column;gap:8px}
.file-item{display:flex;align-items:center;gap:12px;background:var(--surface);border:1px solid var(--border);border-radius:3px;padding:10px 14px;font-size:12px;animation:fadeIn 0.2s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:none}}
.file-ext{font-family:'Syne',sans-serif;font-weight:700;font-size:10px;letter-spacing:1px;width:36px;text-align:center;padding:2px 0;border-radius:2px;flex-shrink:0}
.ext-txt{background:#1a2a1a;color:var(--success)}.ext-pdf{background:#2a1a1a;color:#ff9966}
.ext-docx{background:#1a1a2a;color:var(--accent2)}.ext-csv,.ext-xlsx{background:#2a2a1a;color:var(--accent)}
.ext-sql{background:#2a1a2a;color:#cc88ff}
.file-name{flex:1;color:var(--text)}.file-size{color:var(--muted);font-size:11px}
.file-remove{color:var(--muted);cursor:pointer;font-size:14px;padding:0 4px;transition:color 0.1s}
.file-remove:hover{color:var(--danger)}
.btn-redact{width:100%;background:var(--accent);color:#0a0a0f;border:none;padding:16px 32px;font-family:'Syne',sans-serif;font-weight:700;font-size:14px;letter-spacing:1px;text-transform:uppercase;cursor:pointer;border-radius:3px;transition:all 0.15s}
.btn-redact:hover:not(:disabled){background:#f5ff80;transform:translateY(-1px)}
.btn-redact:disabled{opacity:0.3;cursor:not-allowed;transform:none}
#progress-panel{display:none;margin-top:32px;background:var(--surface);border:1px solid var(--border);border-radius:4px;overflow:hidden}
.progress-header{padding:16px 20px;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:10px;font-family:'Syne',sans-serif;font-weight:600;font-size:13px}
.spinner{width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin 0.6s linear infinite;flex-shrink:0}
@keyframes spin{to{transform:rotate(360deg)}}
.progress-bar-wrap{padding:20px;border-bottom:1px solid var(--border)}
.progress-bar-track{background:var(--surface2);border-radius:2px;height:4px;overflow:hidden}
.progress-bar-fill{height:100%;background:var(--accent);border-radius:2px;width:0%;transition:width 0.4s ease}
.progress-label{font-size:11px;color:var(--muted);margin-top:8px}
#results-panel{display:none;margin-top:32px}
.results-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.btn-download{background:transparent;border:1px solid var(--accent);color:var(--accent);padding:10px 20px;font-family:'Syne',sans-serif;font-weight:600;font-size:12px;letter-spacing:1px;text-transform:uppercase;cursor:pointer;border-radius:3px;transition:all 0.15s;text-decoration:none;display:inline-flex;align-items:center;gap:8px}
.btn-download:hover{background:var(--accent);color:#0a0a0f}
.stats-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:16px}
.stat-value{font-family:'Syne',sans-serif;font-weight:800;font-size:28px;color:var(--accent);line-height:1;margin-bottom:4px}
.stat-label{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted)}
table{width:100%;border-collapse:collapse;font-size:12px}
thead tr{border-bottom:1px solid var(--border)}
th{text-align:left;padding:10px 12px;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);font-weight:400}
td{padding:10px 12px;border-bottom:1px solid #16161e;color:var(--text);vertical-align:top}
tr:last-child td{border-bottom:none}
tr:hover td{background:#111118}
.type-pill{display:inline-block;font-size:9px;letter-spacing:1px;text-transform:uppercase;padding:2px 6px;border-radius:2px;margin:1px;background:var(--surface2);color:var(--muted)}
.btn-new{margin-top:32px;background:transparent;border:1px solid var(--border);color:var(--muted);padding:12px 24px;font-family:'Syne',sans-serif;font-weight:600;font-size:12px;letter-spacing:1px;text-transform:uppercase;cursor:pointer;border-radius:3px;transition:all 0.15s;width:100%}
.btn-new:hover{border-color:var(--text);color:var(--text)}
.error-msg{background:#1a0a0a;border:1px solid var(--danger);color:var(--danger);padding:14px 18px;border-radius:3px;font-size:12px;margin-top:16px;display:none}
</style></head><body>
<div class="wrap">
<header>
  <div class="logo">Redact<span>IQ</span></div>
  <nav>
    {% if is_admin %}<a class="nav-link" href="/admin">Admin</a>{% endif %}
    <a class="nav-link logout" href="/logout">Logout</a>
  </nav>
</header>

<div class="section-label">01 — Select Redaction Mode</div>
<div class="modes">
  <label class="mode-card active"><input type="radio" name="mode" value="public" checked/>
    <div class="mode-name">Public</div>
    <div class="mode-desc">All PII replaced with uniform blocks. Zero length information leaked.</div>
    <div class="mode-tag">████████████</div></label>
  <label class="mode-card"><input type="radio" name="mode" value="research"/>
    <div class="mode-name">Research</div>
    <div class="mode-desc">Consistent pseudonyms. Re-linkable across documents, not re-identifiable.</div>
    <div class="mode-tag">[NAME-R001]</div></label>
  <label class="mode-card"><input type="radio" name="mode" value="audit"/>
    <div class="mode-name">Audit</div>
    <div class="mode-desc">Type labels only. Identity stripped, operational data preserved.</div>
    <div class="mode-tag">[NAME][EMAIL]</div></label>
</div>

<div class="section-label">02 — Upload Files</div>
<div class="dropzone" id="dropzone">
  <input type="file" id="file-input" multiple accept=".txt,.pdf,.docx,.csv,.xlsx,.sql"/>
  <div class="drop-icon">⬆</div>
  <div class="drop-title">Drop files here or click to browse</div>
  <div class="drop-sub">Supports <span>.txt .pdf .docx .csv .xlsx .sql</span> — up to 100 MB total</div>
</div>
<div id="file-list"></div>
<button class="btn-redact" id="btn-redact" disabled>Redact Files</button>
<div class="error-msg" id="error-msg"></div>

<div id="progress-panel">
  <div class="progress-header"><div class="spinner"></div><span id="progress-title">Processing…</span></div>
  <div class="progress-bar-wrap">
    <div class="progress-bar-track"><div class="progress-bar-fill" id="progress-fill"></div></div>
    <div class="progress-label" id="progress-label">Starting…</div>
  </div>
</div>

<div id="results-panel">
  <div class="results-header">
    <div>
      <div class="section-label" style="margin-bottom:4px">03 — Results</div>
      <div style="font-family:'Syne',sans-serif;font-weight:700;font-size:18px">Redaction complete</div>
    </div>
    <a class="btn-download" id="btn-download" href="#">↓ Download ZIP</a>
  </div>
  <div class="stats-grid" id="stats-grid"></div>
  <table><thead><tr><th>File</th><th>Types detected</th><th>Redactions</th><th>Status</th></tr></thead>
  <tbody id="results-body"></tbody></table>
  <button class="btn-new" id="btn-new">← Redact more files</button>
</div>
</div>

<script>
const dropzone=document.getElementById('dropzone'),fileInput=document.getElementById('file-input'),
      fileList=document.getElementById('file-list'),btnRedact=document.getElementById('btn-redact'),
      errorMsg=document.getElementById('error-msg');
let selectedFiles=[];
document.querySelectorAll('.mode-card').forEach(card=>{
  card.addEventListener('click',()=>{
    document.querySelectorAll('.mode-card').forEach(c=>c.classList.remove('active'));
    card.classList.add('active');
  });
});
dropzone.addEventListener('click',()=>fileInput.click());
dropzone.addEventListener('dragover',e=>{e.preventDefault();dropzone.classList.add('drag-over')});
dropzone.addEventListener('dragleave',()=>dropzone.classList.remove('drag-over'));
dropzone.addEventListener('drop',e=>{e.preventDefault();dropzone.classList.remove('drag-over');addFiles([...e.dataTransfer.files])});
fileInput.addEventListener('change',()=>addFiles([...fileInput.files]));
function addFiles(files){files.forEach(f=>{if(!selectedFiles.find(x=>x.name===f.name&&x.size===f.size))selectedFiles.push(f)});renderFileList()}
function renderFileList(){
  fileList.innerHTML='';
  selectedFiles.forEach((f,i)=>{
    const ext=f.name.split('.').pop().toLowerCase();
    const sz=f.size>1024*1024?(f.size/1024/1024).toFixed(1)+' MB':(f.size/1024).toFixed(0)+' KB';
    const div=document.createElement('div');div.className='file-item';
    div.innerHTML=`<span class="file-ext ext-${ext}">${ext.toUpperCase()}</span><span class="file-name">${f.name}</span><span class="file-size">${sz}</span><span class="file-remove" data-i="${i}">✕</span>`;
    fileList.appendChild(div);
  });
  fileList.querySelectorAll('.file-remove').forEach(btn=>btn.addEventListener('click',()=>{selectedFiles.splice(+btn.dataset.i,1);renderFileList()}));
  btnRedact.disabled=selectedFiles.length===0;
}
btnRedact.addEventListener('click',async()=>{
  const mode=document.querySelector('input[name=mode]:checked').value;
  const fd=new FormData();fd.append('mode',mode);
  selectedFiles.forEach(f=>fd.append('files',f));
  errorMsg.style.display='none';btnRedact.disabled=true;
  document.getElementById('progress-panel').style.display='block';
  setProgress(5,'Uploading files…');
  let jobId;
  try{const res=await fetch('/api/redact',{method:'POST',body:fd});const data=await res.json();
    if(!res.ok)throw new Error(data.error||'Upload failed');jobId=data.job_id;}
  catch(e){showError(e.message);return;}
  setProgress(15,'Scanning for PII…');
  await pollJob(jobId);
});
async function pollJob(jobId){
  const msgs=['Scanning for PII patterns…','Running regex detection…','Applying name gazetteer…','Redacting structured fields…','Finalising output…'];
  let msgIdx=0;
  const iv=setInterval(async()=>{
    try{const res=await fetch(`/api/job/${jobId}`);const data=await res.json();
      if(data.status==='done'){clearInterval(iv);setProgress(100,'Complete!');setTimeout(()=>showResults(jobId,data),400);}
      else if(data.status==='error'){clearInterval(iv);showError(data.error||'Failed');}
      else{const pct=Math.min(15+(data.progress||0)*0.8,90);msgIdx=Math.min(Math.floor(pct/18),msgs.length-1);setProgress(pct,msgs[msgIdx]);}
    }catch(e){}
  },600);
}
function setProgress(pct,label){document.getElementById('progress-fill').style.width=pct+'%';document.getElementById('progress-label').textContent=label;}
function showResults(jobId,data){
  document.getElementById('progress-panel').style.display='none';
  document.getElementById('results-panel').style.display='block';
  const total=data.total_redactions||0,files=data.files?data.files.length:0,types=Object.keys(data.summary||{}).length;
  document.getElementById('stats-grid').innerHTML=`
    <div class="stat-card"><div class="stat-value">${files}</div><div class="stat-label">Files processed</div></div>
    <div class="stat-card"><div class="stat-value">${total.toLocaleString()}</div><div class="stat-label">Total redactions</div></div>
    <div class="stat-card"><div class="stat-value">${types}</div><div class="stat-label">PII types found</div></div>
    <div class="stat-card"><div class="stat-value">${data.mode.toUpperCase()}</div><div class="stat-label">Mode used</div></div>`;
  const tbody=document.getElementById('results-body');tbody.innerHTML='';
  (data.files||[]).forEach(f=>{
    const pills=Object.entries(f.stats||{}).map(([t,c])=>`<span class="type-pill">${t} ×${c}</span>`).join('');
    const tot=Object.values(f.stats||{}).reduce((a,b)=>a+b,0);
    const tr=document.createElement('tr');
    tr.innerHTML=`<td style="font-family:'Syne',sans-serif;font-weight:600">${f.name}</td><td>${pills||'<span style="color:var(--muted)">none</span>'}</td><td style="color:var(--accent);font-weight:600">${tot}</td><td style="color:var(--success)">✓ done</td>`;
    tbody.appendChild(tr);
  });
  document.getElementById('btn-download').href=`/api/download/${jobId}`;
}
function showError(msg){document.getElementById('progress-panel').style.display='none';errorMsg.textContent='✕ '+msg;errorMsg.style.display='block';btnRedact.disabled=false;}
document.getElementById('btn-new').addEventListener('click',()=>{
  selectedFiles=[];renderFileList();
  document.getElementById('results-panel').style.display='none';
  document.getElementById('progress-panel').style.display='none';
  errorMsg.style.display='none';btnRedact.disabled=true;fileInput.value='';
});
</script></body></html>"""


ADMIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"/>
<title>RedactIQ — Admin</title>
<link href="https://fonts.googleapis.com/css2?family=Syne:wght@400;600;700;800&family=DM+Mono:wght@300;400;500&display=swap" rel="stylesheet"/>
<style>
:root{--bg:#0a0a0f;--surface:#111118;--surface2:#1a1a24;--border:#2a2a3a;--accent:#e8ff47;--accent2:#47c8ff;--danger:#ff4747;--text:#f0f0f8;--muted:#6b6b8a;--success:#47ffb2}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:'DM Mono',monospace;min-height:100vh}
body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(rgba(232,255,71,0.03) 1px,transparent 1px),linear-gradient(90deg,rgba(232,255,71,0.03) 1px,transparent 1px);background-size:40px 40px;pointer-events:none;z-index:0}
.wrap{position:relative;z-index:1;max-width:1100px;margin:0 auto;padding:48px 24px 80px}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:48px;padding-bottom:24px;border-bottom:1px solid var(--border)}
.logo{font-family:'Syne',sans-serif;font-weight:800;font-size:24px}.logo span{color:var(--accent)}
nav{display:flex;gap:8px}
.nav-link{font-size:11px;letter-spacing:2px;text-transform:uppercase;padding:8px 16px;border-radius:3px;text-decoration:none;border:1px solid var(--border);color:var(--muted);transition:all 0.15s}
.nav-link:hover{border-color:var(--text);color:var(--text)}
.nav-link.active{border-color:var(--accent);color:var(--accent);background:#111a00}
.nav-link.logout{border-color:var(--danger);color:var(--danger)}
.nav-link.logout:hover{background:var(--danger);color:#0a0a0f}
.tabs{display:flex;gap:4px;margin-bottom:32px;border-bottom:1px solid var(--border)}
.tab{font-size:11px;letter-spacing:2px;text-transform:uppercase;padding:12px 20px;cursor:pointer;color:var(--muted);border-bottom:2px solid transparent;margin-bottom:-1px;transition:all 0.15s;background:none;border-top:none;border-left:none;border-right:none}
.tab:hover{color:var(--text)}.tab.active{color:var(--accent);border-bottom-color:var(--accent)}
.tab-panel{display:none}.tab-panel.active{display:block}
.stats-row{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:32px}
.stat-card{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:20px}
.stat-value{font-family:'Syne',sans-serif;font-weight:800;font-size:28px;color:var(--accent);line-height:1;margin-bottom:4px}
.stat-label{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted)}
.section-label{font-size:10px;letter-spacing:3px;text-transform:uppercase;color:var(--muted);margin-bottom:16px}
.table-wrap{background:var(--surface);border:1px solid var(--border);border-radius:4px;overflow:hidden}
table{width:100%;border-collapse:collapse;font-size:12px}
thead tr{border-bottom:1px solid var(--border)}
th{text-align:left;padding:12px 16px;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted);font-weight:400}
td{padding:11px 16px;border-bottom:1px solid #16161e;color:var(--text);vertical-align:middle}
tr:last-child td{border-bottom:none}tr:hover td{background:#111118}
.mode-badge{display:inline-block;font-size:9px;letter-spacing:1px;text-transform:uppercase;padding:3px 8px;border-radius:2px;font-weight:600}
.mode-public{background:#2a3300;color:var(--accent);border:1px solid var(--accent)}
.mode-research{background:#00202a;color:var(--accent2);border:1px solid var(--accent2)}
.mode-audit{background:#2a002a;color:#cc88ff;border:1px solid #cc88ff}
.role-badge{display:inline-block;font-size:9px;letter-spacing:1px;text-transform:uppercase;padding:3px 8px;border-radius:2px}
.role-admin{background:#2a3300;color:var(--accent);border:1px solid var(--accent)}
.role-analyst{background:var(--surface2);color:var(--muted);border:1px solid var(--border)}
.btn-sm{font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:6px 12px;border-radius:2px;text-decoration:none;border:1px solid var(--border);color:var(--muted);transition:all 0.15s;display:inline-block;cursor:pointer;background:none;margin-right:4px;font-family:'DM Mono',monospace}
.btn-sm:hover{border-color:var(--accent);color:var(--accent)}
.btn-sm.orig:hover{border-color:var(--accent2);color:var(--accent2)}
.btn-sm.del:hover{border-color:var(--danger);color:var(--danger)}
.add-user-form{background:var(--surface);border:1px solid var(--border);border-radius:4px;padding:24px;margin-bottom:24px;display:flex;gap:12px;align-items:flex-end;flex-wrap:wrap}
.fg{display:flex;flex-direction:column;gap:6px}
.fg label{font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--muted)}
.fg input,.fg select{background:#0a0a0f;border:1px solid var(--border);color:var(--text);padding:9px 12px;font-family:'DM Mono',monospace;font-size:12px;border-radius:3px;outline:none}
.fg input:focus,.fg select:focus{border-color:var(--accent)}
.btn-add{background:var(--accent);color:#0a0a0f;border:none;padding:10px 20px;font-family:'Syne',sans-serif;font-weight:700;font-size:11px;letter-spacing:1px;text-transform:uppercase;cursor:pointer;border-radius:3px}
.user-col{color:var(--accent2);font-weight:600}
.status-done{color:var(--success)}.status-error{color:var(--danger)}
.expand-btn{cursor:pointer;color:var(--muted);font-size:11px;user-select:none}
.expand-btn:hover{color:var(--text)}
.file-detail{display:none}.file-detail.open{display:table-row}
.file-detail td{padding:0 16px 12px}
.file-sub{background:var(--surface2);border-radius:3px;padding:12px;font-size:11px}
.file-row{display:flex;justify-content:space-between;padding:4px 0;border-bottom:1px solid var(--border)}
.file-row:last-child{border-bottom:none}
</style></head><body>
<div class="wrap">
<header>
  <div class="logo">Redact<span>IQ</span> <span style="font-size:12px;color:var(--muted);font-weight:400">Admin</span></div>
  <nav>
    <a class="nav-link" href="/">Redact</a>
    <a class="nav-link active" href="/admin">Admin</a>
    <a class="nav-link logout" href="/logout">Logout</a>
  </nav>
</header>
<div class="tabs">
  <button class="tab active" onclick="switchTab('jobs')">Jobs</button>
  <button class="tab" onclick="switchTab('users')">Users</button>
</div>

<!-- JOBS -->
<div class="tab-panel active" id="tab-jobs">
  <div class="stats-row" id="stats-row"></div>
  <div class="section-label">All Redaction Jobs</div>
  <div class="table-wrap"><table>
    <thead><tr><th>Job ID</th><th>Timestamp</th><th>Run By</th><th>Mode</th><th>Files</th><th>Redactions</th><th>Status</th><th>Downloads</th></tr></thead>
    <tbody id="jobs-tbody"></tbody>
  </table></div>
</div>

<!-- USERS -->
<div class="tab-panel" id="tab-users">
  <div class="section-label">Add User</div>
  <div class="add-user-form">
    <div class="fg"><label>Username</label><input type="text" id="new-username" placeholder="username"/></div>
    <div class="fg"><label>Password</label><input type="password" id="new-password" placeholder="password"/></div>
    <div class="fg"><label>Role</label><select id="new-role"><option value="analyst">Analyst</option><option value="admin">Admin</option></select></div>
    <button class="btn-add" onclick="addUser()">Add User</button>
  </div>
  <div class="section-label">All Users</div>
  <div class="table-wrap"><table>
    <thead><tr><th>Username</th><th>Role</th><th>Created</th><th>Actions</th></tr></thead>
    <tbody id="users-tbody"></tbody>
  </table></div>
</div>
</div>

<script>
function switchTab(name){
  document.querySelectorAll('.tab').forEach((t,i)=>t.classList.remove('active'));
  document.querySelectorAll('.tab-panel').forEach(p=>p.classList.remove('active'));
  const idx=name==='jobs'?0:1;
  document.querySelectorAll('.tab')[idx].classList.add('active');
  document.getElementById('tab-'+name).classList.add('active');
}
async function loadJobs(){
  const res=await fetch('/api/logs');const data=await res.json();const jobs=data.jobs||[];
  const totalR=jobs.reduce((a,b)=>a+(b.total_redactions||0),0);
  const totalF=jobs.reduce((a,b)=>a+(b.file_count||0),0);
  const users=new Set(jobs.map(j=>j.run_by)).size;
  document.getElementById('stats-row').innerHTML=`
    <div class="stat-card"><div class="stat-value">${jobs.length}</div><div class="stat-label">Total jobs</div></div>
    <div class="stat-card"><div class="stat-value">${totalF}</div><div class="stat-label">Files processed</div></div>
    <div class="stat-card"><div class="stat-value">${totalR.toLocaleString()}</div><div class="stat-label">Total redactions</div></div>
    <div class="stat-card"><div class="stat-value">${users}</div><div class="stat-label">Active users</div></div>`;
  const tbody=document.getElementById('jobs-tbody');tbody.innerHTML='';
  jobs.forEach(job=>{
    const files=typeof job.files==='string'?JSON.parse(job.files):(job.files||[]);
    const ts=(job.timestamp||'—').replace('T',' ');
    const sCls=job.status==='done'?'status-done':'status-error';
    const sTxt=job.status==='done'?'✓ done':'✕ error';
    const dlR=job.status==='done'?`<a class="btn-sm" href="/api/download/${job.job_id}">↓ Redacted</a>`:'';
    const dlO=`<a class="btn-sm orig" href="/api/download/original/${job.job_id}">↓ Original</a>`;
    const rid='d-'+job.job_id;
    const tr=document.createElement('tr');
    tr.innerHTML=`
      <td style="font-family:'Syne',sans-serif;font-weight:700;color:var(--accent2)">${job.job_id}</td>
      <td style="color:var(--muted)">${ts}</td>
      <td class="user-col">${job.run_by||'—'}</td>
      <td><span class="mode-badge mode-${job.mode}">${job.mode}</span></td>
      <td>${job.file_count||0}</td>
      <td style="color:var(--accent);font-weight:600">${(job.total_redactions||0).toLocaleString()}</td>
      <td class="${sCls}">${sTxt}</td>
      <td>${dlR}${dlO}<span class="expand-btn" onclick="toggle('${rid}')"> ▾</span></td>`;
    tbody.appendChild(tr);
    const det=document.createElement('tr');det.className='file-detail';det.id=rid;
    const fRows=files.map(f=>{
      const ft=Object.values(f.stats||{}).reduce((a,b)=>a+b,0);
      return `<div class="file-row"><span>${f.name}</span><span style="color:var(--accent)">${ft} redactions</span></div>`;
    }).join('');
    det.innerHTML=`<td colspan="8"><div class="file-sub">${fRows||'No detail'}</div></td>`;
    tbody.appendChild(det);
  });
}
async function loadUsers(){
  const res=await fetch('/api/admin/users');const data=await res.json();
  const tbody=document.getElementById('users-tbody');tbody.innerHTML='';
  (data.users||[]).forEach(u=>{
    const tr=document.createElement('tr');
    tr.innerHTML=`
      <td class="user-col">${u.username}</td>
      <td><span class="role-badge role-${u.role}">${u.role}</span></td>
      <td style="color:var(--muted)">${(u.created_at||'—').replace('T',' ')}</td>
      <td><button class="btn-sm del" onclick="deleteUser('${u.username}')">Delete</button></td>`;
    tbody.appendChild(tr);
  });
}
async function addUser(){
  const username=document.getElementById('new-username').value.trim();
  const password=document.getElementById('new-password').value;
  const role=document.getElementById('new-role').value;
  if(!username||!password)return alert('Username and password required');
  const res=await fetch('/api/admin/users',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,role})});
  const data=await res.json();
  if(data.error)return alert(data.error);
  document.getElementById('new-username').value='';
  document.getElementById('new-password').value='';
  loadUsers();
}
async function deleteUser(u){
  if(!confirm('Delete user "'+u+'"?'))return;
  await fetch('/api/admin/users/'+u,{method:'DELETE'});loadUsers();
}
function toggle(id){document.getElementById(id).classList.toggle('open')}
loadJobs();loadUsers();
</script></body></html>"""


# ── Routes ─────────────────────────────────────────────────────

@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username","").strip()
        password = request.form.get("password","")
        con = sqlite3.connect(str(DB_PATH))
        row = con.execute("SELECT password_hash FROM users WHERE username=?", (username,)).fetchone()
        con.close()
        if row and row[0] == hash_pw(password):
            session["username"] = username
            return redirect("/")
        error = "Invalid username or password"
    return render_template_string(LOGIN_HTML, error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

@app.route("/")
@login_required
def index():
    con = sqlite3.connect(str(DB_PATH))
    row = con.execute("SELECT role FROM users WHERE username=?", (session["username"],)).fetchone()
    con.close()
    is_admin = row and row[0] == "admin"
    return render_template_string(MAIN_HTML, is_admin=is_admin)

@app.route("/admin")
@login_required
def admin_page():
    con = sqlite3.connect(str(DB_PATH))
    row = con.execute("SELECT role FROM users WHERE username=?", (session["username"],)).fetchone()
    con.close()
    if not row or row[0] != "admin":
        return redirect("/")
    return render_template_string(ADMIN_HTML)

@app.route("/api/redact", methods=["POST"])
@login_required
def api_redact():
    files = request.files.getlist("files")
    mode  = request.form.get("mode","public")
    if not files or all(f.filename=="" for f in files):
        return jsonify({"error":"No files uploaded"}),400
    if mode not in ("public","research","audit"):
        return jsonify({"error":"Invalid mode"}),400
    job_id  = str(uuid.uuid4())[:8]
    job_dir = UPLOAD_DIR / job_id
    out_dir = OUTPUT_DIR / job_id
    job_dir.mkdir(parents=True); out_dir.mkdir(parents=True)
    saved = []
    for f in files:
        ext = Path(f.filename).suffix.lower()
        if ext not in ALLOWED_EXTENSIONS: continue
        f.save(str(job_dir / f.filename)); saved.append(f.filename)
    if not saved:
        return jsonify({"error":"No supported file types"}),400
    JOBS[job_id] = {
        "status":"running","progress":0,"mode":mode,
        "files":[],"total_redactions":0,"summary":{},
        "error":None,
        "timestamp":datetime.now().isoformat(timespec="seconds"),
        "run_by":session.get("username","unknown"),
    }
    threading.Thread(target=run_job, args=(job_id,job_dir,out_dir,mode), daemon=True).start()
    return jsonify({"job_id":job_id})

def run_job(job_id, job_dir, out_dir, mode):
    job = JOBS[job_id]
    try:
        from redactor import READERS, VAULT, PseudonymVault, auto_scan, redact_text, load_schema, WRITERS
        import redactor as _r
        _r.VAULT = PseudonymVault()
        schema = load_schema()
        # Check total size of uploaded files
        total_size = sum(p.stat().st_size for p in job_dir.iterdir())
        if total_size > 1_000_000:  # 1MB threshold
            known_names = set()
        else:
            schema, known_names = auto_scan(job_dir, schema)
        paths = sorted(p for p in job_dir.iterdir() if p.suffix.lower() in READERS)
        n = len(paths); total = 0; summary = {}; results = []
        for i, path in enumerate(paths):
            job["progress"] = int((i/n)*100)
            text = READERS[path.suffix.lower()](path)
            redacted, stats = redact_text(text, mode, known_names, schema)
            out_path = out_dir / (path.stem + f"_{mode}" + path.suffix)
            writer = WRITERS.get(path.suffix.lower())
            if writer: writer(redacted, out_path, path, mode=mode, known_names=known_names)
            else:
                from redactor import write_txt
                write_txt(redacted, out_path.with_suffix(".txt"))
            file_total = sum(stats.values()); total += file_total
            for k,v in stats.items(): summary[k] = summary.get(k,0)+v
            results.append({"name":path.name,"stats":stats})
        job.update({"status":"done","progress":100,"files":results,"total_redactions":total,"summary":summary})
        db_save(job_id, job)
    except Exception as e:
        import traceback; traceback.print_exc()
        job.update({"status":"error","error":str(e)})
        db_save(job_id, job)

@app.route("/api/job/<job_id>")
@login_required
def api_job_status(job_id):
    job = JOBS.get(job_id)
    if not job: return jsonify({"error":"Not found"}),404
    return jsonify(job)

@app.route("/api/download/<job_id>")
@login_required
def api_download(job_id):
    out_dir = OUTPUT_DIR / job_id
    if not out_dir.exists(): return "Not found",404
    zip_path = OUTPUT_DIR / f"{job_id}_redacted.zip"
    with zipfile.ZipFile(str(zip_path),"w",zipfile.ZIP_DEFLATED) as zf:
        for f in out_dir.iterdir(): zf.write(str(f),f.name)
    return send_file(str(zip_path),as_attachment=True,download_name=f"redacted_{job_id}.zip",mimetype="application/zip")

@app.route("/api/download/original/<job_id>")
@login_required
def api_download_original(job_id):
    upload_dir = UPLOAD_DIR / job_id
    if not upload_dir.exists(): return "Original files not found",404
    zip_path = OUTPUT_DIR / f"{job_id}_original.zip"
    with zipfile.ZipFile(str(zip_path),"w",zipfile.ZIP_DEFLATED) as zf:
        for f in upload_dir.iterdir(): zf.write(str(f),f.name)
    return send_file(str(zip_path),as_attachment=True,download_name=f"original_{job_id}.zip",mimetype="application/zip")

@app.route("/api/logs")
@login_required
def api_logs():
    return jsonify({"jobs":db_all_jobs()})

@app.route("/api/admin/users", methods=["GET"])
@login_required
def api_get_users():
    return jsonify({"users":db_all_users()})

@app.route("/api/admin/users", methods=["POST"])
@login_required
def api_add_user():
    data = request.get_json()
    username = data.get("username","").strip()
    password = data.get("password","")
    role     = data.get("role","analyst")
    if not username or not password:
        return jsonify({"error":"Username and password required"}),400
    try:
        con = sqlite3.connect(str(DB_PATH))
        con.execute("INSERT INTO users VALUES (?,?,?,?)",
            (username, hash_pw(password), role, datetime.now().isoformat(timespec="seconds")))
        con.commit(); con.close()
        return jsonify({"ok":True})
    except sqlite3.IntegrityError:
        return jsonify({"error":"Username already exists"}),400

@app.route("/api/admin/users/<username>", methods=["DELETE"])
@login_required
def api_delete_user(username):
    con = sqlite3.connect(str(DB_PATH))
    con.execute("DELETE FROM users WHERE username=?",(username,))
    con.commit(); con.close()
    return jsonify({"ok":True})

if __name__ == "__main__":
    print("\n  RedactIQ running → http://localhost:5000")
    print("  Default login: admin / admin123\n")
    app.run(debug=False, host="0.0.0.0", port=5000, threaded=True)
