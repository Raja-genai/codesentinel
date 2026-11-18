
import ast, json, os, re, shutil, subprocess, tempfile, uuid, zipfile
from pathlib import Path
from collections import Counter
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from google import genai

load_dotenv()

app = FastAPI(title="CodeSentinel AI", version="1.1.0")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")
TMP = Path(tempfile.gettempdir()) / "codesentinel"
TMP.mkdir(exist_ok=True)
HTML = """<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>CodeSentinel AI</title><style>*{box-sizing:border-box}body{margin:0;background:#0b1018;color:#edf3f8;font:15px system-ui}main{max-width:950px;margin:auto;padding:28px 20px}nav{padding:18px 0;border-bottom:1px solid #293747;color:#a5f3c5;font-weight:800}header{text-align:center;padding:65px 0 45px}h1{font-size:clamp(40px,7vw,68px);line-height:1.05;letter-spacing:-3px}h1 em{color:#a5f3c5;font-style:normal}header p{color:#9aaaba;line-height:1.7}.panel,.issue,.metric{background:#151e29;border:1px solid #2b3949;border-radius:12px;padding:20px;margin:12px 0}.tabs{display:flex;gap:10px;margin:20px 0}button{border:0;border-radius:7px;padding:12px 16px;background:#a5f3c5;color:#102018;font-weight:800;cursor:pointer}button.secondary{background:#263647;color:#dce8f4}input{padding:13px;background:#0b121b;border:1px solid #405064;color:white;border-radius:7px;flex:1;min-width:0}label{font:11px monospace;color:#a5f3c5;display:block;margin:12px 0}.input{display:flex;gap:10px}.hide{display:none!important}.muted{color:#91a0b1;font-size:12px}.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:9px}.metric{margin:0}.metric b{font-size:27px;display:block}.metric span{font:10px monospace;color:#a1afbe}.critical,.high{color:#ff9999}.medium{color:#ffd28d}.low{color:#a5f3c5}.issue h3{margin:10px 0 5px}.fix{background:#1a2b24;padding:10px;border-left:2px solid #a5f3c5;color:#c2eed0;font-size:13px}.meta{color:#91a0b1;font:11px monospace;margin:18px 0}footer{padding:45px 0;color:#78899a;font:11px monospace}@media(max-width:650px){.input{flex-direction:column}.metrics{grid-template-columns:repeat(2,1fr)}}</style></head><body><main><nav>⌘ CodeSentinel AI <span style="float:right;font:11px monospace">READ-ONLY CODE AUDIT</span></nav><header><div class="muted">ARCHITECTURE-AGNOSTIC CODE INTELLIGENCE</div><h1>Ship better code.<br><em>Leave fewer gaps.</em></h1><p>Scan repositories for security risks, code slop and unfinished work.<br>Get actionable findings with file locations and remediation guidance.</p></header><section class="panel"><h2>Connect a codebase</h2><div class="tabs"><button class="secondary" onclick="show(0)">GitHub URL</button><button class="secondary" onclick="show(1)">Upload ZIP</button></div><div id="git"><label>PUBLIC GITHUB REPOSITORY</label><div class="input"><input id="url" placeholder="https://github.com/owner/repository"><button onclick="github()">Analyze repository ↗</button></div></div><div id="zip" class="hide"><label>PROJECT ZIP ARCHIVE</label><div class="input"><input id="file" type="file" accept=".zip"><button onclick="upload()">Analyze archive ↗</button></div></div><p class="muted">✓ Read-only scan　 ✓ Static analysis works without AI　 ✓ Public repository or ZIP</p><div id="status" class="muted"></div></section><section id="results" class="hide"><h2 id="name"></h2><div id="metrics" class="metrics"></div><div id="meta" class="meta"></div><div id="issues"></div><div class="panel"><h2>Gemini AI Review</h2><p class="muted">Optional second-pass analysis of scan findings and repository structure. The report is sent to Google Gemini only when you click below.</p><button id="aiBtn" onclick="aiReview()">Generate AI insights ✦</button><div id="aiStatus" class="muted"></div><div id="aiResult"></div></div><button class="secondary" onclick="exportReport()">↓ Export JSON</button><p id="limits" class="muted"></p></section><footer>CodeSentinel AI · Hackathon MVP · Built for clarity, not false certainty.</footer></main><script>let data=null;function show(n){git.classList.toggle("hide",n===1);zip.classList.toggle("hide",n===0)}async function send(u,o){status.textContent="Scanning repository…";try{let r=await fetch(u,o),d=await r.json();if(!r.ok)throw Error(d.detail||"Scan failed");data=d;render();results.classList.remove("hide");status.textContent="Analysis complete.";results.scrollIntoView({behavior:"smooth"})}catch(e){status.textContent=e.message}}function github(){if(url.value)send("/api/scan/github",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({github_url:url.value})})}function upload(){if(file.files[0]){let f=new FormData();f.append("file",file.files[0]);send("/api/scan/upload",{method:"POST",body:f})}}function esc(s){return String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))}function render(){let s=data.summary;name.textContent=data.project+" / Audit report";metrics.innerHTML=[["Files scanned",s.files_scanned,""],["Critical",s.critical,"critical"],["High",s.high,"high"],["Medium",s.medium,"medium"],["Low",s.low,"low"]].map(x=>`<div class="metric"><b class="${x[2]}">${x[1]}</b><span>${x[0]}</span></div>`).join("");meta.textContent="LANGUAGES: "+JSON.stringify(s.languages)+" · SEMGREP: "+data.scanners.semgrep;issues.innerHTML=data.issues.length?data.issues.map(x=>`<article class="issue"><span class="${esc(x.severity)}">${esc(x.severity.toUpperCase())} · ${esc(x.category)}</span><h3>${esc(x.title)}</h3><div class="muted">${esc(x.file)}${x.line?" · line "+x.line:""}</div><p>${esc(x.detail)}</p><div class="fix"><b>Suggested action</b> · ${esc(x.recommendation)}</div></article>`).join(""):"<div class=issue>No findings detected by enabled checks.</div>";limits.textContent=data.limitations.join(" ")}async function aiReview(){aiStatus.textContent="Sending scan findings to Gemini…";aiBtn.disabled=true;try{let r=await fetch("/api/ai/analyze",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(data)}),d=await r.json();if(!r.ok)throw Error(d.detail||"AI review failed");aiResult.innerHTML=`<div class="issue"><h3>Executive summary</h3><p>${esc(d.executive_summary)}</p><h3>Architectural gaps</h3><ul>${(d.architectural_gaps||[]).map(x=>`<li>${esc(x)}</li>`).join("")}</ul><h3>Priority actions</h3><ol>${(d.priority_actions||[]).map(x=>`<li>${esc(x)}</li>`).join("")}</ol><h3>Code quality observations</h3><ul>${(d.code_quality_observations||[]).map(x=>`<li>${esc(x)}</li>`).join("")}</ul><p class="muted">${esc(d.caveat||"")}</p></div>`;aiStatus.textContent="Gemini review complete."}catch(e){aiStatus.textContent=e.message}finally{aiBtn.disabled=false}}function exportReport(){let a=document.createElement("a"),u=URL.createObjectURL(new Blob([JSON.stringify(data,null,2)],{type:"application/json"}));a.href=u;a.download=data.project+"-audit.json";a.click();URL.revokeObjectURL(u)}</script></body></html>'"""

class ScanRequest(BaseModel):
    github_url: str

EXT = {".py",".js",".jsx",".ts",".tsx",".java",".go",".rb",".php",".cs",".cpp",".c",".h",".sql",".sh",".yaml",".yml",".json",".env",".toml",".xml"}
SKIP = {".git","node_modules","venv",".venv","__pycache__","dist","build",".next","coverage"}
def finding(cat,title,sev,file,line,detail,fix):
    return {"category":cat,"title":title,"severity":sev,"file":file,"line":line,"detail":detail,"recommendation":fix}
def analyze_repository(root):
    root=Path(root).resolve(); files=[]; issues=[]
    for cur,dirs,names in os.walk(root):
        dirs[:]=[d for d in dirs if d not in SKIP and not d.startswith(".")]
        for name in names:
            p=Path(cur)/name
            if p.suffix.lower() in EXT and p.stat().st_size<=500000: files.append(p)
            if len(files)>=1500: break
        if len(files)>=1500: break
    langs=Counter(p.suffix.lower().lstrip(".") for p in files)
    secret_patterns=[(r'''(?i)(api[_-]?key|secret|access[_-]?token)\s*[:=]\s*["'][A-Za-z0-9_./+=-]{12,}["']''',"Possible hardcoded credential","critical"),(r'''(?i)(password|passwd|pwd)\s*[:=]\s*["'][^"']{4,}["']''',"Possible hardcoded password","high"),(r"-----BEGIN .*PRIVATE KEY-----","Private key embedded in source","critical"),(r"gh[pousr]_[A-Za-z0-9]{30,}","GitHub token pattern","critical"),(r"AKIA[0-9A-Z]{16}","AWS access key pattern","critical")]
    dangerous=[(r"\beval\s*\(","Dynamic eval usage","high","Avoid evaluating untrusted strings."),(r"\bexec\s*\(","Dynamic exec usage","high","Avoid executing dynamic code."),(r"verify\s*=\s*False","TLS verification disabled","high","Enable TLS certificate verification."),(r"pickle\.loads?\s*\(","Unsafe deserialization candidate","high","Never deserialize untrusted pickle data."),(r"debug\s*=\s*True","Debug mode enabled","medium","Disable debug mode in production."),(r'''allow_origins\s*=\s*\[\s*["']\*["']''',"Wildcard CORS configuration","medium","Restrict allowed origins.")]
    for p in files:
        rel=str(p.relative_to(root)).replace("\\","/")
        try: lines=p.read_text(encoding="utf-8",errors="replace").splitlines()
        except OSError: continue
        for i,line in enumerate(lines,1):
            for pat,title,sev in secret_patterns:
                if re.search(pat,line): issues.append(finding("Security",title,sev,rel,i,"Source pattern resembles a credential; verify whether it is real.","Revoke exposed credentials and use environment variables or a secret manager."))
            for pat,title,sev,fix in dangerous:
                if re.search(pat,line,re.I): issues.append(finding("Security",title,sev,rel,i,"Potentially risky API/configuration pattern detected.",fix))
            m=re.search(r"\b(TODO|FIXME|XXX|HACK|NOT IMPLEMENTED|IMPLEMENT ME)\b",line,re.I)
            if m: issues.append(finding("Completeness","Outstanding "+m.group(1).upper()+" marker","low",rel,i,line.strip()[:200],"Resolve the task or create a tracked issue."))
            if re.search(r"\breturn\s+(None|null|undefined)\s*(#.*)?$",line.strip(),re.I): issues.append(finding("Completeness","Possible placeholder return","medium",rel,i,"May return a placeholder value.","Confirm the function contract and implement intended behavior."))
            if p.suffix.lower() in {".js",".jsx",".ts",".tsx"} and "console.log(" in line: issues.append(finding("Code quality","Debug logging left in source","low",rel,i,"Console logging may expose internal data.","Remove temporary logs or use structured logging."))
        if p.suffix.lower()==".py":
            try: tree=ast.parse("\n".join(lines))
            except SyntaxError: tree=None
            if tree:
                for n in ast.walk(tree):
                    if isinstance(n,ast.FunctionDef) and len(n.body)==1 and isinstance(n.body[0],ast.Pass): issues.append(finding("Completeness","Function contains only pass","medium",rel,n.lineno,n.name+"() has no implementation.","Implement it or raise an explicit NotImplementedError."))
                    if isinstance(n,ast.ExceptHandler) and n.type is None: issues.append(finding("Code quality","Bare except clause","medium",rel,n.lineno,"Catches every exception.","Catch specific exception types."))
    top={p.name for p in root.iterdir()}
    if not top.intersection({"README.md","README","README.rst"}): issues.append(finding("Completeness","Repository README missing","low",".",0,"No top-level README found.","Document setup, purpose and usage."))
    if ".gitignore" not in top: issues.append(finding("Code quality",".gitignore missing","low",".",0,"No top-level .gitignore found.","Ignore secrets, environments, caches and build output."))
    semgrep="not installed"
    if shutil.which("semgrep"):
        try:
            p=subprocess.run(["semgrep","scan","--config","auto","--json","--quiet",str(root)],capture_output=True,text=True,timeout=25)
            if p.returncode in (0,1):
                semgrep="completed"
                for f in json.loads(p.stdout or "{}").get("results",[])[:100]:
                    ex=f.get("extra",{}); sev=str(ex.get("severity","WARNING")).lower()
                    issues.append(finding("Security",ex.get("message","Semgrep finding"),"high" if sev=="error" else "medium",f.get("path","?"),f.get("start",{}).get("line",0),ex.get("message","Static analysis finding"),"Review rule guidance and validate in context."))
        except Exception: semgrep="error"
    unique={(x["category"],x["title"],x["file"],x["line"]):x for x in issues}; issues=list(unique.values())
    order={"critical":0,"high":1,"medium":2,"low":3}; issues.sort(key=lambda x:(order[x["severity"]],x["file"],x["line"]))
    c=Counter(x["severity"] for x in issues)
    return {"project":root.name,"summary":{"files_scanned":len(files),"languages":dict(langs),"total_issues":len(issues),"critical":c["critical"],"high":c["high"],"medium":c["medium"],"low":c["low"]},"scanners":{"built_in_heuristics":"completed","python_ast":"completed","semgrep":semgrep},"issues":issues,"limitations":["Hackathon MVP, not a formal security audit.","Heuristic findings can be false positives or miss context-dependent vulnerabilities; validate each result.","Supported text files only, max 500 KB each and 1,500 files.","Scanning is read-only; repository code is never executed."]}

@app.get("/",response_class=HTMLResponse)
def home(): return HTML
class AIReviewRequest(BaseModel):
    project: str
    summary: dict
    scanners: dict
    issues: list[dict]
    limitations: list[str] = []

@app.post("/api/ai/analyze")
def ai_analyze(req: AIReviewRequest):
    api_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise HTTPException(503, "Gemini is not configured. Add GEMINI_API_KEY to your .env file and restart the server.")
    # Send only the scan report, not the repository's source code.
    report = {
        "project": req.project,
        "summary": req.summary,
        "scanners": req.scanners,
        "file_level_findings": req.issues[:100],
        "limitations": req.limitations,
    }
    prompt = """You are a pragmatic senior application-security and software-quality reviewer.
Analyze this architecture-agnostic static code scan report. Do not claim vulnerabilities are confirmed; distinguish evidence from hypotheses. Identify likely architectural/completeness gaps only when supported by the report, and say when evidence is insufficient. Do not invent files, frameworks, or dependencies. Return valid JSON only with exactly these keys:
{
  "executive_summary": "2-4 concise sentences",
  "architectural_gaps": ["evidence-grounded observations; if none can be inferred, say so"],
  "priority_actions": ["specific, ordered actions"],
  "code_quality_observations": ["concise observations"],
  "caveat": "state that this is advisory and findings require human validation"
}
Keep the output concise and useful for a hackathon demo.

SCAN REPORT:
""" + json.dumps(report, ensure_ascii=False)
    try:
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(model=GEMINI_MODEL, contents=prompt)
        raw = (response.text or "").strip()
        raw = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw, flags=re.I)
        result = json.loads(raw)
        required = ["executive_summary", "architectural_gaps", "priority_actions", "code_quality_observations", "caveat"]
        if not all(k in result for k in required):
            raise ValueError("Gemini response did not contain the expected fields")
        return result
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(502, f"Gemini request failed: {type(exc).__name__}. Check your API key, model access and quota.")

@app.get("/api/health")
def health(): return {"status":"ok", "gemini_configured": bool(os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY"))}
@app.post("/api/scan/github")
def github_scan(req:ScanRequest):
    url=req.github_url.strip()
    if not re.fullmatch(r"https://github\.com/[\w.-]+/[\w.-]+(?:\.git)?/?",url,re.I): raise HTTPException(400,"Use https://github.com/owner/repo")
    dest=TMP/uuid.uuid4().hex
    try:
        p=subprocess.run(["git","clone","--depth","1",url,str(dest)],capture_output=True,text=True,timeout=45)
        if p.returncode: raise HTTPException(400,"Clone failed. Check URL and ensure repository is public.")
        return analyze_repository(dest)
    except subprocess.TimeoutExpired: raise HTTPException(408,"Clone timed out. Try ZIP upload.")
    finally: shutil.rmtree(dest,ignore_errors=True)
@app.post("/api/scan/upload")
async def upload_scan(file:UploadFile=File(...)):
    if not file.filename or not file.filename.lower().endswith(".zip"): raise HTTPException(400,"Upload a ZIP archive.")
    job=TMP/uuid.uuid4().hex;job.mkdir()
    try:
        data=await file.read()
        if len(data)>20_000_000: raise HTTPException(413,"ZIP upload limit is 20 MB.")
        archive=job/"input.zip";archive.write_bytes(data);target=job/"repo";target.mkdir();total=0
        with zipfile.ZipFile(archive) as z:
            for info in z.infolist():
                dest=(target/info.filename).resolve()
                if not str(dest).startswith(str(target.resolve())+os.sep): raise HTTPException(400,"Unsafe ZIP path.")
                total+=info.file_size
                if total>50_000_000: raise HTTPException(413,"Extracted ZIP exceeds 50 MB.")
            z.extractall(target)
        children=list(target.iterdir()); repo=children[0] if len(children)==1 and children[0].is_dir() else target
        return analyze_repository(repo)
    finally: shutil.rmtree(job,ignore_errors=True)
