let token = "";
const out = (x) => document.getElementById("out").textContent = JSON.stringify(x, null, 2);
const body = () => ({name:name.value,email:email.value,password:password.value,role:role.value});
async function signup(){let r=await fetch('/api/auth/signup',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body())});let j=await r.json();token=j.token||'';out(j)}
async function login(){let r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:email.value,password:password.value})});let j=await r.json();token=j.token||'';out(j)}
async function createProject(){let r=await fetch('/api/projects',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({name:pname.value})});out(await r.json())}
