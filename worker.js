export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Auth-Email, X-Auth-Key",
      "Access-Control-Max-Age": "86400",
    };

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });

    // API Logic
    if (url.pathname.startsWith('/api/')) {
      try {
        // Ambil auth dari headers (lebih aman & fleksibel)
        const authEmail = request.headers.get("X-Auth-Email");
        const authKey = request.headers.get("X-Auth-Key");

        if (!authEmail || !authKey) throw new Error("Email atau API Key tidak ditemukan di header.");

        const commonHeaders = {
          "X-Auth-Email": authEmail,
          "X-Auth-Key": authKey,
          "Content-Type": "application/json"
        };

        // Helper: Dapatkan Account ID (karena hampir semua endpoint butuh ini)
        const getAccountId = async () => {
          const res = await fetch("https://api.cloudflare.com/client/v4/accounts", { headers: commonHeaders });
          const data = await res.json();
          if (!data.success) throw new Error("Gagal login API Cloudflare. Cek Email/Key.");
          return data.result[0].id;
        };

        // 1. List Workers
        if (url.pathname === '/api/list') {
          const accountId = await getAccountId();
          const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts`, { headers: commonHeaders });
          const data = await res.json();
          return new Response(JSON.stringify(data), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // 2. Get Script Code
        if (url.pathname === '/api/get') {
          const workerName = url.searchParams.get("name");
          const accountId = await getAccountId();
          const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}`, { headers: commonHeaders });
          const scriptContent = await res.text();
          // Note: Cloudflare mengembalikan raw text untuk script
          return new Response(JSON.stringify({ success: true, code: scriptContent }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // 3. Deploy/Update Script
        if (url.pathname === '/api/update') {
          const { name, code } = await request.json();
          const accountId = await getAccountId();

          const formData = new FormData();
          formData.append("metadata", JSON.stringify({ main_module: "worker.js", compatibility_date: "2024-01-01" }));
          formData.append("worker.js", new Blob([code], { type: "application/javascript+module" }));

          const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${name}`, {
            method: "PUT",
            headers: { "X-Auth-Email": authEmail, "X-Auth-Key": authKey },
            body: formData
          });
          const data = await res.json();
          return new Response(JSON.stringify(data), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

      } catch (e) {
        return new Response(JSON.stringify({ success: false, errors: [{ message: e.message }] }), { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
      }
    }

    // Serve HTML
    const html = `
    <!DOCTYPE html>
    <html lang="id">
    <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>CF Multi-Account Editor</title>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
      <style>
        :root { --bg: #0d1117; --card: #161b22; --blue: #58a6ff; --border: #30363d; --green: #238636; --red: #da3633; }
        body { font-family: -apple-system, system-ui, sans-serif; background: var(--bg); color: #c9d1d9; margin: 0; padding: 10px; line-height: 1.4; }
        .container { max-width: 900px; margin: auto; }
        .card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 15px; margin-bottom: 15px; }
        input, select { background: #0d1117; color: white; border: 1px solid var(--border); padding: 12px; border-radius: 6px; width: 100%; box-sizing: border-box; margin-bottom: 10px; font-size: 14px; }
        .flex { display: flex; gap: 8px; margin-bottom: 10px; }
        button { padding: 12px 15px; border-radius: 6px; border: none; font-weight: bold; cursor: pointer; transition: 0.2s; font-size: 13px; }
        .btn-blue { background: var(--blue); color: #fff; }
        .btn-green { background: var(--green); color: #fff; }
        .btn-red { background: var(--red); color: #fff; }
        .btn-outline { background: transparent; border: 1px solid var(--border); color: #c9d1d9; }
        button:active { opacity: 0.7; transform: scale(0.98); }
        .editor-container { position: relative; height: 60vh; border: 1px solid var(--border); border-radius: 8px; overflow: hidden; background: #1d1d1d; }
        #editor, #highlighting { margin: 0; padding: 15px; width: 100%; height: 100%; position: absolute; top: 0; left: 0; tab-size: 2; box-sizing: border-box; font-family: 'Fira Code', monospace; font-size: 13px; line-height: 1.5; overflow: auto; white-space: pre; }
        #editor { color: transparent; background: transparent; caret-color: white; z-index: 1; resize: none; outline: none; -webkit-text-fill-color: transparent; }
        #highlighting { z-index: 0; pointer-events: none; }
        #status { margin-top: 10px; padding: 12px; border-radius: 6px; display: none; text-align: center; font-weight: bold; }
        .hidden { display: none; }
        .label { font-size: 12px; color: #8b949e; margin-bottom: 5px; display: block; }
      </style>
    </head>
    <body>
      <div class="container">
        <div class="card">
          <div style="display:flex; justify-content: space-between; align-items: center; margin-bottom: 15px;">
            <strong style="color: var(--blue); font-size: 18px;">⚡ Worker Editor</strong>
          </div>
          
          <label class="label">Pilih Akun Cloudflare:</label>
          <select id="accSelector" onchange="switchAccount()"></select>
          
          <div id="addAccForm" class="hidden">
            <input id="accEmail" type="email" placeholder="Email Akun Cloudflare">
            <input id="accKey" type="password" placeholder="Global API Key">
            <div class="flex">
              <button onclick="saveAccount()" class="btn-green" style="flex:1">Simpan</button>
              <button onclick="toggleAddForm()" class="btn-outline" style="flex:1">Batal</button>
            </div>
          </div>
          
          <div class="flex" id="accActionBtns">
            <button onclick="toggleAddForm()" class="btn-outline" style="flex:1">+ Akun Baru</button>
            <button onclick="deleteAccount()" class="btn-red">Hapus Akun</button>
          </div>
        </div>

        <div class="card">
          <label class="label">Daftar Worker:</label>
          <div class="flex">
            <select id="workerList" style="margin-bottom:0;"><option value="">Pilih Akun...</option></select>
            <button onclick="fetchList()" class="btn-blue">🔄 Refresh</button>
          </div>
        </div>

        <div class="editor-container">
          <textarea id="editor" spellcheck="false" oninput="updateView(); syncScroll();" onscroll="syncScroll();"></textarea>
          <pre id="highlighting" aria-hidden="true"><code class="language-javascript" id="highlighting-content"></code></pre>
        </div>

        <div class="flex" style="margin-top: 15px;">
          <button onclick="loadWorker()" class="btn-outline" style="flex:1; height:50px;">📥 LOAD CODE</button>
          <button onclick="saveWorker()" class="btn-green" style="flex:1; height:50px;">🚀 DEPLOY SEKARANG</button>
        </div>
        <div id="status"></div>
      </div>

      <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-javascript.min.js"></script>
      
      <script>
        const $ = id => document.getElementById(id);
        let accounts = JSON.parse(localStorage.getItem('cf_accounts_v2') || '[]');
        let currentAcc = null;

        function toggleAddForm() { 
          $('addAccForm').classList.toggle('hidden');
          $('accActionBtns').classList.toggle('hidden');
        }

        function updateAccSelector() {
          if(accounts.length === 0) {
            $('accSelector').innerHTML = '<option value="-1">Belum ada akun</option>';
            currentAcc = null;
          } else {
            $('accSelector').innerHTML = accounts.map((a, i) => \`<option value="\${i}">\${a.email}</option>\`).join('');
            switchAccount();
          }
        }

        function switchAccount() {
          const idx = $('accSelector').value;
          if(idx !== "-1") {
            currentAcc = accounts[idx];
            fetchList();
          }
        }

        function saveAccount() {
          const email = $('accEmail').value.trim();
          const key = $('accKey').value.trim();
          if(!email || !key) return alert("Isi Email dan Global Key!");
          accounts.push({ email, key });
          localStorage.setItem('cf_accounts_v2', JSON.stringify(accounts));
          toggleAddForm();
          updateAccSelector();
        }

        function deleteAccount() {
          const idx = $('accSelector').value;
          if(idx === "-1" || !confirm("Hapus akun ini?")) return;
          accounts.splice(idx, 1);
          localStorage.setItem('cf_accounts_v2', JSON.stringify(accounts));
          updateAccSelector();
        }

        async function fetchList() {
          if(!currentAcc) return;
          $('workerList').innerHTML = '<option>Loading...</option>';
          try {
            const res = await fetch('/api/list', {
              headers: { 'X-Auth-Email': currentAcc.email, 'X-Auth-Key': currentAcc.key }
            });
            const d = await res.json();
            if(d.success) {
              $('workerList').innerHTML = d.result.map(w => \`<option value="\${w.id}">\${w.id}</option>\`).join('');
            } else {
              throw new Error(d.errors?.[0]?.message || "Gagal load");
            }
          } catch(e) { 
            notify(e.message, true);
            $('workerList').innerHTML = '<option>Gagal memuat</option>';
          }
        }

        async function loadWorker() {
          const name = $('workerList').value;
          if(!name || !currentAcc) return notify("Pilih worker dulu", true);
          notify("Mengambil kode...");
          try {
            const res = await fetch('/api/get?name=' + name, {
              headers: { 'X-Auth-Email': currentAcc.email, 'X-Auth-Key': currentAcc.key }
            });
            const d = await res.json();
            $('editor').value = d.code;
            updateView();
            notify("Kode dimuat!");
          } catch(e) { notify("Gagal ambil kode", true); }
        }

        async function saveWorker() {
          const name = $('workerList').value;
          const code = $('editor').value;
          if(!name || !code) return notify("Data tidak lengkap", true);
          
          notify("Mendeploy...");
          try {
            const res = await fetch('/api/update', {
              method: 'POST',
              headers: { 
                'X-Auth-Email': currentAcc.email, 
                'X-Auth-Key': currentAcc.key,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({ name, code })
            });
            const d = await res.json();
            if(d.success) notify("✅ BERHASIL DI-DEPLOY!");
            else notify("❌ Gagal: " + d.errors[0].message, true);
          } catch(e) { notify("Network Error", true); }
        }

        function updateView() {
          let code = $('editor').value;
          if(code[code.length-1] == "\\n") code += " ";
          $('highlighting-content').textContent = code;
          Prism.highlightElement($('highlighting-content'));
        }

        function syncScroll() {
          $('highlighting').scrollTop = $('editor').scrollTop;
          $('highlighting').scrollLeft = $('editor').scrollLeft;
        }

        function notify(msg, err=false) {
          const s = $("status");
          s.style.display = "block";
          s.style.background = err ? "rgba(218,54,51,0.2)" : "rgba(35,134,54,0.2)";
          s.style.color = err ? "#f87171" : "#34d399";
          s.innerText = msg;
          if(!err) setTimeout(() => s.style.display="none", 3000);
        }

        updateAccSelector();

        $('editor').onkeydown = function(e) {
          if(e.key == 'Tab') {
            e.preventDefault();
            const s = this.selectionStart;
            this.value = this.value.substring(0, s) + "  " + this.value.substring(this.selectionEnd);
            this.selectionEnd = s + 2;
            updateView();
          }
        };
      </script>
    </body>
    </html>
    `;
    return new Response(html, { headers: { 'content-type': 'text/html;charset=UTF-8' } });
  },
};
