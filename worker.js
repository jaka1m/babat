export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Auth-Email, X-Auth-Key",
      "Access-Control-Max-Age": "86400",
    };

    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders });

    // ENDPOINT IMPORT (tidak perlu auth - biar bisa import dari mana saja)
    if (url.pathname === '/api/import' && request.method === 'POST') {
      try {
        const { importUrl } = await request.json();
        if (!importUrl) {
          return new Response(JSON.stringify({ success: false, error: "URL diperlukan" }), {
            status: 400,
            headers: { ...corsHeaders, "Content-Type": "application/json" }
          });
        }
        
        console.log("Importing from:", importUrl);
        const res = await fetch(importUrl);
        
        if (!res.ok) {
          throw new Error(`HTTP ${res.status}: Gagal mengambil file dari ${importUrl}`);
        }
        
        const code = await res.text();
        return new Response(JSON.stringify({ success: true, code }), {
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      } catch (e) {
        console.error("Import error:", e);
        return new Response(JSON.stringify({ success: false, error: e.message }), {
          status: 400,
          headers: { ...corsHeaders, "Content-Type": "application/json" }
        });
      }
    }

    // API Logic (perlu auth)
    if (url.pathname.startsWith('/api/')) {
      try {
        const authEmail = request.headers.get("X-Auth-Email");
        const authKey = request.headers.get("X-Auth-Key");

        if (!authEmail || !authKey) throw new Error("Email atau API Key tidak ditemukan di header.");

        const commonHeaders = {
          "X-Auth-Email": authEmail,
          "X-Auth-Key": authKey,
          "Content-Type": "application/json"
        };

        const getAccountId = async () => {
          const res = await fetch("https://api.cloudflare.com/client/v4/accounts", { headers: commonHeaders });
          const data = await res.json();
          if (!data.success) throw new Error("Gagal login API Cloudflare. Cek Email/Key.");
          return data.result[0].id;
        };

        // List Workers
        if (url.pathname === '/api/list') {
          const accountId = await getAccountId();
          const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts`, { headers: commonHeaders });
          const data = await res.json();
          return new Response(JSON.stringify(data), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // Get Script Code - FIXED: Membersihkan boundary multipart
        if (url.pathname === '/api/get') {
          const workerName = url.searchParams.get("name");
          const accountId = await getAccountId();
          const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}`, { 
            headers: commonHeaders 
          });
          
          let scriptContent = await res.text();
          
          // Bersihkan dari multipart boundary jika ada
          scriptContent = scriptContent.replace(/^--[a-f0-9]+(\r?\n)Content-Disposition: form-data; name="[^"]+"(\r?\n\r?\n)?/gm, '');
          scriptContent = scriptContent.replace(/--[a-f0-9]+--(\r?\n)?$/g, '');
          scriptContent = scriptContent.replace(/--[a-f0-9]+(\r?\n)Content-Disposition: form-data; name="[^"]+"(\r?\n\r?\n)?/g, '');
          scriptContent = scriptContent.trim();
          
          return new Response(JSON.stringify({ success: true, code: scriptContent }), { 
            headers: { ...corsHeaders, "Content-Type": "application/json" } 
          });
        }

        // Get Custom Domains untuk Worker tertentu
        if (url.pathname === '/api/get-custom-domains') {
          const workerName = url.searchParams.get("name");
          const accountId = await getAccountId();
          
          try {
            const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}/subdomain`, {
              headers: commonHeaders
            });
            const data = await res.json();
            
            // Ambil daftar custom domain dari zone
            const zonesRes = await fetch(`https://api.cloudflare.com/client/v4/zones`, {
              headers: commonHeaders
            });
            const zonesData = await zonesRes.json();
            
            const domains = [];
            if (zonesData.success && zonesData.result) {
              for (const zone of zonesData.result) {
                domains.push({
                  zone_id: zone.id,
                  zone_name: zone.name,
                  hostname: zone.name
                });
              }
            }
            
            return new Response(JSON.stringify({ 
              success: true, 
              subdomain: data.success ? `https://${workerName}.workers.dev` : null,
              customDomains: domains
            }), { 
              headers: { ...corsHeaders, "Content-Type": "application/json" } 
            });
          } catch(e) {
            return new Response(JSON.stringify({ success: false, error: e.message }), {
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }
        }

        // Attach Custom Domain ke Worker
        if (url.pathname === '/api/attach-domain') {
          const { workerName, domain, zoneId } = await request.json();
          const accountId = await getAccountId();
          
          try {
            // Pertama, buat route untuk domain
            const routeRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/workers/routes`, {
              method: "POST",
              headers: commonHeaders,
              body: JSON.stringify({
                pattern: `${domain}/*`,
                script: workerName
              })
            });
            
            const routeData = await routeRes.json();
            
            return new Response(JSON.stringify({ 
              success: routeData.success,
              message: routeData.success ? `Domain ${domain} berhasil diattach ke ${workerName}` : routeData.errors?.[0]?.message
            }), { 
              headers: { ...corsHeaders, "Content-Type": "application/json" } 
            });
          } catch(e) {
            return new Response(JSON.stringify({ success: false, error: e.message }), {
              status: 400,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }
        }

        // Get Routes untuk Worker
        if (url.pathname === '/api/get-routes') {
          const workerName = url.searchParams.get("name");
          const accountId = await getAccountId();
          
          try {
            // Ambil semua zone
            const zonesRes = await fetch(`https://api.cloudflare.com/client/v4/zones`, {
              headers: commonHeaders
            });
            const zonesData = await zonesRes.json();
            
            const allRoutes = [];
            
            if (zonesData.success && zonesData.result) {
              for (const zone of zonesData.result) {
                const routesRes = await fetch(`https://api.cloudflare.com/client/v4/zones/${zone.id}/workers/routes`, {
                  headers: commonHeaders
                });
                const routesData = await routesRes.json();
                
                if (routesData.success && routesData.result) {
                  for (const route of routesData.result) {
                    if (route.script === workerName) {
                      allRoutes.push({
                        id: route.id,
                        pattern: route.pattern,
                        zone_name: zone.name,
                        zone_id: zone.id
                      });
                    }
                  }
                }
              }
            }
            
            return new Response(JSON.stringify({ 
              success: true, 
              routes: allRoutes
            }), { 
              headers: { ...corsHeaders, "Content-Type": "application/json" } 
            });
          } catch(e) {
            return new Response(JSON.stringify({ success: false, error: e.message }), {
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }
        }

        // Delete Custom Domain (Route)
        if (url.pathname === '/api/delete-domain') {
          const { zoneId, routeId } = await request.json();
          
          try {
            const res = await fetch(`https://api.cloudflare.com/client/v4/zones/${zoneId}/workers/routes/${routeId}`, {
              method: "DELETE",
              headers: commonHeaders
            });
            const data = await res.json();
            
            return new Response(JSON.stringify({ 
              success: data.success,
              message: data.success ? "Domain berhasil dihapus" : data.errors?.[0]?.message
            }), { 
              headers: { ...corsHeaders, "Content-Type": "application/json" } 
            });
          } catch(e) {
            return new Response(JSON.stringify({ success: false, error: e.message }), {
              status: 400,
              headers: { ...corsHeaders, "Content-Type": "application/json" }
            });
          }
        }

        // Delete Worker
        if (url.pathname === '/api/delete') {
          const { name } = await request.json();
          if (!name) throw new Error("Nama worker diperlukan");
          
          const accountId = await getAccountId();
          const res = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${name}`, {
            method: "DELETE",
            headers: { "X-Auth-Email": authEmail, "X-Auth-Key": authKey },
          });
          const data = await res.json();
          return new Response(JSON.stringify(data), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
        }

        // Deploy/Update Script
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
          
          let subdomainUrl = null;
          if (data.success) {
            try {
              const subRes = await fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${name}/subdomain`, {
                method: "POST",
                headers: { "X-Auth-Email": authEmail, "X-Auth-Key": authKey, "Content-Type": "application/json" },
                body: JSON.stringify({ enabled: true }),
              });
              const subData = await subRes.json();
              if (subData.success) {
                subdomainUrl = `https://${name}.workers.dev`;
              }
            } catch(e) {
              console.log("Subdomain activation failed:", e);
            }
          }
          
          return new Response(JSON.stringify({ ...data, subdomain: subdomainUrl }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
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
      <title>CF Worker Manager - With Custom Domain</title>
      <link href="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/themes/prism-tomorrow.min.css" rel="stylesheet" />
      <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
      <style>
        * {
          margin: 0;
          padding: 0;
          box-sizing: border-box;
        }

        :root {
          --bg: #0a0c10;
          --card: #111318;
          --sidebar: #0f1117;
          --blue: #3b82f6;
          --blue-dark: #2563eb;
          --border: #1e2229;
          --green: #10b981;
          --red: #ef4444;
          --orange: #f59e0b;
          --purple: #8b5cf6;
          --text: #e5e7eb;
          --text-secondary: #9ca3af;
        }

        body {
          font-family: 'Inter', -apple-system, system-ui, sans-serif;
          background: var(--bg);
          color: var(--text);
          margin: 0;
          overflow-x: hidden;
        }

        /* Loading Bar */
        .loading-bar {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          height: 3px;
          background: linear-gradient(90deg, var(--blue), var(--purple), var(--blue));
          z-index: 10000;
          transform: translateX(-100%);
          transition: transform 0.3s ease;
        }

        .loading-bar.active {
          transform: translateX(0%);
          animation: loading 1.5s infinite;
        }

        @keyframes loading {
          0% { transform: translateX(-100%); }
          50% { transform: translateX(0%); }
          100% { transform: translateX(100%); }
        }

        /* Sidebar */
        .sidebar {
          position: fixed;
          left: -280px;
          top: 0;
          width: 280px;
          height: 100vh;
          background: var(--sidebar);
          border-right: 1px solid var(--border);
          z-index: 1000;
          transition: left 0.3s ease;
          overflow-y: auto;
          box-shadow: 2px 0 10px rgba(0,0,0,0.3);
        }

        .sidebar.open {
          left: 0;
        }

        .sidebar-header {
          padding: 24px 20px;
          border-bottom: 1px solid var(--border);
          background: linear-gradient(135deg, var(--blue), var(--purple));
        }

        .sidebar-header h2 {
          font-size: 18px;
          margin-bottom: 4px;
        }

        .sidebar-header p {
          font-size: 12px;
          opacity: 0.8;
        }

        .sidebar-content {
          padding: 20px;
        }

        .sidebar-section {
          margin-bottom: 24px;
        }

        .sidebar-section-title {
          font-size: 12px;
          font-weight: 600;
          text-transform: uppercase;
          letter-spacing: 1px;
          color: var(--text-secondary);
          margin-bottom: 12px;
        }

        /* Menu Button */
        .menu-btn {
          position: fixed;
          top: 20px;
          left: 20px;
          z-index: 1001;
          background: var(--card);
          border: 1px solid var(--border);
          border-radius: 10px;
          padding: 10px;
          cursor: pointer;
          transition: all 0.3s ease;
          display: flex;
          flex-direction: column;
          gap: 5px;
        }

        .menu-btn:hover {
          background: var(--blue);
          border-color: var(--blue);
        }

        .menu-btn span {
          width: 24px;
          height: 2px;
          background: var(--text);
          border-radius: 2px;
          transition: all 0.3s ease;
        }

        .menu-btn:hover span {
          background: white;
        }

        /* Overlay */
        .overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0,0,0,0.5);
          z-index: 999;
          display: none;
        }

        .overlay.active {
          display: block;
        }

        /* Main Content */
        .main-content {
          margin-left: 0;
          transition: margin-left 0.3s ease;
          padding: 20px;
        }

        .main-content.shifted {
          margin-left: 280px;
        }

        .container {
          max-width: 1400px;
          margin: 0 auto;
        }

        /* Hero Header */
        .hero-header {
          text-align: center;
          padding: 40px 20px;
          background: linear-gradient(135deg, rgba(59,130,246,0.1), rgba(139,92,246,0.1));
          border-radius: 24px;
          margin-bottom: 32px;
          border: 1px solid rgba(59,130,246,0.2);
        }

        .hero-header h1 {
          font-size: 2.5rem;
          font-weight: 700;
          background: linear-gradient(135deg, #3b82f6, #8b5cf6);
          -webkit-background-clip: text;
          background-clip: text;
          color: transparent;
          margin-bottom: 8px;
        }

        .hero-header p {
          color: var(--text-secondary);
          font-size: 1rem;
        }

        @media (max-width: 768px) {
          .hero-header h1 { font-size: 1.8rem; }
          .hero-header { padding: 30px 16px; }
        }

        /* Cards */
        .card {
          background: var(--card);
          border: 1px solid var(--border);
          border-radius: 12px;
          padding: 20px;
          margin-bottom: 20px;
          transition: all 0.3s ease;
        }

        .card:hover {
          border-color: var(--blue);
          box-shadow: 0 4px 12px rgba(59,130,246,0.1);
        }

        .card-title {
          font-size: 16px;
          font-weight: 600;
          margin-bottom: 16px;
          display: flex;
          align-items: center;
          gap: 8px;
        }

        /* Styled Select */
        .styled-select {
          background: var(--bg);
          border: 1px solid var(--border);
          border-radius: 12px;
          padding: 12px 16px;
          width: 100%;
          font-size: 14px;
          color: var(--text);
          cursor: pointer;
          transition: all 0.2s ease;
          appearance: none;
          background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%239ca3af' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><polyline points='6 9 12 15 18 9'></polyline></svg>");
          background-repeat: no-repeat;
          background-position: right 16px center;
        }

        .styled-select:focus {
          outline: none;
          border-color: var(--blue);
          box-shadow: 0 0 0 2px rgba(59,130,246,0.2);
        }

        /* Worker Grid untuk List Worker */
        .worker-grid {
          display: flex;
          flex-wrap: wrap;
          gap: 10px;
          margin-top: 12px;
          max-height: 300px;
          overflow-y: auto;
          padding: 4px;
        }
        
        .worker-card {
          background: linear-gradient(135deg, var(--card), var(--bg));
          border: 1px solid var(--border);
          border-radius: 12px;
          padding: 12px 16px;
          display: flex;
          align-items: center;
          gap: 12px;
          transition: all 0.2s ease;
          cursor: pointer;
          width: calc(33.33% - 8px);
          min-width: 180px;
          flex: 1 0 auto;
        }
        
        .worker-card:hover {
          border-color: var(--blue);
          transform: translateY(-2px);
          background: rgba(59,130,246,0.1);
        }
        
        .worker-card.selected {
          border-color: var(--blue);
          background: rgba(59,130,246,0.15);
          box-shadow: 0 0 0 1px var(--blue);
        }
        
        .worker-icon {
          width: 36px;
          height: 36px;
          background: linear-gradient(135deg, var(--blue), var(--purple));
          border-radius: 10px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 18px;
        }
        
        .worker-info {
          flex: 1;
        }
        
        .worker-name {
          font-weight: 600;
          font-size: 14px;
          font-family: monospace;
          word-break: break-all;
        }
        
        .worker-status {
          font-size: 10px;
          color: var(--green);
          margin-top: 4px;
        }
        
        .delete-worker-btn {
          background: transparent;
          border: none;
          color: var(--red);
          cursor: pointer;
          padding: 6px;
          border-radius: 6px;
          transition: all 0.2s;
          font-size: 14px;
        }
        
        .delete-worker-btn:hover {
          background: rgba(239,68,68,0.2);
          transform: scale(1.05);
        }
        
        .section-label {
          font-size: 11px;
          color: var(--text-secondary);
          margin-bottom: 8px;
          letter-spacing: 1px;
          font-weight: 600;
        }
        
        .empty-workers {
          text-align: center;
          padding: 40px;
          color: var(--text-secondary);
          background: var(--bg);
          border-radius: 12px;
          border: 1px dashed var(--border);
        }

        /* Forms */
        input, select, textarea {
          background: var(--bg);
          color: var(--text);
          border: 1px solid var(--border);
          padding: 10px 12px;
          border-radius: 8px;
          width: 100%;
          box-sizing: border-box;
          margin-bottom: 12px;
          font-size: 14px;
          transition: all 0.2s ease;
        }

        input:focus, select:focus, textarea:focus {
          outline: none;
          border-color: var(--blue);
          box-shadow: 0 0 0 2px rgba(59,130,246,0.1);
        }

        /* Buttons */
        button {
          padding: 10px 16px;
          border-radius: 8px;
          border: none;
          font-weight: 500;
          cursor: pointer;
          transition: all 0.2s ease;
          font-size: 13px;
          display: inline-flex;
          align-items: center;
          gap: 6px;
        }

        button:active {
          transform: scale(0.98);
        }

        .btn-blue { background: var(--blue); color: #fff; }
        .btn-blue:hover { background: var(--blue-dark); }
        .btn-green { background: var(--green); color: #fff; }
        .btn-green:hover { background: #059669; }
        .btn-red { background: var(--red); color: #fff; }
        .btn-red:hover { background: #dc2626; }
        .btn-orange { background: var(--orange); color: #fff; }
        .btn-orange:hover { background: #d97706; }
        .btn-purple { background: var(--purple); color: #fff; }
        .btn-purple:hover { background: #7c3aed; }
        .btn-outline { background: transparent; border: 1px solid var(--border); color: var(--text); }
        .btn-outline:hover { border-color: var(--blue); color: var(--blue); }

        .flex { display: flex; gap: 10px; flex-wrap: wrap; }
        .grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }

        /* Editor */
        .editor-container {
          position: relative;
          min-height: 400px;
          border: 1px solid var(--border);
          border-radius: 12px;
          overflow: hidden;
          background: #1a1d24;
        }
        
        #editor, #highlighting {
          margin: 0;
          padding: 16px;
          width: 100%;
          height: 100%;
          position: absolute;
          top: 0;
          left: 0;
          tab-size: 2;
          box-sizing: border-box;
          font-family: 'Fira Code', 'Courier New', monospace;
          font-size: 13px;
          line-height: 1.5;
          overflow: auto;
          white-space: pre;
        }
        
        #editor {
          color: transparent;
          background: transparent;
          caret-color: white;
          z-index: 1;
          resize: none;
          outline: none;
          -webkit-text-fill-color: transparent;
        }
        
        #highlighting {
          z-index: 0;
          pointer-events: none;
        }

        /* Status */
        .status-toast {
          position: fixed;
          bottom: 20px;
          right: 20px;
          background: var(--card);
          border-left: 3px solid var(--green);
          padding: 12px 16px;
          border-radius: 8px;
          display: none;
          z-index: 1000;
          box-shadow: 0 4px 12px rgba(0,0,0,0.3);
          max-width: 350px;
        }

        .status-toast.error {
          border-left-color: var(--red);
        }

        .domain-item {
          background: var(--bg);
          padding: 12px;
          border-radius: 8px;
          margin-bottom: 8px;
          display: flex;
          justify-content: space-between;
          align-items: center;
        }

        @media (max-width: 768px) {
          .grid-2 { grid-template-columns: 1fr; }
          .main-content.shifted { margin-left: 0; }
          .worker-card { width: calc(50% - 6px); min-width: 140px; }
        }
        
        @media (max-width: 480px) {
          .worker-card { width: 100%; }
        }
      </style>
    </head>
    <body>
      <div class="loading-bar" id="loadingBar"></div>
      
      <div class="menu-btn" onclick="toggleSidebar()">
        <span></span>
        <span></span>
        <span></span>
      </div>

      <div class="sidebar" id="sidebar">
        <div class="sidebar-content">
          <div class="sidebar-section">
            <div class="sidebar-section-title">Akun Cloudflare</div>
            <select id="accSelector" onchange="switchAccount()" style="margin-bottom: 12px;"></select>
            <div id="addAccForm" class="hidden" style="display:none;">
              <input id="accEmail" type="email" placeholder="Email Akun Cloudflare">
              <input id="accKey" type="password" placeholder="Global API Key">
              <div class="flex">
                <button onclick="saveAccount()" class="btn-green" style="flex:1">Simpan</button>
                <button onclick="toggleAddForm()" class="btn-outline" style="flex:1">Batal</button>
              </div>
            </div>
            <div class="flex" id="accActionBtns">
              <button onclick="toggleAddForm()" class="btn-outline" style="flex:1">+ Akun Baru</button>
              <button onclick="deleteAccount()" class="btn-red" style="flex:1">Hapus Akun</button>
            </div>
          </div>

          <div class="sidebar-section">
            <div class="sidebar-section-title">Custom Domain</div>
            <select id="customDomainSelect" style="margin-bottom: 12px;" disabled>
              <option>Pilih Worker dulu</option>
            </select>
            <button onclick="loadCustomDomains()" class="btn-purple" id="loadDomainsBtn" disabled style="width:100%; margin-bottom:12px;">📋 Load Domains</button>
            <div id="domainList" style="max-height: 200px; overflow-y: auto;"></div>
            <div id="addDomainForm" class="hidden" style="display:none; margin-top: 12px;">
              <input type="text" id="newDomain" placeholder="contoh: proxy.jamol.web.id" />
              <select id="zoneSelect" style="margin-bottom: 12px;"></select>
              <div class="flex">
                <button onclick="attachCustomDomain()" class="btn-green" style="flex:1">➕ Attach</button>
                <button onclick="toggleAddDomainForm()" class="btn-outline" style="flex:1">Batal</button>
              </div>
            </div>
            <button onclick="toggleAddDomainForm()" class="btn-outline" id="showAddBtn" style="width:100%;">+ Tambah Domain</button>
          </div>
        </div>
      </div>

      <div class="overlay" id="overlay" onclick="closeSidebar()"></div>

      <div class="main-content" id="mainContent">
        <div class="container">
          <!-- Hero Header -->
          <div class="hero-header">
            <h1>⚡ Cloudflare Manager</h1>
            <p>Kelola Worker & Custom Domain</p>
          </div>

          <!-- LIST WORKER Section - Menggantikan PENGATURAN KARAKTER -->
          <div class="card">
            <div class="card-title">
              📋 LIST WORKER
              <button onclick="fetchList()" class="btn-blue" style="margin-left: auto; padding: 6px 12px; font-size: 12px;">🔄 Refresh</button>
            </div>
            <div id="workerGridContainer" class="worker-grid">
              <div class="empty-workers">
                ⚡ Pilih akun Cloudflare terlebih dahulu dari menu samping
              </div>
            </div>
            <div class="flex" style="margin-top: 16px;">
              <button onclick="loadSelectedWorker()" class="btn-purple" style="flex:1;">📂 Load Kode Worker</button>
              <button onclick="deployWorker()" class="btn-green" style="flex:1;">🚀 DEPLOY</button>
            </div>
          </div>

          <div class="card">
            <div class="card-title">
              ✏️ Nama Worker Baru
            </div>
            <input type="text" id="newWorkerName" placeholder="Kosongkan jika ingin update worker yang dipilih" />
            <small style="color: var(--text-secondary);">* Kosongkan jika ingin update worker yang sudah dipilih</small>
          </div>

          <div class="card">
            <div class="card-title">
              🔗 Import Kode dari URL
            </div>
            <div class="flex">
              <input type="text" id="githubUrl" placeholder="https://raw.githubusercontent.com/.../worker.js" style="flex:1;" />
              <button onclick="importFromUrl()" class="btn-orange">📥 Import</button>
            </div>
            <div style="font-size: 11px; color: var(--text-secondary); margin-top: 8px;">
              📌 Contoh: 
              <span onclick="setExampleUrl('https://raw.githubusercontent.com/example/worker.js')" style="color: var(--blue); cursor: pointer;">GitHub Raw</span> | 
              <span onclick="setExampleUrl('https://r2.lunas.workers.dev/raw/xnxn.js')" style="color: var(--orange); cursor: pointer;">R2</span>
            </div>
          </div>

          <div class="card">
            <div class="card-title">
              📝 Editor Kode
            </div>
            <div class="editor-container" style="height: 400px;">
              <textarea id="editor" spellcheck="false" oninput="updateView(); syncScroll();" onscroll="syncScroll();"></textarea>
              <pre id="highlighting" aria-hidden="true"><code class="language-javascript" id="highlighting-content"></code></pre>
            </div>
          </div>
        </div>
      </div>

      <div id="statusToast" class="status-toast"></div>

      <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/prism.min.js"></script>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/prism/1.29.0/components/prism-javascript.min.js"></script>
      
      <script>
        let loadingTimeout;
        let selectedWorkerName = null;
        
        function showLoading() {
          const loadingBar = document.getElementById('loadingBar');
          loadingBar.classList.add('active');
          if (loadingTimeout) clearTimeout(loadingTimeout);
        }
        
        function hideLoading() {
          const loadingBar = document.getElementById('loadingBar');
          loadingBar.classList.remove('active');
        }
        
        function toggleSidebar() {
          const sidebar = document.getElementById('sidebar');
          const overlay = document.getElementById('overlay');
          const mainContent = document.getElementById('mainContent');
          
          sidebar.classList.toggle('open');
          overlay.classList.toggle('active');
          
          if (sidebar.classList.contains('open')) {
            mainContent.classList.add('shifted');
          } else {
            mainContent.classList.remove('shifted');
          }
        }
        
        function closeSidebar() {
          const sidebar = document.getElementById('sidebar');
          const overlay = document.getElementById('overlay');
          const mainContent = document.getElementById('mainContent');
          
          sidebar.classList.remove('open');
          overlay.classList.remove('active');
          mainContent.classList.remove('shifted');
        }
        
        const $ = id => document.getElementById(id);
        let accounts = JSON.parse(localStorage.getItem('cf_accounts_v2') || '[]');
        let currentAcc = null;
        let workersList = [];
        let currentWorkerDomains = [];
        let availableZones = [];

        function toggleAddForm() { 
          const form = $('addAccForm');
          const btns = $('accActionBtns');
          if (form.style.display === 'none' || form.style.display === '') {
            form.style.display = 'block';
            btns.style.display = 'none';
          } else {
            form.style.display = 'none';
            btns.style.display = 'flex';
          }
        }

        function toggleAddDomainForm() {
          const form = $('addDomainForm');
          const btn = $('showAddBtn');
          if (form.style.display === 'none' || form.style.display === '') {
            form.style.display = 'block';
            btn.style.display = 'none';
          } else {
            form.style.display = 'none';
            btn.style.display = 'block';
          }
        }

        function setExampleUrl(url) {
          $('githubUrl').value = url;
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
          if(idx !== "-1" && accounts[idx]) {
            currentAcc = accounts[idx];
            fetchList();
          }
        }

        function saveAccount() {
          const email = $('accEmail').value.trim();
          const key = $('accKey').value.trim();
          if(!email || !key) return notify("Isi Email dan Global Key!", true);
          accounts.push({ email, key });
          localStorage.setItem('cf_accounts_v2', JSON.stringify(accounts));
          $('accEmail').value = '';
          $('accKey').value = '';
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

        function renderWorkerGrid() {
          const container = $('workerGridContainer');
          if(!workersList || workersList.length === 0) {
            container.innerHTML = '<div class="empty-workers">📭 Belum ada worker. Buat worker baru dengan mengisi nama dan deploy!</div>';
            return;
          }
          
          container.innerHTML = workersList.map(worker => \`
            <div class="worker-card \${selectedWorkerName === worker.id ? 'selected' : ''}" onclick="selectWorker('\${worker.id}')">
              <div class="worker-icon">⚡</div>
              <div class="worker-info">
                <div class="worker-name">\${worker.id}</div>
                <div class="worker-status">● Active</div>
              </div>
              <button class="delete-worker-btn" onclick="event.stopPropagation(); deleteWorker('\${worker.id}')" title="Hapus Worker">🗑️</button>
            </div>
          \`).join('');
        }

        async function fetchList() {
          if(!currentAcc) {
            $('workerGridContainer').innerHTML = '<div class="empty-workers">⚡ Pilih akun Cloudflare terlebih dahulu dari menu samping</div>';
            $('customDomainSelect').disabled = true;
            $('loadDomainsBtn').disabled = true;
            return;
          }
          
          showLoading();
          
          try {
            const res = await fetch('/api/list', {
              headers: { 'X-Auth-Email': currentAcc.email, 'X-Auth-Key': currentAcc.key }
            });
            const d = await res.json();
            if(d.success) {
              workersList = d.result || [];
              renderWorkerGrid();
              
              $('customDomainSelect').disabled = false;
              $('loadDomainsBtn').disabled = false;
              $('customDomainSelect').innerHTML = '<option value="">Pilih Worker</option>' + 
                workersList.map(w => \`<option value="\${w.id}">\${w.id}</option>\`).join('');
            } else {
              throw new Error(d.errors?.[0]?.message || "Gagal load");
            }
          } catch(e) { 
            notify(e.message, true);
            $('workerGridContainer').innerHTML = '<div class="empty-workers">❌ Gagal memuat worker: ' + e.message + '</div>';
          } finally {
            hideLoading();
          }
        }
        
        function selectWorker(workerName) {
          selectedWorkerName = workerName;
          renderWorkerGrid();
          notify(\`✅ Worker "\${workerName}" dipilih\`);
        }
        
        async function loadSelectedWorker() {
          if(!selectedWorkerName) {
            notify("Pilih worker terlebih dahulu dengan mengklik card worker!", true);
            return;
          }
          await loadWorker(selectedWorkerName);
        }

        async function loadCustomDomains() {
          const workerName = $('customDomainSelect').value;
          if(!workerName || !currentAcc) {
            notify("Pilih worker terlebih dahulu!", true);
            return;
          }
          
          showLoading();
          notify("Memuat domain...");
          
          try {
            const routesRes = await fetch('/api/get-routes?name=' + encodeURIComponent(workerName), {
              headers: { 'X-Auth-Email': currentAcc.email, 'X-Auth-Key': currentAcc.key }
            });
            const routesData = await routesRes.json();
            
            const domainsRes = await fetch('/api/get-custom-domains?name=' + encodeURIComponent(workerName), {
              headers: { 'X-Auth-Email': currentAcc.email, 'X-Auth-Key': currentAcc.key }
            });
            const domainsData = await domainsRes.json();
            
            if(domainsData.success) {
              availableZones = domainsData.customDomains || [];
              $('zoneSelect').innerHTML = availableZones.map(z => \`<option value="\${z.zone_id}">\${z.zone_name}</option>\`).join('');
            }
            
            if(routesData.success && routesData.routes) {
              currentWorkerDomains = routesData.routes;
              $('domainList').innerHTML = currentWorkerDomains.length === 0 ? 
                '<div style="text-align:center; padding:20px; color:var(--text-secondary);">Belum ada custom domain</div>' :
                currentWorkerDomains.map(route => \`
                  <div class="domain-item">
                    <div>
                      <div style="font-family: monospace; color: var(--blue);">🔗 \${route.pattern.replace('/*', '')}</div>
                      <small style="color: var(--text-secondary);">Zone: \${route.zone_name}</small>
                    </div>
                    <span class="delete-domain" onclick="deleteCustomDomain('\${route.zone_id}', '\${route.id}')" style="color: var(--red); cursor: pointer;">🗑️</span>
                  </div>
                \`).join('');
              notify("✅ Domain berhasil dimuat!");
            } else {
              $('domainList').innerHTML = '<div style="text-align:center; padding:20px; color:var(--text-secondary);">Belum ada custom domain</div>';
            }
          } catch(e) {
            notify("❌ Gagal load domain: " + e.message, true);
          } finally {
            hideLoading();
          }
        }
        
        async function attachCustomDomain() {
          const workerName = $('customDomainSelect').value;
          const domain = $('newDomain').value.trim();
          const zoneId = $('zoneSelect').value;
          
          if(!workerName) {
            notify("Pilih worker terlebih dahulu!", true);
            return;
          }
          if(!domain) {
            notify("Masukkan domain!", true);
            return;
          }
          if(!zoneId) {
            notify("Pilih zone!", true);
            return;
          }
          
          showLoading();
          notify(\`Mengattach domain \${domain} ke \${workerName}...\`);
          
          try {
            const res = await fetch('/api/attach-domain', {
              method: 'POST',
              headers: {
                'X-Auth-Email': currentAcc.email,
                'X-Auth-Key': currentAcc.key,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({ workerName, domain, zoneId })
            });
            const d = await res.json();
            if(d.success) {
              notify(\`✅ \${d.message}\`);
              $('newDomain').value = '';
              toggleAddDomainForm();
              loadCustomDomains();
            } else {
              notify("❌ Gagal: " + (d.message || d.error), true);
            }
          } catch(e) {
            notify("❌ Error: " + e.message, true);
          } finally {
            hideLoading();
          }
        }
        
        async function deleteCustomDomain(zoneId, routeId) {
          if(!confirm("Yakin ingin menghapus custom domain ini?")) return;
          
          showLoading();
          notify("Menghapus domain...");
          
          try {
            const res = await fetch('/api/delete-domain', {
              method: 'POST',
              headers: {
                'X-Auth-Email': currentAcc.email,
                'X-Auth-Key': currentAcc.key,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({ zoneId, routeId })
            });
            const d = await res.json();
            if(d.success) {
              notify("✅ Domain berhasil dihapus!");
              loadCustomDomains();
            } else {
              notify("❌ Gagal: " + (d.message || d.error), true);
            }
          } catch(e) {
            notify("❌ Error: " + e.message, true);
          } finally {
            hideLoading();
          }
        }

        async function deleteWorker(workerName) {
          if(!confirm(\`Yakin ingin menghapus worker "\${workerName}"?\`)) return;
          
          showLoading();
          notify(\`Menghapus \${workerName}...\`);
          
          try {
            const res = await fetch('/api/delete', {
              method: 'DELETE',
              headers: {
                'X-Auth-Email': currentAcc.email,
                'X-Auth-Key': currentAcc.key,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({ name: workerName })
            });
            const d = await res.json();
            if(d.success) {
              notify(\`✅ Worker "\${workerName}" berhasil dihapus!\`);
              if(selectedWorkerName === workerName) {
                selectedWorkerName = null;
              }
              fetchList();
              $('editor').value = '';
              updateView();
              loadCustomDomains();
            } else {
              notify("❌ Gagal hapus: " + (d.errors?.[0]?.message || "Unknown error"), true);
            }
          } catch(e) {
            notify("❌ Error: " + e.message, true);
          } finally {
            hideLoading();
          }
        }

        async function importFromUrl() {
          const url = $('githubUrl').value.trim();
          if(!url) {
            notify("Masukkan URL terlebih dahulu!", true);
            return;
          }
          
          showLoading();
          notify("Mengambil kode dari URL...");
          
          try {
            const res = await fetch('/api/import', {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ importUrl: url })
            });
            const d = await res.json();
            if(d.success) {
              $('editor').value = d.code;
              updateView();
              notify("✅ Kode berhasil diimport dari URL!");
            } else {
              throw new Error(d.error || "Gagal mengambil kode");
            }
          } catch(e) {
            notify("❌ Gagal: " + e.message, true);
          } finally {
            hideLoading();
          }
        }

        async function loadWorker(workerName) {
          if(!workerName || !currentAcc) return notify("Pilih worker terlebih dahulu", true);
          
          showLoading();
          notify("Mengambil kode...");
          
          try {
            const res = await fetch('/api/get?name=' + encodeURIComponent(workerName), {
              headers: { 'X-Auth-Email': currentAcc.email, 'X-Auth-Key': currentAcc.key }
            });
            const d = await res.json();
            if(d.success) {
              $('editor').value = d.code;
              updateView();
              notify("✅ Kode berhasil dimuat!");
            } else {
              throw new Error(d.errors?.[0]?.message || "Gagal ambil kode");
            }
          } catch(e) { 
            notify("❌ Gagal ambil kode: " + e.message, true); 
          } finally {
            hideLoading();
          }
        }

        async function deployWorker() {
          let workerName = selectedWorkerName;
          const newName = $('newWorkerName').value.trim();
          const code = $('editor').value;
          
          if(!code) return notify("Kode masih kosong!", true);
          
          if(newName) {
            workerName = newName;
          }
          
          if(!workerName) return notify("Pilih worker dari list atau isi nama worker baru!", true);
          
          showLoading();
          notify("Mendeploy ke Cloudflare...");
          
          try {
            const res = await fetch('/api/update', {
              method: 'POST',
              headers: { 
                'X-Auth-Email': currentAcc.email, 
                'X-Auth-Key': currentAcc.key,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({ name: workerName, code: code })
            });
            const d = await res.json();
            if(d.success) {
              let msg = "✅ BERHASIL DI-DEPLOY!\\n";
              msg += "Worker: " + workerName + "\\n";
              if(d.subdomain) msg += "URL: " + d.subdomain;
              notify(msg);
              fetchList();
              $('newWorkerName').value = '';
              selectedWorkerName = workerName;
              setTimeout(() => {
                if($('customDomainSelect').value === workerName) {
                  loadCustomDomains();
                }
              }, 1000);
            } else {
              notify("❌ Gagal: " + (d.errors?.[0]?.message || "Unknown error"), true);
            }
          } catch(e) { 
            notify("❌ Network Error: " + e.message, true); 
          } finally {
            hideLoading();
          }
        }

        function updateView() {
          let code = $('editor').value;
          if(code && code[code.length-1] == "\\n") code += " ";
          $('highlighting-content').textContent = code || '';
          Prism.highlightElement($('highlighting-content'));
        }

        function syncScroll() {
          $('highlighting').scrollTop = $('editor').scrollTop;
          $('highlighting').scrollLeft = $('editor').scrollLeft;
        }

        function notify(msg, err=false) {
          const toast = $("statusToast");
          toast.className = "status-toast" + (err ? " error" : "");
          toast.innerText = msg;
          toast.style.display = "block";
          
          setTimeout(() => {
            toast.style.display = "none";
          }, 5000);
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
