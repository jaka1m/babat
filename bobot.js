import { connect } from "cloudflare:sockets";

export default {
  async fetch(request, env) {
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type, X-Auth-Email, X-Auth-Key",
      "Access-Control-Max-Age": "86400",
    };

    if (request.method === "OPTIONS") {
      return new Response(null, { 
        status: 204, 
        headers: corsHeaders 
      });
    }

    if (request.method === "POST") {
      try {
        const body = await request.json();
        const { email, globalAPIKey, workerName, githubUrl, scriptContent: manualScript } = body;

        // Validasi input minimal
        if (!email || !globalAPIKey || !workerName) {
          throw new Error("Email, API Key, dan Nama Worker wajib diisi.");
        }

        let finalScript = "";

        // Logika pemilihan sumber script
        if (manualScript && manualScript.trim() !== "") {
          // Gunakan input manual jika ada
          finalScript = manualScript;
        } else if (githubUrl) {
          // Jika tidak ada input manual, baru ambil dari URL
          const res = await fetch(githubUrl);
          if (!res.ok) throw new Error(`Gagal mengambil script dari URL: ${githubUrl}`);
          finalScript = await res.text();
        } else {
          throw new Error("Mohon masukkan Script Manual atau GitHub URL.");
        }

        const commonHeaders = {
          "X-Auth-Email": email,
          "X-Auth-Key": globalAPIKey,
        };

        // Ambil Account ID
        const accRes = await fetch("https://api.cloudflare.com/client/v4/accounts", { 
          headers: commonHeaders 
        });
        const accData = await accRes.json();
        if (!accData.success) throw new Error("Gagal login API Cloudflare. Cek Email/API Key.");
        const accountId = accData.result[0].id;

        // Deploy sebagai MODULE
        const formData = new FormData();
        const metadata = {
          main_module: "worker.js",
          compatibility_date: "2024-01-01",
        };
        
        formData.append("metadata", JSON.stringify(metadata));
        formData.append("worker.js", new Blob([finalScript], { type: "application/javascript+module" }));

        const deployRes = await fetch(
          `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}`,
          {
            method: "PUT",
            headers: commonHeaders, 
            body: formData,
          }
        );

        const deployData = await deployRes.json();
        if (!deployData.success) throw new Error(deployData.errors[0]?.message || "Gagal deploy script.");

        // Aktifkan Subdomain
        await fetch(
          `https://api.cloudflare.com/client/v4/accounts/${accountId}/workers/scripts/${workerName}/subdomain`,
          {
            method: "POST",
            headers: { ...commonHeaders, "Content-Type": "application/json" },
            body: JSON.stringify({ enabled: true }),
          }
        );

        return new Response(JSON.stringify({
          success: true,
          workerName: workerName,
          sub: `https://${workerName}.workers.dev`
        }), { 
          headers: { 
            ...corsHeaders, 
            "Content-Type": "application/json" 
          } 
        });

      } catch (err) {
        return new Response(JSON.stringify({ 
          success: false, 
          error: err.message 
        }), { 
          status: 400,
          headers: { 
            ...corsHeaders, 
            "Content-Type": "application/json" 
          } 
        });
      }
    }

    return new Response("Method Not Allowed", { 
      status: 405, 
      headers: corsHeaders 
    });
  }
};
