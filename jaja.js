// src/converter/linkParser.js
function decodeBase64(str) {
  if (typeof atob === "function") {
    return atob(str);
  }
  const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let result = "";
  let i = 0;
  let char1, char2, char3;
  let enc1, enc2, enc3, enc4;
  str = str.replace(/[^A-Za-z0-9+/=]/g, "");
  while (i < str.length) {
    enc1 = base64Chars.indexOf(str.charAt(i++));
    enc2 = base64Chars.indexOf(str.charAt(i++));
    enc3 = base64Chars.indexOf(str.charAt(i++));
    enc4 = base64Chars.indexOf(str.charAt(i++));
    char1 = enc1 << 2 | enc2 >> 4;
    char2 = (enc2 & 15) << 4 | enc3 >> 2;
    char3 = (enc3 & 3) << 6 | enc4;
    result += String.fromCharCode(char1);
    if (enc3 !== 64) result += String.fromCharCode(char2);
    if (enc4 !== 64) result += String.fromCharCode(char3);
  }
  return result;
}
function parseV2RayLink(link) {
  try {
    if (link.startsWith("vmess://")) {
      const base64 = link.substring(8);
      const decoded = decodeBase64(base64);
      let config;
      try {
        config = JSON.parse(decoded);
      } catch (e) {
        const match = decoded.match(/{"v":"\d+".*}/);
        if (match) {
          config = JSON.parse(match[0]);
        } else {
          throw new Error("Invalid VMess format");
        }
      }
      return {
        type: "vmess",
        name: config.ps || `VMess-${config.add}:${config.port}`,
        server: config.add,
        port: config.port,
        uuid: config.id,
        alterId: config.aid || 0,
        cipher: config.scy || "auto",
        tls: config.tls === "tls",
        skipCertVerify: false,
        network: config.net || "tcp",
        wsPath: config.path || "",
        wsHost: config.host || config.add,
        sni: config.sni || config.host || config.add
      };
    }
    if (link.startsWith("vless://")) {
      return parseVLESSLink(link);
    }
    if (link.startsWith("trojan://")) {
      return parseTrojanLink(link);
    }
    if (link.startsWith("ss://")) {
      return parseShadowsocksLink(link);
    }
    throw new Error("Unsupported link type");
  } catch (error) {
    console.error(`Failed to parse link: ${link}`, error);
    throw new Error(`Failed to parse VMess link: ${error.message}`);
  }
}
function parseVLESSLink(link) {
  const url = new URL(link);
  const params = new URLSearchParams(url.search);
  return {
    type: "vless",
    name: decodeURIComponent(url.hash.substring(1)),
    server: url.hostname,
    port: parseInt(url.port),
    uuid: url.username,
    tls: params.get("security") === "tls",
    skipCertVerify: false,
    network: params.get("type") || "tcp",
    wsPath: params.get("path") || "",
    wsHost: params.get("host") || url.hostname,
    sni: params.get("sni") || params.get("host") || url.hostname
  };
}
function parseTrojanLink(link) {
  const url = new URL(link);
  const params = new URLSearchParams(url.search);
  return {
    type: "trojan",
    name: decodeURIComponent(url.hash.substring(1)),
    server: url.hostname,
    port: parseInt(url.port),
    password: url.username,
    tls: params.get("security") === "tls",
    skipCertVerify: false,
    network: params.get("type") || "tcp",
    wsPath: params.get("path") || "",
    wsHost: params.get("host") || url.hostname,
    sni: params.get("sni") || params.get("host") || url.hostname
  };
}
function parseShadowsocksLink(link) {
  const url = new URL(link);
  const params = new URLSearchParams(url.search);
  if (params.get("plugin") === "v2ray-plugin" || params.get("type") === "ws") {
    return {
      type: "ss",
      name: decodeURIComponent(url.hash.substring(1)),
      server: url.hostname,
      port: parseInt(url.port),
      cipher: url.protocol.substring(3) || "none",
      password: url.username,
      tls: params.get("security") === "tls",
      skipCertVerify: false,
      network: params.get("type") || "tcp",
      wsPath: params.get("path") || "",
      wsHost: params.get("host") || url.hostname,
      sni: params.get("sni") || params.get("host") || url.hostname
    };
  }
  throw new Error("Shadowsocks link invalid");
}

// src/converter/configGenerators.js
const backToMenuButton = { text: "⬅️ Back to Menu", callback_data: "menu_page_0" };

function generateClashConfig(links, isFullConfig = false) {
  const parsedLinks = links.map((link) => parseV2RayLink(link));
  let proxiesConfig = 'proxies:\n';

  parsedLinks.forEach((link, index) => {
    const proxyName = `${link.name} [${index + 1}]`;
    proxiesConfig += `- name: "${proxyName}"\n`;
    proxiesConfig += `  type: ${link.type}\n`;
    proxiesConfig += `  server: ${link.server}\n`;
    proxiesConfig += `  port: ${link.port}\n`;

    if (link.type === "vmess") {
      proxiesConfig += `  uuid: ${link.uuid}\n`;
      proxiesConfig += `  alterId: ${link.alterId}\n`;
      proxiesConfig += `  cipher: ${link.cipher}\n`;
    } else if (link.type === "vless") {
      proxiesConfig += `  uuid: ${link.uuid}\n`;
    } else if (link.type === "trojan") {
      proxiesConfig += `  password: ${link.password}\n`;
    } else if (link.type === "ss") {
      proxiesConfig += `  cipher: ${link.cipher}\n`;
      proxiesConfig += `  password: ${link.password}\n`;
    }

    proxiesConfig += `  udp: true\n`;

    if (link.tls) {
      proxiesConfig += `  tls: true\n`;
      proxiesConfig += `  servername: ${link.sni}\n`;
      proxiesConfig += `  skip-cert-verify: true\n`;
    }

    if (link.network === "ws") {
      proxiesConfig += `  network: ws\n`;
      proxiesConfig += `  ws-opts:\n`;
      proxiesConfig += `    path: "${link.wsPath}"\n`;
      proxiesConfig += `    headers:\n`;
      proxiesConfig += `      Host: "${link.wsHost}"\n`;
    }
  });

  if (!isFullConfig) {
    return proxiesConfig;
  }

  const proxyNames = parsedLinks.map((link, index) => `${link.name} [${index + 1}]`);
  const proxyListString = proxyNames.map((name) => `  - "${name}"`).join("\n");

  let fullConfig = `# V2Clash Configuration
# Generated by V2Clash - Compatible with Clash & Mihomo
# Mode: mihomo

port: 7890
socks-port: 7891
allow-lan: false
bind-address: '*'
ipv6: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
geodata-mode: false
tcp-concurrent: false
find-process-mode: strict
unified-delay: false
dns:
  enable: true
  listen: 0.0.0.0:1053
  ipv6: true
  prefer-h3: false
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  respect-rules: true
  default-nameserver:
  - 1.1.1.1
  - 8.8.8.8
  nameserver:
  - https://8.8.8.8/dns-query
  - https://1.1.1.1/dns-query
  - https://dns.google/dns-query
  - https://dns.cloudflare.com/dns-query
  proxy-server-nameserver:
  - 112.215.198.254
  - 112.215.198.248
  fake-ip-filter:
  - '*.lan'
  - '*.localdomain'
  - '*.example'
  - '*.invalid'
  - '*.localhost'
  - '*.test'
  - '*.local'
  - +.stun.*.*
  - +.stun.*.*.*
  - +.stun.*.*.*.*
  - +.stun.*.*.*.*.*
  - '*.msftconnecttest.com'
  - '*.msftncsi.com'
  fallback:
  - https://1.1.1.1/dns-query
  - https://8.8.8.8/dns-query
  - https://dns.google/dns-query
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
    - 240.0.0.0/4
    - 0.0.0.0/32
    domain:
    - +.google.com
    - +.facebook.com
    - +.youtube.com
    geosite:
    - gfw
  nameserver-policy:
    geosite:cn:
    - 114.114.114.114
    - 223.5.5.5
    geosite:geolocation-!cn:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
experimental:
  sniff-tls-sni: true
  ignore-resolve-fail: true
${proxiesConfig}
proxy-groups:
- name: PROXY
  type: select
  proxies:
  - Auto
  - Fallback
  - LoadBalance
${proxyListString}
  icon: https://raw.githubusercontent.com/Koolson/Qure/master/IconSet/Color/Proxy.png
- name: Auto
  type: url-test
  proxies: &id001
${proxyListString}
  url: https://www.gstatic.com/generate_204
  interval: 300
  tolerance: 50
  lazy: true
- name: Fallback
  type: fallback
  proxies: *id001
  url: https://www.gstatic.com/generate_204
  interval: 300
  lazy: false
- name: LoadBalance
  type: load-balance
  proxies: *id001
  url: https://www.gstatic.com/generate_204
  interval: 300
  strategy: consistent-hashing
- name: Streaming
  type: select
  proxies:
  - Auto
  - LoadBalance
${proxyListString}
- name: Social
  type: select
  proxies:
  - Auto
  - DIRECT
${proxyListString}
- name: Gaming
  type: select
  proxies:
  - Auto
  - LoadBalance
  - DIRECT
${proxyListString}
rules:
- IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
- IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
- IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
- IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
- DOMAIN-SUFFIX,netflix.com,Streaming
- DOMAIN-SUFFIX,youtube.com,Streaming
- DOMAIN-SUFFIX,youtu.be,Streaming
- DOMAIN-SUFFIX,googlevideo.com,Streaming
- DOMAIN-SUFFIX,hulu.com,Streaming
- DOMAIN-SUFFIX,disneyplus.com,Streaming
- DOMAIN-SUFFIX,facebook.com,Social
- DOMAIN-SUFFIX,instagram.com,Social
- DOMAIN-SUFFIX,twitter.com,Social
- DOMAIN-SUFFIX,telegram.org,Social
- DOMAIN-SUFFIX,google.com,PROXY
- DOMAIN-SUFFIX,googleapis.com,PROXY
- DOMAIN-SUFFIX,googleusercontent.com,PROXY
- GEOIP,CN,DIRECT
- GEOIP,PRIVATE,DIRECT,no-resolve
- MATCH,PROXY
profile:
  store-selected: true
  store-fake-ip: true
`;
  return fullConfig;
}
function generateNekoboxConfig(links, isFullConfig = false) {
  const parsedLinks = links.map((link) => parseV2RayLink(link));
  let config = isFullConfig ? `{
  "dns": {
    "final": "dns-final",
    "independent_cache": true,
    "rules": [
      {
        "disable_cache": false,
        "domain": [
          "family.cloudflare-dns.com"
        ],
        "server": "direct-dns"
      }
    ],
    "servers": [
      {
        "address": "https://family.cloudflare-dns.com/dns-query",
        "address_resolver": "direct-dns",
        "strategy": "ipv4_only",
        "tag": "remote-dns"
      },
      {
        "address": "local",
        "strategy": "ipv4_only",
        "tag": "direct-dns"
      },
      {
        "address": "local",
        "address_resolver": "dns-local",
        "strategy": "ipv4_only",
        "tag": "dns-final"
      },
      {
        "address": "local",
        "tag": "dns-local"
      },
      {
        "address": "rcode://success",
        "tag": "dns-block"
      }
    ]
  },
  "experimental": {
    "cache_file": {
      "enabled": true,
      "path": "../cache/clash.db",
      "store_fakeip": true
    },
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "../files/yacd"
    }
  },
  "inbounds": [
    {
      "listen": "0.0.0.0",
      "listen_port": 6450,
      "override_address": "8.8.8.8",
      "override_port": 53,
      "tag": "dns-in",
      "type": "direct"
    },
    {
      "domain_strategy": "",
      "endpoint_independent_nat": true,
      "inet4_address": [
        "172.19.0.1/28"
      ],
      "mtu": 9000,
      "sniff": true,
      "sniff_override_destination": true,
      "stack": "system",
      "tag": "tun-in",
      "type": "tun"
    },
    {
      "domain_strategy": "",
      "listen": "0.0.0.0",
      "listen_port": 2080,
      "sniff": true,
      "sniff_override_destination": true,
      "tag": "mixed-in",
      "type": "mixed"
    }
  ],
  "log": {
    "level": "info"
  },
  "outbounds": [
    {
      "tag": "Internet",
      "type": "selector",
      "outbounds": [
        "Best Latency",
` : `{
  "outbounds": [
`;
  parsedLinks.forEach((link) => {
    config += `        "${link.name}",
`;
  });
  if (isFullConfig) {
    config += `        "direct"
      ]
    },
    {
      "type": "urltest",
      "tag": "Best Latency",
      "outbounds": [
`;
    parsedLinks.forEach((link) => {
      config += `        "${link.name}",
`;
    });
    config += `        "direct"
      ],
      "url": "https://detectportal.firefox.com/success.txt",
      "interval": "1m0s"
    },
`;
  }
  parsedLinks.forEach((link, index) => {
    if (index > 0) config += ",\n";
    config += `    {
`;
    config += `      "tag": "${link.name}",
`;
    if (link.type === "vmess") {
      config += `      "type": "vmess",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "uuid": "${link.uuid}",
`;
      config += `      "alter_id": ${link.alterId || 0},
`;
      config += `      "security": "${link.cipher || "auto"}",
`;
      config += `      "packet_encoding": "xudp",
`;
      config += `      "domain_strategy": "ipv4_only",
`;
      if (link.tls) {
        config += `      "tls": {
`;
        config += `        "enabled": true,
`;
        config += `        "insecure": ${link.skipCertVerify},
`;
        config += `        "server_name": "${link.sni || link.wsHost || link.server}",
`;
        config += `        "utls": {
`;
        config += `          "enabled": true,
`;
        config += `          "fingerprint": "randomized"
`;
        config += `        }
`;
        config += `      },
`;
      }
      if (link.network === "ws") {
        config += `      "transport": {
`;
        config += `        "type": "ws",
`;
        config += `        "path": "${link.wsPath}",
`;
        config += `        "headers": {
`;
        config += `          "Host": "${link.wsHost || link.server}"
`;
        config += `        },
`;
        config += `        "early_data_header_name": "Sec-WebSocket-Protocol"
`;
        config += `      },
`;
      }
      config += `      "multiplex": {
`;
      config += `        "enabled": false,
`;
      config += `        "protocol": "smux",
`;
      config += `        "max_streams": 32
`;
      config += `      }
`;
    } else if (link.type === "vless") {
      config += `      "type": "vless",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "uuid": "${link.uuid}",
`;
      config += `      "flow": "",
`;
      config += `      "packet_encoding": "xudp",
`;
      config += `      "domain_strategy": "ipv4_only",
`;
      if (link.tls) {
        config += `      "tls": {
`;
        config += `        "enabled": true,
`;
        config += `        "insecure": ${link.skipCertVerify},
`;
        config += `        "server_name": "${link.sni || link.wsHost || link.server}",
`;
        config += `        "utls": {
`;
        config += `          "enabled": true,
`;
        config += `          "fingerprint": "randomized"
`;
        config += `        }
`;
        config += `      },
`;
      }
      if (link.network === "ws") {
        config += `      "transport": {
`;
        config += `        "type": "ws",
`;
        config += `        "path": "${link.wsPath}",
`;
        config += `        "headers": {
`;
        config += `          "Host": "${link.wsHost || link.server}"
`;
        config += `        },
`;
        config += `        "early_data_header_name": "Sec-WebSocket-Protocol"
`;
        config += `      },
`;
      }
      config += `      "multiplex": {
`;
      config += `        "enabled": false,
`;
      config += `        "protocol": "smux",
`;
      config += `        "max_streams": 32
`;
      config += `      }
`;
    } else if (link.type === "trojan") {
      config += `      "type": "trojan",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "password": "${link.password}",
`;
      config += `      "domain_strategy": "ipv4_only",
`;
      if (link.tls) {
        config += `      "tls": {
`;
        config += `        "enabled": true,
`;
        config += `        "insecure": ${link.skipCertVerify},
`;
        config += `        "server_name": "${link.sni || link.wsHost || link.server}",
`;
        config += `        "utls": {
`;
        config += `          "enabled": true,
`;
        config += `          "fingerprint": "randomized"
`;
        config += `        }
`;
        config += `      },
`;
      }
      if (link.network === "ws") {
        config += `      "transport": {
`;
        config += `        "type": "ws",
`;
        config += `        "path": "${link.wsPath}",
`;
        config += `        "headers": {
`;
        config += `          "Host": "${link.wsHost || link.server}"
`;
        config += `        },
`;
        config += `        "early_data_header_name": "Sec-WebSocket-Protocol"
`;
        config += `      },
`;
      }
      config += `      "multiplex": {
`;
      config += `        "enabled": false,
`;
      config += `        "protocol": "smux",
`;
      config += `        "max_streams": 32
`;
      config += `      }
`;
    } else if (link.type === "ss") {
      config += `      "type": "shadowsocks",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "method": "${link.cipher || "none"}",
`;
      config += `      "password": "${link.password}",
`;
      config += `      "plugin": "v2ray-plugin",
`;
      config += `      "plugin_opts": "mux=0;path=${link.wsPath};host=${link.wsHost || link.server};tls=${link.tls ? "1" : "0"}"
`;
    }
    config += `    }`;
  });
  if (isFullConfig) {
    config += `,
    {
      "tag": "direct",
      "type": "direct"
    },
    {
      "tag": "bypass",
      "type": "direct"
    },
    {
      "tag": "block",
      "type": "block"
    },
    {
      "tag": "dns-out",
      "type": "dns"
    }
  ],
  "route": {
    "auto_detect_interface": true,
    "rules": [
      {
        "outbound": "dns-out",
        "port": [
          53
        ]
      },
      {
        "inbound": [
          "dns-in"
        ],
        "outbound": "dns-out"
      },
      {
        "network": [
          "udp"
        ],
        "outbound": "block",
        "port": [
          443
        ],
        "port_range": []
      },
      {
        "ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ],
        "outbound": "block",
        "source_ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ]
      }
    ]
  }
}`;
  } else {
    config += `
  ]
}`;
  }
  return config;
}
function generateSingboxConfig(links, isFullConfig = false) {
  const parsedLinks = links.map((link) => parseV2RayLink(link));
  let config = isFullConfig ? `{
  "log": {
    "level": "info"
  },
  "dns": {
    "servers": [
      {
        "tag": "remote-dns",
        "address": "https://8.8.8.8/dns-query",
        "address_resolver": "direct-dns",
        "strategy": "ipv4_only"
      },
      {
        "tag": "direct-dns",
        "address": "local",
        "strategy": "ipv4_only"
      },
      {
        "tag": "dns-final",
        "address": "local",
        "address_resolver": "dns-local",
        "strategy": "ipv4_only"
      },
      {
        "tag": "dns-local",
        "address": "local"
      },
      {
        "tag": "dns-block",
        "address": "rcode://success"
      }
    ],
    "rules": [
      {
        "domain": [
          "8.8.8.8"
        ],
        "server": "direct-dns"
      }
    ],
    "final": "dns-final",
    "independent_cache": true
  },
  "inbounds": [
    {
      "type": "tun",
      "mtu": 1400,
      "inet4_address": "172.19.0.1/30",
      "inet6_address": "fdfe:dcba:9876::1/126",
      "auto_route": true,
      "strict_route": true,
      "endpoint_independent_nat": true,
      "stack": "mixed",
      "sniff": true
    }
  ],
  "outbounds": [
    {
      "tag": "Internet",
      "type": "selector",
      "outbounds": [
        "Best Latency",
` : `{
  "outbounds": [
`;
  parsedLinks.forEach((link) => {
    config += `        "${link.name}",
`;
  });
  if (isFullConfig) {
    config += `        "direct"
      ]
    },
    {
      "type": "urltest",
      "tag": "Best Latency",
      "outbounds": [
`;
    parsedLinks.forEach((link) => {
      config += `        "${link.name}",
`;
    });
    config += `        "direct"
      ],
      "url": "https://www.google.com",
      "interval": "10s"
    },
`;
  }
  parsedLinks.forEach((link, index) => {
    if (index > 0) config += ",\n";
    config += `    {
`;
    config += `      "tag": "${link.name}",
`;
    if (link.type === "vmess") {
      config += `      "type": "vmess",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "uuid": "${link.uuid}",
`;
      config += `      "alter_id": ${link.alterId || 0},
`;
      config += `      "security": "${link.cipher || "zero"}",
`;
      config += `      "packet_encoding": "xudp",
`;
      config += `      "domain_strategy": "ipv4_only",
`;
      if (link.tls) {
        config += `      "tls": {
`;
        config += `        "enabled": true,
`;
        config += `        "server_name": "${link.sni || link.wsHost || link.server}",
`;
        config += `        "insecure": ${link.skipCertVerify},
`;
        config += `        "utls": {
`;
        config += `          "enabled": true,
`;
        config += `          "fingerprint": "randomized"
`;
        config += `        }
`;
        config += `      },
`;
      }
      if (link.network === "ws") {
        config += `      "transport": {
`;
        config += `        "type": "ws",
`;
        config += `        "path": "${link.wsPath}",
`;
        config += `        "headers": {
`;
        config += `          "Host": "${link.wsHost || link.server}"
`;
        config += `        },
`;
        config += `        "early_data_header_name": "Sec-WebSocket-Protocol"
`;
        config += `      },
`;
      }
      config += `      "multiplex": {
`;
      config += `        "enabled": false,
`;
      config += `        "protocol": "smux",
`;
      config += `        "max_streams": 32
`;
      config += `      }
`;
    } else if (link.type === "vless") {
      config += `      "type": "vless",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "uuid": "${link.uuid}",
`;
      config += `      "packet_encoding": "xudp",
`;
      config += `      "domain_strategy": "ipv4_only",
`;
      if (link.tls) {
        config += `      "tls": {
`;
        config += `        "enabled": true,
`;
        config += `        "server_name": "${link.sni || link.wsHost || link.server}",
`;
        config += `        "insecure": ${link.skipCertVerify},
`;
        config += `        "utls": {
`;
        config += `          "enabled": true,
`;
        config += `          "fingerprint": "randomized"
`;
        config += `        }
`;
        config += `      },
`;
      }
      if (link.network === "ws") {
        config += `      "transport": {
`;
        config += `        "type": "ws",
`;
        config += `        "path": "${link.wsPath}",
`;
        config += `        "headers": {
`;
        config += `          "Host": "${link.wsHost || link.server}"
`;
        config += `        },
`;
        config += `        "early_data_header_name": "Sec-WebSocket-Protocol"
`;
        config += `      },
`;
      }
      config += `      "multiplex": {
`;
      config += `        "enabled": false,
`;
      config += `        "protocol": "smux",
`;
      config += `        "max_streams": 32
`;
      config += `      }
`;
    } else if (link.type === "trojan") {
      config += `      "type": "trojan",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "password": "${link.password}",
`;
      config += `      "domain_strategy": "ipv4_only",
`;
      if (link.tls) {
        config += `      "tls": {
`;
        config += `        "enabled": true,
`;
        config += `        "server_name": "${link.sni || link.wsHost || link.server}",
`;
        config += `        "insecure": ${link.skipCertVerify},
`;
        config += `        "utls": {
`;
        config += `          "enabled": true,
`;
        config += `          "fingerprint": "randomized"
`;
        config += `        }
`;
        config += `      },
`;
      }
      if (link.network === "ws") {
        config += `      "transport": {
`;
        config += `        "type": "ws",
`;
        config += `        "path": "${link.wsPath}",
`;
        config += `        "headers": {
`;
        config += `          "Host": "${link.wsHost || link.server}"
`;
        config += `        },
`;
        config += `        "early_data_header_name": "Sec-WebSocket-Protocol"
`;
        config += `      },
`;
      }
      config += `      "multiplex": {
`;
      config += `        "enabled": false,
`;
      config += `        "protocol": "smux",
`;
      config += `        "max_streams": 32
`;
      config += `      }
`;
    } else if (link.type === "ss") {
      config += `      "type": "shadowsocks",
`;
      config += `      "server": "${link.server}",
`;
      config += `      "server_port": ${link.port},
`;
      config += `      "method": "${link.cipher || "none"}",
`;
      config += `      "password": "${link.password}",
`;
      config += `      "plugin": "v2ray-plugin",
`;
      config += `      "plugin_opts": "mux=0;path=${link.wsPath};host=${link.wsHost || link.server};tls=${link.tls ? "1" : "0"}"
`;
    }
    config += `    }`;
  });
  if (isFullConfig) {
    config += `,
    {
      "type": "direct",
      "tag": "direct"
    },
    {
      "type": "direct",
      "tag": "bypass"
    },
    {
      "type": "block",
      "tag": "block"
    },
    {
      "type": "dns",
      "tag": "dns-out"
    }
  ],
  "route": {
    "rules": [
      {
        "port": 53,
        "outbound": "dns-out"
      },
      {
        "inbound": "dns-in",
        "outbound": "dns-out"
      },
      {
        "network": "udp",
        "port": 443,
        "outbound": "block"
      },
      {
        "source_ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ],
        "ip_cidr": [
          "224.0.0.0/3",
          "ff00::/8"
        ],
        "outbound": "block"
      }
    ],
    "auto_detect_interface": true
  },
  "experimental": {
    "cache_file": {
      "enabled": false
    },
    "clash_api": {
      "external_controller": "127.0.0.1:9090",
      "external_ui": "ui",
      "external_ui_download_url": "https://github.com/MetaCubeX/metacubexd/archive/gh-pages.zip",
      "external_ui_download_detour": "Internet",
      "secret": "stupid",
      "default_mode": "rule"
    }
  }
}`;
  } else {
    config += `
  ]
}`;
  }
  return config;
}

// src/converter/converter.js
// src/converter/converter.js
const Converterbot = class {
  constructor(token, apiUrl, ownerId, env) {
    this.token = token;
    this.apiUrl = apiUrl || "https://api.telegram.org";
    this.ownerId = ownerId;
    this.kv = env.GEO_DB;
    this.groupId = -1002042632790;
  }

  async _checkGroupMembership(update) {
    const from = update.message?.from || update.callback_query?.from;
    const chat = update.message?.chat || update.callback_query?.message?.chat;
    const message = update.message || update.callback_query?.message;

    if (!from || !chat || !message) {
      return true; // Don't block if we can't determine the user
    }
    
    // Owner is always allowed
    const userId = from.id;
    if (userId.toString() === this.ownerId.toString()) {
      return true;
    }

    const groupId = "@auto_sc";
    try {
      const member = await this.getChatMember(groupId, userId);
      if (member.ok && ["member", "administrator", "creator"].includes(member.result.status)) {
        return true;
      }
    } catch (error) {
      console.error("Error checking group membership:", error);
    }

    // If not a member, send the join message
    const chatId = chat.id;
    const messageId = message.message_id;
    const message_thread_id = message.message_thread_id;
    const options = message_thread_id ? { message_thread_id } : {};

    if (update.callback_query) {
      await this.answerCallbackQuery(update.callback_query.id, { text: "Anda harus bergabung dengan grup untuk menggunakan bot ini.", show_alert: true });
    } else {
      await this.sendMessage(chatId,
        "  *Akses Dibatasi*\n\nAnda harus bergabung dengan grup terlebih dahulu untuk menggunakan bot ini.", {
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [{ text: "✅ Gabung Grup Sekarang", url: "https://t.me/auto_sc" }],
            [{ text: "🔄 Coba Lagi", callback_data: "retry_join" }]
          ]
        },
        reply_to_message_id: messageId,
        ...options
      });
    }
    return false;
  }

  // Format broadcast message with premium styling
  formatBroadcastMessage(message, type = 'text') {
    const timestamp = new Date().toLocaleDateString('en-US', {
      weekday: 'long',
      year: 'numeric',
      month: 'long',
      day: 'numeric'
    });

    const footer = `\n\n┅┅┅┅┅┅┅┅┅┅┅┅\n📅 ${timestamp}\n_✨ Official message from admin_`;

    // Premium styling based on content type
    let styledMessage = message;
    const styles = {
      text: {
        icon: "📢",
        title: "BROADCAST MESSAGE",
      },
      photo: {
        icon: "🖼️",
        title: "GALLERY UPDATE",
      },
      video: {
        icon: "🎥",
        title: "VIDEO UPDATE",
      }
    };

    const style = styles[type];
    styledMessage = `${style.color} ${style.icon} *${style.title}* ${style.icon} ${style.color}\n\n${message}`;

    return styledMessage + footer;
  }

  // Format media caption with elegant styling
  formatMediaCaption(caption, mediaType) {
    const styles = {
      photo: {
        icon: "🖼️",
        title: "GALLERY UPDATE",
      },
      video: {
        icon: "🎬", 
        title: "VIDEO UPDATE",
      }
    };
    
    const style = styles[mediaType];
    return `${style.color} ${style.icon} *${style.title}*\n\n${caption || '📝 No description'}\n\n┅┅┅┅┅┅┅┅┅┅┅┅\n_✨ Broadcast message from admin_`;
  }

  // Format user-friendly error message
  formatErrorMessage(message) {
    return `❌ *ERROR*\n\n${message}\n\n🔧 Please try again or contact the admin if the problem persists.`;
  }

  // Format success message
  formatSuccessMessage(message) {
    return `✅ *SUCCESS*\n\n${message}\n\n🎉 Enjoy!`;
  }

  async generateUserListPage(page) {
    const allUsers = await this.getAllUsers() || [];
    let totalUsers = allUsers.length;

    if (totalUsers === 0) {
        return { 
            messageText: "👥 *No registered users yet.*\n\n📝 *Users will be automatically registered when they interact with the bot.*", 
            keyboard: [[backToMenuButton]] 
        };
    }

    // Real-time group membership check
    const membershipChecks = allUsers.map(user => this.getChatMember('@auto_sc', user.id));
    const results = await Promise.allSettled(membershipChecks);

    let currentGroupMembers = 0;
    const kvUpdatePromises = [];

    results.forEach((result, index) => {
        const user = allUsers[index];
        let isMember = false;
        if (result.status === 'fulfilled' && result.value.ok) {
            const status = result.value.result.status;
            isMember = ['member', 'administrator', 'creator'].includes(status);
        }
        
        if (isMember) {
            currentGroupMembers++;
        }

        // Update KV store if the status is different
        if (user.is_group_member !== isMember) {
            user.is_group_member = isMember;
            kvUpdatePromises.push(this.kv.put(`user:${user.id}`, JSON.stringify(user)));
        }
    });

    // Wait for all KV updates to finish
    await Promise.all(kvUpdatePromises);

    const pageSize = 10;
    const totalPages = Math.ceil(totalUsers / pageSize);
    const start = page * pageSize;
    const end = start + pageSize;
    const pageUsers = allUsers.slice(start, end);

    const userListText = pageUsers.map((user, index) => {
        const userNumber = start + index + 1;
        const userId = typeof user === "object" ? user.id : user;
        const username = typeof user === "object" ? user.username : null;
        const isMember = user.is_group_member ? "🟢" : "🟢";
        
        const escapeMarkdown = (text) => {
            if (text === null || typeof text === 'undefined') {
                return '';
            }
            return text.toString().replace(/([_*\[\]()~`>#+\-=|{}.!])/g, '\\$1');
        };
        
        let userLine = `${isMember} **${userNumber}.**`;
        if (username && username !== "N/A") {
            userLine += ` @${escapeMarkdown(username)}`;
        }
        const idLine = `🆔 ID: \`${userId}\``;
        return `${userLine}\n${idLine}`;
    }).join("\n\n");

    const messageText = `📊 **BOT USER LIST**\n
┅┅┅┅┅┅┅┅┅┅┅┅
👥 **Total Group Users:** ${currentGroupMembers} Active Users
🤖 **Total Bot Users:** ${totalUsers} Users
📑 **Page:** ${page + 1}/${totalPages}
┅┅┅┅┅┅┅┅┅┅┅┅

${userListText}`;

    const keyboard = [];
    const row = [];

    if (page > 0) {
        row.push({ text: "⬅️ Prev", callback_data: `userlist_page_${page - 1}` });
    }
    if (page < totalPages - 1) {
        row.push({ text: "Next ➡️", callback_data: `userlist_page_${page + 1}` });
    }

    if (row.length > 0) {
        keyboard.push(row);
    }

    keyboard.push([
        { text: "🔄 Reload", callback_data: "userlist_page_0" },
        backToMenuButton
    ]);

    return { messageText, keyboard };
  }

  async handleUpdate(update) {
    if (update.callback_query) {
      return this.handleCallbackQuery(update.callback_query);
    }
    if (!update.message) return new Response("OK", { status: 200 });
    
    if (update.message.new_chat_members) {
      for (const member of update.message.new_chat_members) {
        await this.addUserToKv(member, update.message.chat, true);
      }
    }

    if (update.message.left_chat_member) {
      await this.addUserToKv(update.message.left_chat_member, update.message.chat, false);
    }
    
    const chatId = update.message.chat.id;
    const text = update.message.text || "";
    const caption = update.message.caption || "";
    const messageId = update.message.message_id;
    const reply = update.message.reply_to_message;
    const message_thread_id = update.message.message_thread_id;
    const options = message_thread_id ? { message_thread_id } : {};
    
    // Handler untuk broadcast message (admin only)
    if (update.message.from.id.toString() === this.ownerId.toString()) {
      // Cek apakah admin sedang dalam proses broadcast
      if (broadcastState.has(chatId)) {
        const lockKey = `broadcast_lock_${messageId}`;
        const isLocked = await this.kv.get(lockKey);

        if (isLocked) {
          return new Response("OK", { status: 200 });
        }
        await this.kv.put(lockKey, "locked", { expirationTtl: 60 });

        broadcastState.delete(chatId); // Hapus state setelah pesan diterima

        // Hardcode target topic ID
        const broadcastOptions = { ...options, message_thread_id: 1876 };

        if (update.message.photo) {
          const file_id = update.message.photo[update.message.photo.length - 1].file_id;
          const formattedCaption = this.formatMediaCaption(caption, 'photo');
          await this.sendBroadcastPhoto(file_id, formattedCaption, broadcastOptions);
        } else if (update.message.video) {
          const file_id = update.message.video.file_id;
          const formattedCaption = this.formatMediaCaption(caption, 'video');
          await this.sendBroadcastVideo(file_id, formattedCaption, broadcastOptions);
        } else if (text) {
          const formattedMessage = this.formatBroadcastMessage(text, 'text');
          await this.sendBroadcastMessage(formattedMessage, broadcastOptions);
        } else {
          await this.sendMessage(chatId, "Message format not supported for broadcast.", { reply_to_message_id: messageId, ...options });
        }
        return new Response("OK", { status: 200 });
      }

      if (text.startsWith("/broadcast")) {
        broadcastState.set(chatId, { step: 'awaiting_message' });
        await this.sendMessage(chatId, 
          " Please send the message you want to broadcast (text, image, or video).", 
          {
            reply_markup: {
              inline_keyboard: [[{ text: " Cancel", callback_data: "cancel_broadcast" }]]
            },
            reply_to_message_id: messageId, 
            ...options 
          }
        );
        return new Response("OK", { status: 200 });
      }
    }

    // Handle userlist command
    if (text.startsWith("/userlist")) {
        const targetMessageId = menuMessageIds.get(chatId) || messageId;
        const loadingMessage = await this.sendMessage(chatId, "  *Loading user list...*", { parse_mode: "Markdown", reply_to_message_id: targetMessageId, ...options });
        let messageIdToDelete;

        if (loadingMessage && loadingMessage.result) {
            messageIdToDelete = loadingMessage.result.message_id;
        }

        try {
            const { messageText, keyboard } = await this.generateUserListPage(0);
            await this.sendMessage(chatId, messageText, {
                reply_markup: {
                    inline_keyboard: keyboard
                },
                parse_mode: "Markdown",
                reply_to_message_id: targetMessageId,
                ...options
            });
        } finally {
            if (messageIdToDelete) {
                await this.deleteMessage(chatId, messageIdToDelete);
            }
        }
        return new Response("OK", { status: 200 });
    }

    
    // Handler untuk command converter
    if (/^\/converter(@\w+)?$/.test(text)) {
      const targetMessageId = menuMessageIds.get(chatId) || messageId;
      await this.sendMessage(
        chatId,
        ` *Geo Project Bot - Converter*\n
 *Fitur Konversi Link Konfigurasi*

Kirimkan link konfigurasi V2Ray dan saya akan mengubahnya ke format:
  *Singbox*
  *Nekobox* 
  *Clash*

** Contoh Format yang Diterima:**
\`vless://...\`
\`vmess://...\` 
\`trojan://...\`
\`ss://...\`

** Ketentuan:**
  Maksimal 10 link per permintaan
  Disarankan menggunakan *Singbox versi 1.10.3* atau *1.11.8*
  Proses konversi otomatis & cepat

 *Kirim link Anda sekarang!*`,
        { 
          parse_mode: "Markdown",
          reply_to_message_id: targetMessageId,
          ...options
        }
      );
      return new Response("OK", { status: 200 });
    }

    // Handler untuk konversi link
    if (text.includes("://")) {
      try {
        const links = text.split("\n")
          .map(line => line.trim())
          .filter(line => line.includes("://"))
          .slice(0, 10);
        
        if (links.length === 0) {
          await this.sendMessage(
            chatId, 
            " *Tidak Ada Link Valid*\n\nTidak ditemukan link yang dapat diproses. Pastikan format link sesuai:\n\n `vless://...`\n `vmess://...`\n `trojan://...`\n `ss://...`",
            { 
              parse_mode: "Markdown",
              reply_to_message_id: messageId, 
              ...options 
            }
          );
          return new Response("OK", { status: 200 });
        }
        
        // Kirim pesan processing
        const processingMsg = await this.sendMessage(
          chatId,
          ` *Memproses ${links.length} Link...*\n\n Sedang mengkonversi ke berbagai format, harap tunggu sebentar...`,
          { 
            parse_mode: "Markdown",
            reply_to_message_id: messageId,
            ...options 
          }
        );

        // Proses konversi
        const clashConfig = generateClashConfig(links, true);
        const clashConfigSimple = generateClashConfig(links, false);
        const nekoboxConfig = generateNekoboxConfig(links, true);
        const singboxConfig = generateSingboxConfig(links, true);
        
        // Hapus pesan processing
        await this.deleteMessage(chatId, processingMsg.result.message_id);
        
        // Kirim hasil konversi
        await this.sendMessage(
          chatId,
          ` *Konversi Berhasil!*\n\n Mengirim ${links.length} konfigurasi dalam 4 format berbeda...`,
          {
            parse_mode: "Markdown",
            reply_to_message_id: messageId,
            ...options
          }
        );
        
        await this.sendDocument(chatId, clashConfig, "clash.yaml", "text/yaml", { 
          caption: " *Clash Configuration*",
          parse_mode: "Markdown",
          ...options 
        });
        await this.sendDocument(chatId, clashConfigSimple, "clash-simple.yaml", "text/yaml", {
          caption: " *Clash Configuration (Simple)*",
          parse_mode: "Markdown",
          ...options
        });
        await this.sendDocument(chatId, nekoboxConfig, "nekobox.json", "application/json", { 
          caption: " *Nekobox Configuration*",
          parse_mode: "Markdown",
          ...options 
        });
        await this.sendDocument(chatId, singboxConfig, "singbox.bpf", "application/json", { 
          caption: " *Singbox Configuration*", 
          parse_mode: "Markdown",
          ...options 
        });

        await this.sendMessage(
          chatId,
          " *Semua file telah terkirim!*",
          {
            parse_mode: "Markdown",
            reply_markup: {
              inline_keyboard: [[backToMenuButton]]
            },
            ...options
          }
        );
        
      } catch (error) {
        console.error("Error processing links:", error);
        await this.sendMessage(
          chatId, 
          this.formatErrorMessage(`Gagal memproses link:\n\`${error.message}\``),
          { 
            parse_mode: "Markdown",
            reply_to_message_id: messageId, 
            ...options 
          }
        );
      }
      return new Response("OK", { status: 200 });
    }

    // Handler untuk command start
    if (text.startsWith("/randomconfig")) {
        const targetMessageId = menuMessageIds.get(chatId) || messageId;
        const loadingMsg = await this.sendMessage(chatId, " *Membuat konfigurasi acak...*", { parse_mode: "Markdown", reply_to_message_id: targetMessageId, ...options });
        let messageIdToDelete;
        if (loadingMsg && loadingMsg.result) {
            messageIdToDelete = loadingMsg.result.message_id;
        }
        try {
            const configText = await randomconfig();
            await this.sendMessage(chatId, configText, {
                parse_mode: "Markdown",
                reply_to_message_id: targetMessageId,
                ...options,
                reply_markup: {
                    inline_keyboard: [[backToMenuButton]]
                }
            });
        } catch (error) {
            console.error("Error generating random config:", error);
            await this.sendMessage(chatId, ` Terjadi kesalahan:\n${error.message}`, { reply_to_message_id: targetMessageId, ...options });
        } finally {
            if (messageIdToDelete) {
                await this.deleteMessage(chatId, messageIdToDelete);
            }
        }
        return new Response("OK", { status: 200 });
    }

    // Handler untuk command start
    if (/^\/start(@\w+)?$/.test(text)) {
      await this.addUserToKv(update.message.from, update.message.chat);
      const imageUrl = "https://github.com/jaka8m/BOT-CONVERTER/raw/main/start.png";
      const targetMessageId = menuMessageIds.get(chatId) || messageId;
      try {
        await this.sendPhoto(chatId, imageUrl, {
          caption: `
 *WELCOME TO PHREAKER BOT* 

 *Cara Penggunaan:*
1 Masukkan alamat IP dan port yang ingin Anda cek
2 Jika tidak memasukkan port, default adalah *443*
3 Tunggu beberapa detik untuk hasilnya

 *Command Tersedia:*
 /start - Menu awal bot
 /converter - Konversi config
 /menu - Lihat semua command

 *Format IP yang Diterua:*
 \`176.97.78.80\`
 \`176.97.78.80:2053\`

 *Catatan Penting:*
 Jika status *DEAD*, Akun *VLESS*, *SS*, dan *TROJAN* tidak akan dibuat

 *Terima kasih telah menggunakan layanan kami!*`,
          parse_mode: "Markdown",
          reply_markup: {
            inline_keyboard: [
              [
                { text: "👤 GEO PROJECT", url: "https://t.me/sampiiiiu" },
                { text: "👥 JOIN GROUP", url: "https://t.me/auto_sc" }
              ],
              [
                { text: "🌐 WEB VPN", url: "https://joss.dus.biz.id" },
                { text: "📢 CHANNEL", url: "https://t.me/testikuy_mang" }
              ]
            ]
          },
          reply_to_message_id: targetMessageId,
          ...options
        });
      } catch (error) {
        console.error("Error sending photo:", error);
        // Fallback ke text message jika gagal kirim photo
        await this.sendMessage(chatId,
          "  *Selamat Datang di Phreaker Bot!*\n\nSilakan gunakan /menu untuk melihat semua command yang tersedia.",
          { parse_mode: "Markdown", reply_to_message_id: targetMessageId, ...options }
        );
      }
      return new Response("OK", { status: 200 });
    }
    
    return new Response("OK", { status: 200 });
  }
    
  async addUserToKv(from, chat, isGroupMember = false) {
    if (!this.kv) {
        return;
    }
    try {
        if (from && from.id) {
            const userId = from.id.toString();
            const userKey = `user:${userId}`;

            // Get existing user data if it exists
            let userData = await this.kv.get(userKey, "json");
            
            if (!userData) {
                userData = {
                    id: from.id,
                    first_name: from.first_name || null,
                    last_name: from.last_name || null,
                    username: from.username || null,
                    joined_at: new Date().toISOString(),
                    is_group_member: false
                };
            }

            // Update data
            userData.first_name = from.first_name || userData.first_name;
            userData.last_name = from.last_name || userData.last_name;
            userData.username = from.username || userData.username;
            userData.is_group_member = isGroupMember;
            
            await this.kv.put(userKey, JSON.stringify(userData));
        }

        if (chat && chat.id < 0) {
            const chatId = chat.id.toString();
            const chatData = {
                id: chat.id,
                title: chat.title || null,
                type: chat.type || null,
                added_at: new Date().toISOString()
            };
            await this.kv.put(`chat:${chatId}`, JSON.stringify(chatData));
        }
    } catch (error) {
        console.error("Failed to add user or group to KV:", error);
    }
  }

  async sendMessage(chatId, text, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/sendMessage`;
    const body = {
      chat_id: chatId,
      text,
      parse_mode: "Markdown",
      ...options
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  async editMessageText(chatId, messageId, text, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/editMessageText`;
    const body = {
      chat_id: chatId,
      message_id: messageId,
      text,
      ...options
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }

  async sendDocument(chatId, content, filename, mimeType, options = {}) {
    const formData = new FormData();
    const blob = new Blob([content], { type: mimeType });
    formData.append("document", blob, filename);
    formData.append("chat_id", chatId.toString());

    for (const key in options) {
      if (options.hasOwnProperty(key)) {
        formData.append(key, options[key].toString());
      }
    }
    
    const response = await fetch(
      `${this.apiUrl}/bot${this.token}/sendDocument`,
      {
        method: "POST",
        body: formData
      }
    );
    return response.json();
  }

  async sendPhoto(chatId, photo, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/sendPhoto`;
    const body = {
      chat_id: chatId,
      photo,
      parse_mode: "Markdown",
      ...options
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }

  async sendVideo(chatId, video, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/sendVideo`;
    const body = {
      chat_id: chatId,
      video,
      parse_mode: "Markdown",
      ...options
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }

  async deleteMessage(chatId, messageId) {
    const url = `${this.apiUrl}/bot${this.token}/deleteMessage`;
    const body = {
      chat_id: chatId,
      message_id: messageId
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }

  async getAllUsers() {
    if (!this.kv) {
        return [];
    }
    try {
        const list = await this.kv.list({
            prefix: "user:"
        });
        const users = [];
        for (const key of list.keys) {
            const userData = await this.kv.get(key.name, "json");
            if (userData) {
                users.push(userData);
            }
        }
        return users;
    } catch (error) {
        console.error("Failed to get all users from KV:", error);
        return [];
    }
  }

  async sendBroadcastMessage(message, options = {}) {
    const users = await this.getAllUsers();
    let successfulSends = 0;
    let failedSends = 0;

    // Kirim pesan broadcast dimulai
    await this.sendMessage(this.ownerId, 
      `  *Starting Broadcast...*\n\n  Total recipients: ${users.length} users\n  Estimated time: ${Math.ceil(users.length * 0.1)} seconds`,
      { parse_mode: "Markdown" }
    );

    for (const user of users) {
        try {
            await new Promise(resolve => setTimeout(resolve, 100)); // Rate limiting
            const response = await this.sendMessage(user.id, message);
            if (response && response.ok) {
                successfulSends++;
            } else {
                failedSends++;
            }
        } catch (error) {
            console.error(`Failed to send message to user ${user.id}:`, error);
            failedSends++;
        }
    }

    let groupSendStatus = "  Failed";
    try {
        const response = await this.sendMessage(this.groupId, message, options);
        if (response && response.ok) {
            groupSendStatus = "  Success";
        }
    } catch (error) {
        console.error(`Failed to send message to group ${this.groupId}:`, error);
    }

    const summary = `  *Broadcast Report Completed*\n\n` +
      `  *User Statistics:*\n` +
      `  Succeed: ${successfulSends}\n` +
      `  Fail: ${failedSends}\n` +
      ` Success Rate: ${((successfulSends / users.length) * 100).toFixed(1)}%\n\n` +
      `  *Group Statistics:*\n` +
      `Status: ${groupSendStatus}`;
    
    await this.sendMessage(this.ownerId, summary, { parse_mode: "Markdown" });
  }

  async sendBroadcastPhoto(file_id, caption, options = {}) {
    const users = await this.getAllUsers();
    let successfulSends = 0;
    let failedSends = 0;

    await this.sendMessage(this.ownerId,
      `   *Starting Photo Broadcast...*\n\n  Total recipients: ${users.length} users`,
      { parse_mode: "Markdown" }
    );

    for (const user of users) {
        try {
            await new Promise(resolve => setTimeout(resolve, 100));
            const response = await this.sendPhoto(user.id, file_id, { caption, parse_mode: "Markdown" });
            if (response && response.ok) {
                successfulSends++;
            } else {
                failedSends++;
            }
        } catch (error) {
            console.error(`Failed to send photo to user ${user.id}:`, error);
            failedSends++;
        }
    }

    let groupSendStatus = "  Failed";
    try {
        const response = await this.sendPhoto(this.groupId, file_id, { caption, parse_mode: "Markdown", ...options });
        if (response && response.ok) {
            groupSendStatus = "  Success";
        }
    } catch (error) {
        console.error(`Failed to send photo to group ${this.groupId}:`, error);
    }

    const summary = ` *Photo Broadcast Report Completed*\n\n` +
      ` *User Statistics:*\n` +
      ` Succeed: ${successfulSends}\n` +
      ` Fail: ${failedSends}\n\n` +
      ` *Group Statistics:*\n` +
      `Status: ${groupSendStatus}`;
      
    await this.sendMessage(this.ownerId, summary, { parse_mode: "Markdown" });
  }

  async sendBroadcastVideo(file_id, caption, options = {}) {
    const users = await this.getAllUsers();
    let successfulSends = 0;
    let failedSends = 0;

    await this.sendMessage(this.ownerId,
      `  *Starting Video Broadcast...*\n\n  Total recipients: ${users.length} users`,
      { parse_mode: "Markdown" }
    );

    for (const user of users) {
        try {
            await new Promise(resolve => setTimeout(resolve, 100));
            const response = await this.sendVideo(user.id, file_id, { caption, parse_mode: "Markdown" });
            if (response && response.ok) {
                successfulSends++;
            } else {
                failedSends++;
            }
        } catch (error) {
            console.error(`Failed to send video to user ${user.id}:`, error);
            failedSends++;
        }
    }
    
    let groupSendStatus = "  Failed";
    try {
        const response = await this.sendVideo(this.groupId, file_id, { caption, parse_mode: "Markdown", ...options });
        if (response && response.ok) {
            groupSendStatus = "  Success";
        }
    } catch (error) {
        console.error(`Failed to send video to group ${this.groupId}:`, error);
    }

    const summary = ` *Video Broadcast Report Completed*\n\n` +
      ` *User Statistics:*\n` +
      ` Succeed: ${successfulSends}\n` +
      ` Fail: ${failedSends}\n\n` +
      ` *Group Statistics:*\n` +
      `Status: ${groupSendStatus}`;
      
    await this.sendMessage(this.ownerId, summary, { parse_mode: "Markdown" });
  }

  async handleCallbackQuery(callbackQuery) {
    const data = callbackQuery.data;
    const chatId = callbackQuery.message.chat.id;
    const messageId = callbackQuery.message.message_id;
    const message_thread_id = callbackQuery.message.message_thread_id;
    const options = message_thread_id ? { message_thread_id } : {};

    if (data === "cancel_broadcast") {
      if (broadcastState.has(chatId)) {
        broadcastState.delete(chatId);
        await this.editMessageText(chatId, messageId, "  *Broadcast canceled.*", { ...options });
      }
      await this.answerCallbackQuery(callbackQuery.id);
      return new Response("OK", { status: 200 });
    }

    if (data === 'retry_join') {
      await this.deleteMessage(chatId, messageId);
      // Create a fake update to re-trigger the /start command logic
      const fakeUpdate = {
        message: {
          ...callbackQuery.message,
          text: '/start',
          from: callbackQuery.from
        }
      };
      // Re-call the main handler to process the faked /start command
      await this.handleUpdate(fakeUpdate);
      await this.answerCallbackQuery(callbackQuery.id);
      return new Response("OK", { status: 200 });
    }

    if (data.startsWith("userlist_page_")) {
        const page = parseInt(data.split("_")[2], 10);
        const { messageText, keyboard } = await this.generateUserListPage(page);
        await this.editMessageText(chatId, messageId, messageText, {
            reply_markup: {
                inline_keyboard: keyboard
            },
            parse_mode: "Markdown",
            ...options
        });
    } else if (data === "show_config_guide") {
      const helpMsg = `\u{1F31F} *ROTATE CONFIG GUIDE* \u{1F31F}

Type the following command to get a rotated config based on the country:

\`rotate + country_code\`

Available countries:
id, sg, my, us, ca, in, gb, ir, ae, fi, tr, md, tw, ch, se, nl, es, ru, ro, pl, al, nz, mx, it, de, fr, am, cy, dk, br, kr, vn, th, hk, cn, jp.

Example:
\`rotate id\`
\`rotate sg\`
\`rotate my\`

The bot will randomly select an IP from that country and send its config.`;
      await this.editMessageText(chatId, messageId, helpMsg, {
        parse_mode: "Markdown",
        ...options,
        reply_markup: {
          inline_keyboard: [[{ text: "⬅️ Back to Menu", callback_data: "menu_page_0" }]]
        }
      });
    }
    
    await this.answerCallbackQuery(callbackQuery.id);
    return new Response("OK", { status: 200 });
  }

  async editMessageText(chatId, messageId, text, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/editMessageText`;
    const body = {
      chat_id: chatId,
      message_id: messageId,
      text,
      ...options
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }

  async answerCallbackQuery(callbackQueryId) {
    const url = `${this.apiUrl}/bot${this.token}/answerCallbackQuery`;
    const body = { callback_query_id: callbackQueryId };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }

  async getChatMember(chatId, userId) {
    const url = `${this.apiUrl}/bot${this.token}/getChatMember`;
    const body = {
      chat_id: chatId,
      user_id: userId
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
};

// src/randomconfig.js
function generateUUID() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === "x" ? r : r & 3 | 8;
    return v.toString(16);
  });
}
async function randomconfig() {
  try {
    const HOSTKU2 = "joss.dus.biz.id";
    const GITHUB_BASE_URL = "https://raw.githubusercontent.com/jaka2m/botak/main/cek/";
    const proxyResponse = await fetch(`${GITHUB_BASE_URL}proxyList.txt`);
    if (!proxyResponse.ok) {
      return "⚠️ Failed to fetch proxy list.";
    }
    const ipText = await proxyResponse.text();
    const ipLines = ipText.split("\n").filter((line) => line.trim() !== "");
    if (ipLines.length === 0) {
      return "⚠️ Proxy list is empty or invalid.";
    }
    const randomIndex = Math.floor(Math.random() * ipLines.length);
    const randomProxyLine = ipLines[randomIndex];
    const sequenceNumber = randomIndex + 1;
    const [ip, port, country, provider] = randomProxyLine.split(",");
    if (!ip || !port) {
      return "⚠️ Incomplete IP or Port data from proxy list.";
    }
    const checkResponse = await fetch(`https://api.sampi.workers.dev/check?ip=${ip}:${port}`);
    if (!checkResponse.ok) {
      return `⚠️ Failed to check status for IP ${ip}:${port}.`;
    }
    const text = await checkResponse.text();
    let data;
    try {
      data = JSON.parse(text);
    } catch (e) {
        return `⚠️ Failed to parse response from server for IP ${ip}:${port}. Response: ${text}`;
    }
    if (data.status?.toUpperCase() !== "ACTIVE") {
      return `⚠️ IP ${ip}:${port} is not active.`;
    }
    const pathIPPORT = `/Free-VPN-CF-Geo-Project/${ip}=${port}`;
    const pathCD = `/Free-VPN-CF-Geo-Project/${data.countryCode}${sequenceNumber}`;
    const toBase642 = (str) => {
      if (typeof btoa === "function") {
        return btoa(unescape(encodeURIComponent(str)));
      } else if (typeof Buffer !== "undefined") {
        return Buffer.from(str, "utf-8").toString("base64");
      } else {
        return encodeURIComponent(str);
      }
    };
    const infoMessage = `
IP      : ${data.ip}
PORT    : ${data.port}
ISP     : ${data.isp}
COUNTRY : ${data.country}
DELAY   : ${data.delay}
STATUS  : ${data.status}
`;
    const vlessUUID = generateUUID();
    const trojanUUID = generateUUID();
    const ssPassword = generateUUID();
    const vlessTLSLink1 = `vless://${vlessUUID}@${HOSTKU2}:443?encryption=none&security=tls&sni=${HOSTKU2}&fp=randomized&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(pathIPPORT)}#${encodeURIComponent(provider)}%20${encodeURIComponent(country)}`;
    const trojanTLSLink1 = `trojan://${trojanUUID}@${HOSTKU2}:443?security=tls&sni=${HOSTKU2}&fp=randomized&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(pathIPPORT)}#${encodeURIComponent(provider)}%20${encodeURIComponent(country)}`;
    const ssTLSLink1 = `ss://${toBase642(`none:${ssPassword}`)}@${HOSTKU2}:443?encryption=none&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(pathIPPORT)}&security=tls&sni=${HOSTKU2}#${encodeURIComponent(provider)}%20${encodeURIComponent(country)}`;
    const vlessTLSLink2 = `vless://${vlessUUID}@${HOSTKU2}:443?encryption=none&security=tls&sni=${HOSTKU2}&fp=randomized&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(pathCD)}#${encodeURIComponent(provider)}%20${encodeURIComponent(country)}`;
    const trojanTLSLink2 = `trojan://${trojanUUID}@${HOSTKU2}:443?security=tls&sni=${HOSTKU2}&fp=randomized&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(pathCD)}#${encodeURIComponent(provider)}%20${encodeURIComponent(country)}`;
    const ssTLSLink2 = `ss://${toBase642(`none:${ssPassword}`)}@${HOSTKU2}:443?encryption=none&type=ws&host=${HOSTKU2}&path=${encodeURIComponent(pathCD)}&security=tls&sni=${HOSTKU2}#${encodeURIComponent(provider)}%20${encodeURIComponent(country)}`;
    const configText = `
\`\`\`INFORMATION
${infoMessage}
\`\`\`
\`\`\`VLESS-TLS
${vlessTLSLink1}
\`\`\`
\`\`\`TROJAN-TLS
${trojanTLSLink1}
\`\`\`
\`\`\`SHADOWSOCKS-TLS
${ssTLSLink1}
\`\`\`

(Country Code Path : ${data.countryCode}${sequenceNumber})

\`\`\`VLESS-TLS
${vlessTLSLink2}
\`\`\`
\`\`\`TROJAN-TLS
${trojanTLSLink2}
\`\`\`
\`\`\`SHADOWSOCKS-TLS
${ssTLSLink2}
\`\`\`

\u{1F468}\u200D\u{1F4BB} Developer : [GEO PROJECT](https://t.me/sampiiiiu)
`;
    return configText;
  } catch (error) {
    console.error("An error occurred:", error);
    return `⚠️ An error occurred: ${error.message}`;
  }
}

// src/config.js
async function rotateconfig(chatId, text, options = {}) {
  const command = text.trim();
  const args = command.split(" ");
  if (args.length < 2) {
    await this.sendMessage(chatId, `⚠️ *Incorrect format! Please use the following example:*
\`/rotate id\``, {
      parse_mode: "Markdown",
      ...options,
      reply_markup: {
        inline_keyboard: [[{ text: "⬅️ Back to Config", callback_data: "show_config_guide" }]]
      }
    });
    return;
  }
  
  const countryCode = args[1].toLowerCase();
  const validCountries = [
    "id", "sg", "my", "us", "ca", "in", "gb", "ir", "ae", "fi", 
    "tr", "md", "tw", "ch", "se", "nl", "es", "ru", "ro", "pl", 
    "al", "nz", "mx", "it", "de", "fr", "am", "cy", "dk", "br", 
    "kr", "vn", "th", "hk", "cn", "jp"
  ];
  
  if (!validCountries.includes(countryCode)) {
    await this.sendMessage(chatId, `⚠️ *Invalid country code! Please use one of the available codes.*`, {
      parse_mode: "Markdown",
      ...options,
      reply_markup: {
        inline_keyboard: [[{ text: "⬅️ Back to Config", callback_data: "show_config_guide" }]]
      }
    });
    return;
  }
  
  const loadingMessage = await this.sendMessage(chatId, "⏳ Processing config...", options);
  
  try {
    const response = await fetch("https://raw.githubusercontent.com/paoandest/botak/refs/heads/main/cek/proxyList.txt");
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    const ipText = await response.text();
    const ipList = ipText.split("\n").map((line) => line.trim()).filter((line) => line !== "");
    
    const filteredIps = ipList.filter(line => {
      const parts = line.split(',');
      return parts.length > 2 && parts[2].toLowerCase() === countryCode;
    });

    if (filteredIps.length === 0) {
      await this.sendMessage(chatId, `⚠️ *No IP available for country ${countryCode.toUpperCase()}*`, {
        parse_mode: "Markdown",
        ...options,
        reply_markup: {
          inline_keyboard: [[{ text: "⬅️ Back to Config", callback_data: "show_config_guide" }]]
        }
      });
      await this.deleteMessage(chatId, loadingMessage.message_id || loadingMessage.result?.message_id);
      return;
    }
    
    const randomIp = filteredIps[Math.floor(Math.random() * filteredIps.length)];
    const [ip, port, country, provider] = randomIp.split(",");
    
    if (!ip || !port) {
      await this.sendMessage(chatId, `⚠️ Incomplete IP or Port data from proxy list.`, {
        parse_mode: "Markdown",
        ...options,
        reply_markup: {
          inline_keyboard: [[{ text: "⬅️ Back to Config", callback_data: "show_config_guide" }]]
        }
      });
      await this.deleteMessage(chatId, loadingMessage.message_id || loadingMessage.result?.message_id);
      return;
    }
    
    const statusResponse = await fetch(`https://api.sampi.workers.dev/check?ip=${ip}:${port}`);
    if (!statusResponse.ok) {
      throw new Error(`Status check failed! status: ${statusResponse.status}`);
    }
    
    const text = await statusResponse.text();
    let ipData;
    try {
      ipData = JSON.parse(text);
    } catch (e) {
      await this.sendMessage(chatId, `⚠️ Failed to parse response from server for IP ${ip}:${port}. Response: ${text}`, {
        parse_mode: "Markdown",
        ...options,
        reply_markup: {
          inline_keyboard: [[{ text: "⬅️ Back to Config", callback_data: "show_config_guide" }]]
        }
      });
      await this.deleteMessage(chatId, loadingMessage.message_id || loadingMessage.result?.message_id);
      return;
    }
    
    if (ipData.status !== "ACTIVE") {
      await this.sendMessage(chatId, `⚠️ *IP ${ip}:${port} is not active.*`, {
        parse_mode: "Markdown",
        ...options,
        reply_markup: {
          inline_keyboard: [[{ text: "⬅️ Back to Config", callback_data: "show_config_guide" }]]
        }
      });
      await this.deleteMessage(chatId, loadingMessage.message_id || loadingMessage.result?.message_id);
      return;
    }
    
    // Helper functions
    const getFlagEmoji = (code) => code.toUpperCase().split("").map((c) => 
      String.fromCodePoint(127462 + c.charCodeAt(0) - 65)
    ).join("");
    
    const generateUUID = () => "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
      const r = Math.random() * 16 | 0;
      const v = c === "x" ? r : r & 3 | 8;
      return v.toString(16);
    });
    
    const toBase64 = (str) => {
      if (typeof btoa === "function") {
        return btoa(unescape(encodeURIComponent(str)));
      } else {
        return Buffer.from(str, "utf-8").toString("base64");
      }
    };
    
    const HOSTKU = "joss.dus.biz.id";
    const path = `/Free-VPN-CF-Geo-Project/${countryCode.toUpperCase()}`;
    const flagEmoji = getFlagEmoji(countryCode);
    
    const encodedVlessLabelTLS = encodeURIComponent(`ROTATE VLESS ${ipData.isp} ${ipData.country} TLS`);
    const encodedVlessLabelNTLS = encodeURIComponent(`ROTATE VLESS ${ipData.isp} ${ipData.country} NTLS`);
    const encodedTrojanLabelTLS = encodeURIComponent(`ROTATE TROJAN ${ipData.isp} ${ipData.country} TLS`);
    const encodedSsLabelTLS = encodeURIComponent(`ROTATE SHADOWSOCKS ${ipData.isp} ${ipData.country} TLS`);
    const encodedSsLabelNTLS = encodeURIComponent(`ROTATE SHADOWSOCKS ${ipData.isp} ${ipData.country} NTLS`);
    
    const configText = `
\`\`\`INFORMATION
IP      : ${ip}
PORT    : ${port}
ISP     : ${provider || 'N/A'}
COUNTRY : ${ipData.country}
STATUS  : ${ipData.status}
\`\`\`

*ROTATE VLESS ${countryCode.toUpperCase()} ${flagEmoji} TLS*
\`\`\`
vless://${generateUUID()}@${HOSTKU}:443?encryption=none&security=tls&sni=${HOSTKU}&fp=randomized&type=ws&host=${HOSTKU}&path=${encodeURIComponent(path)}#${encodedVlessLabelTLS}
\`\`\`

*ROTATE VLESS ${countryCode.toUpperCase()} ${flagEmoji} NTLS*
\`\`\`
vless://${generateUUID()}@${HOSTKU}:80?path=${encodeURIComponent(path)}&security=none&encryption=none&host=${HOSTKU}&fp=randomized&type=ws&sni=${HOSTKU}#${encodedVlessLabelNTLS}
\`\`\`

*ROTATE TROJAN ${countryCode.toUpperCase()} ${flagEmoji} TLS*
\`\`\`
trojan://${generateUUID()}@${HOSTKU}:443?encryption=none&security=tls&sni=${HOSTKU}&fp=randomized&type=ws&host=${HOSTKU}&path=${encodeURIComponent(path)}#${encodedTrojanLabelTLS}
\`\`\`

*ROTATE SS ${countryCode.toUpperCase()} ${flagEmoji} TLS*
\`\`\`
ss://${toBase64(`none:${generateUUID()}`)}@${HOSTKU}:443?encryption=none&type=ws&host=${HOSTKU}&path=${encodeURIComponent(path)}&security=tls&sni=${HOSTKU}#${encodedSsLabelTLS}
\`\`\`

*ROTATE SS ${countryCode.toUpperCase()} ${flagEmoji} NTLS*
\`\`\`
ss://${toBase64(`none:${generateUUID()}`)}@${HOSTKU}:80?encryption=none&type=ws&host=${HOSTKU}&path=${encodeURIComponent(path)}&security=none&sni=${HOSTKU}#${encodedSsLabelNTLS}
\`\`\`

👨‍💻 Developer : [GEO PROJECT](https://t.me/sampiiiiu)
`;
    
    await this.sendMessage(chatId, configText, {
      parse_mode: "Markdown",
      ...options,
      reply_markup: {
        inline_keyboard: [[{ text: "⬅️ Back to Config", callback_data: "show_config_guide" }]]
      }
    });
    
    await this.deleteMessage(chatId, loadingMessage.message_id || loadingMessage.result?.message_id);
    
  } catch (error) {
    console.error('Error in rotateconfig:', error);
    await this.sendMessage(chatId, `⚠️ An error occurred: ${error.message}`, { 
      ...options,
      reply_markup: {
        inline_keyboard: [[{ text: "⬅️ Back to Config", callback_data: "show_config_guide" }]]
      }
    });
    await this.deleteMessage(chatId, loadingMessage.message_id || loadingMessage.result?.message_id);
  }
}
// src/randomip/randomip.js
let globalIpList = [];
let globalCountryCodes = [];
const menuMessageIds = new Map();
const broadcastState = new Map();
const awaitingAddList = new Map();
const awaitingKuotaNumber = new Map();
async function fetchProxyList(url) {
  const response = await fetch(url);
  const ipText = await response.text();
  const ipList = ipText.split("\n").map((line) => line.trim()).filter((line) => line !== "");
  return ipList;
}
function getFlagEmoji(code) {
  const OFFSET = 127397;
  return [...code.toUpperCase()].map((c) => String.fromCodePoint(c.charCodeAt(0) + OFFSET)).join("");
}
function buildCountryButtons(page = 0, pageSize = 15) {
  const start = page * pageSize;
  const end = start + pageSize;
  const pageItems = globalCountryCodes.slice(start, end);
  const buttons = pageItems.map((code) => ({
    text: `${getFlagEmoji(code)} ${code}`,
    callback_data: `cc_${code}`
  }));
  const inline_keyboard = [];
  for (let i = 0; i < buttons.length; i += 3) {
    inline_keyboard.push(buttons.slice(i, i + 3));
  }
  const navButtons = [];
  if (page > 0) navButtons.push({ text: "⬅️ Prev", callback_data: `randomip_page_${page - 1}` });
if (end < globalCountryCodes.length) navButtons.push({ text: "Next ➡️", callback_data: `randomip_page_${page + 1}` });
if (navButtons.length) inline_keyboard.push(navButtons);
  
  // Hanya tombol developer dan Donate yang tetap
  inline_keyboard.push([
    { text: "👨‍💻 Developer", url: "https://t.me/sampiiiiu" },
    { text: "❤️ Donate", callback_data: "menu_cmd_donate" }
]);
  
return { inline_keyboard };
}
function generateCountryIPsMessage(ipList, countryCode) {
  const filteredIPs = ipList.filter((line) => line.split(",")[2] === countryCode);
  if (filteredIPs.length === 0) return null;
  let msg = `\u{1F310} *Proxy IP untuk negara ${countryCode} ${getFlagEmoji(countryCode)}:*

`;
  filteredIPs.slice(0, 20).forEach((line) => {
    const [ip, port, _code, isp] = line.split(",");
    msg += `
📍 *IP:PORT* : \`${ip}:${port}\` 
🌐 *Country* : ${_code} ${getFlagEmoji(_code)}
💻 *ISP* : ${isp}
`;
});
  
  // Tambahkan tombol di bawah pesan IP
  msg += `\n\n_GEO PROJECT_`;
  return msg;
}
async function handleRandomIpCommand(bot, chatId, options = {}) {
  try {
    globalIpList = await fetchProxyList("https://raw.githubusercontent.com/paoandest/botak/refs/heads/main/cek/proxyList.txt");
    if (globalIpList.length === 0) {
      await bot.sendMessage(chatId, `\u26A0\uFE0F *Daftar IP kosong atau tidak ditemukan. Coba lagi nanti.*`, { parse_mode: "Markdown", ...options });
      return;
    }
    globalCountryCodes = [...new Set(globalIpList.map((line) => line.split(",")[2]))].sort();
    const text = "Please select a country to get a random IP:";
    const reply_markup = buildCountryButtons(0);
    await bot.sendMessage(chatId, text, {
      parse_mode: "Markdown",
      reply_markup,
      ...options
    });
  } catch (error) {
    await bot.sendMessage(chatId, `\u274C Gagal mengambil data IP: ${error.message}`, options);
  }
}
async function handleCallbackQuery(bot, callbackQuery, options = {}) {
  const chatId = callbackQuery.message.chat.id;
  const messageId = callbackQuery.message.message_id;
  const data = callbackQuery.data;
  if (data.startsWith("randomip_page_")) {
    const page = parseInt(data.split("_")[2], 10);
    const keyboard = buildCountryButtons(page);
    await bot.editMessageReplyMarkup({
      chat_id: chatId,
      message_id: messageId,
      reply_markup: keyboard
    }, options);
    await bot.answerCallbackQuery(callbackQuery.id);
    return;
  }
  if (data.startsWith("cc_")) {
    const code = data.split("_")[1];
    const msg = generateCountryIPsMessage(globalIpList, code);
    if (!msg) {
      await bot.sendMessage(chatId, `\u26A0\uFE0F Tidak ditemukan IP untuk negara: ${code}`, {
        parse_mode: "Markdown",
        reply_markup: {
          inline_keyboard: [
            [
    { text: "👨‍💻 Developer", url: "https://t.me/sampiiiiu" },
    { text: "❤️ Donate", callback_data: "menu_cmd_donate" }
],
            [backToMenuButton]
          ]
        },
        ...options
      });
    } else {
      const keyboard = {
        inline_keyboard: [
          [
    { text: "👨‍💻 Developer", url: "https://t.me/sampiiiiu" },
    { text: "❤️ Donate", callback_data: "menu_cmd_donate" }
],
          [backToMenuButton]
        ]
      };
      await bot.sendMessage(chatId, msg, {
        parse_mode: "Markdown",
        reply_markup: keyboard,
        ...options
      });
    }
    await bot.answerCallbackQuery(callbackQuery.id);
    return;
  }
}

// src/randomip/bot2.js
const MENU_COMMANDS = [
    // Page 1
    { text: "🎌 Config by Flag", callback_data: "menu_cmd_proxyip" },
    { text: "🎲 Random Config", callback_data: "menu_cmd_randomconfig" },
    { text: "🔄 Convert Sub", callback_data: "menu_cmd_converter" },
    { text: "🔄 Rotate Config", callback_data: "menu_cmd_config" },
    { text: "🔗 Sub Link", callback_data: "menu_cmd_sublink" },
    // Page 2
    { text: "🌐 Get Proxy", callback_data: "menu_cmd_proxy" },
    { text: "📈 Usage Stats", callback_data: "menu_cmd_stats" },
    { text: "🔍 Find Proxy", callback_data: "menu_cmd_findproxy" },
    { text: "👥 Bot User List", callback_data: "menu_cmd_userlist" },
    { text: "📡 Ping Bot", callback_data: "menu_cmd_ping" },
    // Page 3
    { text: "📱 Check XL Quota", callback_data: "menu_cmd_kuota" },
    { text: "➕ Add Wildcard", callback_data: "menu_cmd_add" },
    { text: "➖ Delete Wildcard", callback_data: "menu_cmd_del" },
    { text: "📝 List Wildcard", callback_data: "menu_cmd_listwildcard" },
    { text: "📢 Broadcast MSG", callback_data: "menu_cmd_broadcast" },
];

function getMenuKeyboard(page = 0) {
    const itemsPerPage = 5;
    const start = page * itemsPerPage;
    const end = start + itemsPerPage;
    const paginatedItems = MENU_COMMANDS.slice(start, end);
    const totalPages = Math.ceil(MENU_COMMANDS.length / itemsPerPage);

    const keyboard = [];
    if (paginatedItems.length > 0) keyboard.push(paginatedItems.slice(0, 2));
    if (paginatedItems.length > 2) keyboard.push(paginatedItems.slice(2, 3));
    if (paginatedItems.length > 3) keyboard.push(paginatedItems.slice(3, 5));

    const navButtons = [];
    if (page > 0) navButtons.push({ text: "⬅️ Prev", callback_data: `menu_page_${page - 1}` });
    if (page < totalPages - 1) navButtons.push({ text: "Next ➡️", callback_data: `menu_page_${page + 1}` });

    if (navButtons.length > 0) keyboard.push(navButtons);

    // Hanya tombol developer dan Donate yang tetap di setiap halaman
    keyboard.push([
        { text: "👨‍💻 Developer", url: "https://t.me/sampiiiiu" },
        { text: "❤️ Donate", callback_data: "menu_cmd_donate" }
    ]);

    return { inline_keyboard: keyboard };
}

const TelegramBotku = class {
  constructor(token, apiUrl = "https://api.telegram.org") {
    this.token = token;
    this.apiUrl = apiUrl;
  }
  
  async sendPhoto(chatId, photo, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/sendPhoto`;
    const body = {
      chat_id: chatId,
      photo,
      parse_mode: "Markdown",
      ...options
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  
  async editMessageText(chatId, messageId, text, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/editMessageText`;
    const body = {
      chat_id: chatId,
      message_id: messageId,
      text,
      ...options
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  
  async handleUpdate(update) {
    const message_thread_id = update.message?.message_thread_id || update.callback_query?.message?.message_thread_id;
    const options = message_thread_id ? { message_thread_id } : {};
    
    if (update.message) {
      const msg = update.message;
      if (msg.text && /^\/proxyip(@\w+)?$/.test(msg.text)) {
        const targetMessageId = menuMessageIds.get(msg.chat.id) || msg.message_id;
        await handleProxyipCommand(this, msg, { ...options, reply_to_message_id: targetMessageId });
      }
    }
    
    if (update.callback_query) {
      const data = update.callback_query.data;
      
      if (data.startsWith("menu_page_")) {
          const page = parseInt(data.split("_")[2], 10);
          const keyboard = getMenuKeyboard(page);
          await this.editMessageText(
              update.callback_query.message.chat.id,
              update.callback_query.message.message_id,
              `*Main Bot Menu*\n  Select an option below:`,
              {
                  parse_mode: "Markdown",
                  reply_markup: keyboard,
                  ...options
              }
          );
          await this.answerCallbackQuery(update.callback_query.id);
          return new Response("OK", { status: 200 });
      }
      
      // Handle menu commands
      if (data.startsWith("menu_cmd_")) {
        const command = data.replace("menu_cmd_", "");
        
        switch(command) {
          case "broadcast":
            // Start interactive broadcast flow
            const chatId = update.callback_query.message.chat.id;
            const messageId = update.callback_query.message.message_id;
            broadcastState.set(chatId, { step: 'awaiting_message' });
            await this.sendMessage(chatId, 
              " Please send the message you want to broadcast (text, image, or video).", 
              {
                reply_markup: {
                  inline_keyboard: [[{ text: " Cancel", callback_data: "cancel_broadcast" }]]
                },
                reply_to_message_id: messageId, 
                ...options 
              }
            );
            break;
          case "proxy":
            await handleRandomIpCommand(this, update.callback_query.message.chat.id, { reply_to_message_id: update.callback_query.message.message_id, ...options });
            break;
          case "findproxy":
            const menuText = `  *PROXY SEARCH TUTORIAL*  

Here are some sites and techniques for finding proxies:

 *ZOOMEYE.HK*
Search query:
\`\`\`
+app:"Cloudflare" +service:"http" +title:"400 The plain HTTP request was sent to HTTPS port" +country:"Singapore"
\`\`\`

 *BINARYEDGE.IO*
Search query:
\`\`\`
country:ID title:"400 The plain HTTP request was sent to HTTPS port" product:nginx protocol:"tcp" name:http banner:"Server: cloudflare" banner:"CF-RAY: -" NOT asn:209242
\`\`\`

 *CENSYS.IO*
Basic search query:
\`\`\`
not autonomous_system.name: "CLOUDFLARE*" and services: (software.product: "CloudFlare Load Balancer" and http.response.html_title: "400 The plain HTTP request was sent to HTTPS port") and location.country: "Indonesia"
\`\`\`

To check the proxy status, send the search results directly to this bot.

*Developer:* [Geo Project](https://t.me/sampiiiiu)`;

            const keyboard = {
                inline_keyboard: [
    [
        { text: "🔍 ZOOMEYE.HK", url: "https://zoomeye.hk" },
        { text: "🔎 BINARYEDGE", url: "https://app.binaryedge.io" }
    ],
    [
        { text: "📡 CENSYS.IO", url: "https://search.censys.io" },
        { text: "📝 NOTES", callback_data: "findproxy_notes" }
    ],
    [
        backToMenuButton
    ],
    [
        { text: "👨‍💻 Developer", url: "https://t.me/sampiiiiu" },
        { text: "❤️ Donate", callback_data: "menu_cmd_donate" }
    ]
]
            };

            await this.sendMessage(update.callback_query.message.chat.id, menuText, { 
                parse_mode: "Markdown", 
                reply_markup: keyboard,
                reply_to_message_id: update.callback_query.message.message_id,
                ...options 
            });
            break;

          case "donate":
            const imageUrl = "https://github.com/jaka1m/project/raw/main/BAYAR.jpg";
            try {
                await this.sendPhoto(update.callback_query.message.chat.id, imageUrl, {
                    caption: `
  *Support Bot Development!*  

Help us continue to grow by scanning the QRIS above!

  *Upcoming Features:*
 Faster servers
 More proxy countries
 Exclusive premium features
 Regular updates and bug fixes

Thank you for your support!  

_ GEO BOT SERVER Team_
`.trim(),
                    parse_mode: "Markdown",
                   reply_markup: {
    inline_keyboard: [
        [
            { 
                text: "👤 GEO PROJECT", 
                url: "https://t.me/sampiiiiu" 
            },
            { 
                text: "📢 Channel", 
                url: "https://t.me/testikuy_mang" 
            }
        ],
        [
            backToMenuButton
        ]
    ]
},
reply_to_message_id: update.callback_query.message.message_id,
...options
});
            } catch (error) {
                console.error(" Error sending donation photo:", error);
                await this.sendMessage(update.callback_query.message.chat.id, 
                    `  *Support Bot Development!*\n\n` +
                    `Help us continue to grow with a donation via QRIS.\n\n` +
                    `Thank you for your support!  \n\n` +
                    ` [GEO PROJECT](https://t.me/sampiiiiu)`,
                    { parse_mode: "Markdown", reply_to_message_id: update.callback_query.message.message_id, ...options }
                );
            }
            break;
          case "stats":
            // Handle stats command
            const CLOUDFLARE_API_TOKEN = "jjtpiyLT97DYmd3zVz8Q3vypTSVxDRrcVF7yTBl8";
            const CLOUDFLARE_ZONE_ID = "fe34f9ac955252fedff0a3907333b456";
            
            const getTenDaysAgoDate = () => {
              const d = new Date();
              d.setDate(d.getDate() - 10);
              return d.toISOString().split("T")[0];
            };

            const tenDaysAgo = getTenDaysAgoDate();
            
            try {
              const response = await fetch("https://api.cloudflare.com/client/v4/graphql", {
                method: "POST",
                headers: {
                  Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
                  "Content-Type": "application/json"
                },
                body: JSON.stringify({
                  query: `query {
                    viewer {
                      zones(filter: { zoneTag: "${CLOUDFLARE_ZONE_ID}" }) {
                        httpRequests1dGroups(
                          limit: 10,
                          orderBy: [date_DESC],
                          filter: { date_geq: "${tenDaysAgo}" }
                        ) {
                          sum {
                            bytes
                            requests
                          }
                          dimensions {
                            date
                          }
                        }
                      }
                    }
                  }`
                })
              });

              const result = await response.json();
              
              if (!result.data?.viewer?.zones?.length) {
                throw new Error("Failed to fetch usage data.");
              }

              let usageText = "  *Usage Data for the Last 10 Days:*\n\n";
              let totalBytes = 0;
              let totalRequests = 0;

              result.data.viewer.zones[0].httpRequests1dGroups.forEach((day) => {
                const tanggal = day.dimensions.date;
                totalBytes += day.sum.bytes;
                totalRequests += day.sum.requests;
                
                const dailyData = (day.sum.bytes / 1024 ** 4).toFixed(2);
                const dailyRequests = day.sum.requests.toLocaleString();
                
                usageText += `  *Date:* ${tanggal}\n`;
                usageText += `  *Daily Data:* ${dailyData} TB\n`;
                usageText += `  *Daily Requests:* ${dailyRequests}\n\n`;
              });

              const totalDataTB = (totalBytes / 1024 ** 4).toFixed(2);
              
              usageText += "*  Overall Total:*\n";
              usageText += ` *Total Data:* ${totalDataTB} TB\n`;
              usageText += ` *Total Requests:* ${totalRequests.toLocaleString()}`;

              await this.sendMessage(update.callback_query.message.chat.id, usageText, { 
                parse_mode: "Markdown",
                reply_to_message_id: update.callback_query.message.message_id,
                ...options,
                reply_markup: {
                  inline_keyboard: [[backToMenuButton]]
                }
              });
              
            } catch (error) {
              await this.sendMessage(
                update.callback_query.message.chat.id,
                `   Failed to fetch usage data.\n\n_Error:_ ${error.message}`,
                { parse_mode: "Markdown", reply_to_message_id: update.callback_query.message.message_id, ...options,
                  reply_markup: {
                    inline_keyboard: [[backToMenuButton]]
                  }
                }
              );
            }
            break;
          default:
            // For other commands, send a placeholder message
            await this.sendMessage(update.callback_query.message.chat.id, 
              `  *${command} feature is under development*\n\nThis feature is currently being developed. Please try again later.`,
              { parse_mode: "Markdown", reply_to_message_id: update.callback_query.message.message_id, ...options }
            );
        }
        
        await this.answerCallbackQuery(update.callback_query.id);
        return new Response("OK", { status: 200 });
      }
      
      // Handle findproxy_notes callback (di luar menu_cmd_)
      if (data === "findproxy_notes") {
        const notesText = `  *USAGE NOTES*

*Notes:*
- Add port filter with \`and services.port=443\`
- Filter provider: \`autonomous_system.name: "provider_name"\`

To check the proxy status, send the search results directly to this bot.

*Developer:* [Geo Project](https://t.me/sampiiiiu)`;

        const notesKeyboard = {
            inline_keyboard: [
                [
                    backToMenuButton
                ],
                [
                    { text: "👨‍💻 Developer", url: "https://t.me/sampiiiiu" },
                    { text: "❤️ Donate", callback_data: "menu_cmd_donate" }
                ]
            ]
        };

        // Edit pesan yang sama
        try {
            await this.editMessageText(
                update.callback_query.message.chat.id,
                update.callback_query.message.message_id,
                notesText,
                {
                    parse_mode: "Markdown",
                    reply_markup: notesKeyboard,
                    ...options
                }
            );
        } catch (error) {
            // Jika edit gagal, kirim pesan baru
            await this.sendMessage(update.callback_query.message.chat.id, notesText, { 
                parse_mode: "Markdown", 
                reply_markup: notesKeyboard,
                ...options 
            });
        }
        await this.answerCallbackQuery(update.callback_query.id);
        return new Response("OK", { status: 200 });
      }
      
      await handleCallbackQuery(this, update.callback_query, options);
      await handleCallbackQuery2(this, update.callback_query, options);
      return new Response("OK", { status: 200 });
    }
    
    if (!update.message) return new Response("OK", { status: 200 });
    const chatId = update.message.chat.id;
    const text = update.message.text || "";
    const messageId = update.message.message_id;
    
    if (/^\/menu(@\w+)?$/.test(text)) {
        const page = 0;
        const keyboard = getMenuKeyboard(page);
        const menuText = `*Main Bot Menu*\n  Select an option below:`;
        const sentMessage = await this.sendMessage(chatId, menuText, {
            parse_mode: "Markdown",
            reply_markup: keyboard,
            reply_to_message_id: messageId,
            ...options
        });
        if (sentMessage && sentMessage.ok && sentMessage.result) {
            menuMessageIds.set(chatId, sentMessage.result.message_id);
        }
        return new Response("OK", { status: 200 });
    }
    
    if (/^\/proxy(@\w+)?$/.test(text)) {
      const targetMessageId = menuMessageIds.get(chatId) || messageId;
      await handleRandomIpCommand(this, chatId, { reply_to_message_id: targetMessageId, ...options });
      return new Response("OK", { status: 200 });
    }
    
    if (/^\/findproxy(@\w+)?$/.test(text)) {
      const menuText = `  *PROXY SEARCH TUTORIAL*  

Here are some sites and techniques for finding proxies:

 *ZOOMEYE.HK*
Search query:
\`\`\`
+app:"Cloudflare" +service:"http" +title:"400 The plain HTTP request was sent to HTTPS port" +country:"Singapore"
\`\`\`

 *BINARYEDGE.IO*
Search query:
\`\`\`
country:ID title:"400 The plain HTTP request was sent to HTTPS port" product:nginx protocol:"tcp" name:http banner:"Server: cloudflare" banner:"CF-RAY: -" NOT asn:209242
\`\`\`

 *CENSYS.IO*
Basic search query:
\`\`\`
not autonomous_system.name: "CLOUDFLARE*" and services: (software.product: "CloudFlare Load Balancer" and http.response.html_title: "400 The plain HTTP request was sent to HTTPS port") and location.country: "Indonesia"
\`\`\`

To check the proxy status, send the search results directly to this bot.

*Developer:* [Geo Project](https://t.me/sampiiiiu)`;

      const keyboard = {
          inline_keyboard: [
    [
        { text: "🔍 ZOOMEYE.HK", url: "https://zoomeye.hk" },
        { text: "🔎 BINARYEDGE", url: "https://app.binaryedge.io" }
    ],
    [
        { text: "📡 CENSYS.IO", url: "https://search.censys.io" },
        { text: "📝 NOTES", callback_data: "findproxy_notes" }
    ],
    [
        backToMenuButton
    ],
    [
        { text: "👨‍💻 Developer", url: "https://t.me/sampiiiiu" },
        { text: "❤️ Donate", callback_data: "menu_cmd_donate" }
    ]
]
      };

      await this.sendMessage(chatId, menuText, { 
          parse_mode: "Markdown", 
          reply_markup: keyboard,
          reply_to_message_id: messageId,
          ...options 
      });
      return new Response("OK", { status: 200 });
    }
    
    if (/^\/donate(@\w+)?$/.test(text)) {
      const imageUrl = "https://github.com/jaka1m/project/raw/main/BAYAR.jpg";
    
    try {
        await this.sendPhoto(chatId, imageUrl, {
            caption: `
  *Support Bot Development!*  

Help us continue to grow by scanning the QRIS above!

  *Upcoming Features:*
 Faster servers
 More proxy countries
 Exclusive premium features
 Regular updates and bug fixes

Thank you for your support!  

_ GEO BOT SERVER Team_
`.trim(),
            parse_mode: "Markdown",
            reply_markup: {
    inline_keyboard: [
        [
            { 
                text: "👤 GEO PROJECT", 
                url: "https://t.me/sampiiiiu" 
            },
            { 
                text: "📢 Channel", 
                url: "https://t.me/testikuy_mang" 
            }
        ],
        [
            backToMenuButton
        ]
    ]
},
reply_to_message_id: messageId,
...options
});
        
    } catch (error) {
        console.error(" Error sending donation photo:", error);
        // Fallback to text message if image fails
        await this.sendMessage(chatId, 
            `  *Support Bot Development!*\n\n` +
            `Help us continue to grow with a donation via QRIS.\n\n` +
            `Thank you for your support!  \n\n` +
            ` [GEO PROJECT](https://t.me/sampiiiiu)`,
            { parse_mode: "Markdown", reply_to_message_id: messageId, ...options }
        );
    }
    
    return new Response("OK", { status: 200 });
    }
    
    if (/^\/stats(@\w+)?$/.test(text)) {
  const targetMessageId = menuMessageIds.get(chatId) || messageId;
  const CLOUDFLARE_API_TOKEN = "jjtpiyLT97DYmd3zVz8Q3vypTSVxDRrcVF7yTBl8";
  const CLOUDFLARE_ZONE_ID = "3be1ebf3d8d2e93efaf8851e6f5b5339";
  
  const getTenDaysAgoDate = () => {
    const d = new Date();
    d.setDate(d.getDate() - 10);
    return d.toISOString().split("T")[0];
  };

  const tenDaysAgo = getTenDaysAgoDate();
  
  try {
    const response = await fetch("https://api.cloudflare.com/client/v4/graphql", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${CLOUDFLARE_API_TOKEN}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        query: `query {
          viewer {
            zones(filter: { zoneTag: "${CLOUDFLARE_ZONE_ID}" }) {
              httpRequests1dGroups(
                limit: 10,
                orderBy: [date_DESC],
                filter: { date_geq: "${tenDaysAgo}" }
              ) {
                sum {
                  bytes
                  requests
                }
                dimensions {
                  date
                }
              }
            }
          }
        }`
      })
    });

    const result = await response.json();
    
    if (!result.data?.viewer?.zones?.length) {
      throw new Error("Gagal mengambil data pemakaian.");
    }

    let usageText = " *Data Pemakaian 10 Hari Terakhir:*\n\n";
    let totalBytes = 0;
    let totalRequests = 0;

    result.data.viewer.zones[0].httpRequests1dGroups.forEach((day) => {
      const tanggal = day.dimensions.date;
      totalBytes += day.sum.bytes;
      totalRequests += day.sum.requests;
      
      const dailyData = (day.sum.bytes / 1024 ** 4).toFixed(2);
      const dailyRequests = day.sum.requests.toLocaleString();
      
      usageText += `📅 *Tanggal:* ${tanggal}\n`;
usageText += `📊 *Data Harian:* ${dailyData} TB\n`;
usageText += `🔄 *Requests Harian:* ${dailyRequests}\n\n`;
    });

    const totalDataTB = (totalBytes / 1024 ** 4).toFixed(2);
    
    usageText += "*📈 Total Keseluruhan:*\n";
usageText += `📦 *Total Data:* ${totalDataTB} TB\n`;
usageText += `🔄 *Total Requests:* ${totalRequests.toLocaleString()}`;

    await this.sendMessage(chatId, usageText, { parse_mode: "Markdown", reply_to_message_id: targetMessageId, ...options,
      reply_markup: {
        inline_keyboard: [[backToMenuButton]]
      } 
    });
    
  } catch (error) {
    await this.sendMessage(
      chatId,
      ` Gagal mengambil data pemakaian.\n\n_Error:_ ${error.message}`,
      { parse_mode: "Markdown", reply_to_message_id: targetMessageId, ...options,
        reply_markup: {
          inline_keyboard: [[backToMenuButton]]
        }
      }
    );
  }
  
  return new Response("OK", { status: 200 });
    }
    
    return new Response("OK", { status: 200 });
  }
  
  async sendMessage(chatId, text, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/sendMessage`;
    const body = {
      chat_id: chatId,
      text,
      parse_mode: "Markdown",
      ...options
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  
  async editMessageReplyMarkup({ chat_id, message_id, reply_markup }, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/editMessageReplyMarkup`;
    const body = { chat_id, message_id, reply_markup, ...options };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  
  async answerCallbackQuery(callbackQueryId) {
    const url = `${this.apiUrl}/bot${this.token}/answerCallbackQuery`;
    const body = { callback_query_id: callbackQueryId };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
};

// src/checkip/cek.js
const WILDCARD_MAP = {
  ava: "ava.game.naver.com",
  api: "api.midtrans.com",
  blibli: "business.blibli.com",
  ig: "graph.instagram.com",
  vidio: "quiz.int.vidio.com",
  iflix: "live.iflix.com",
  zoom: "support.zoom.us",
  webex: "blog.webex.com",
  spotify: "investors.spotify.com",
  netflix: "cache.netflix.com",
  viu: "zaintest.vuclip.com",
  ruangguru: "io.ruangguru.com",
  fb: "investor.fb.com",
  bakrie: "bakrie.ac.id"
};
const WILDCARD_OPTIONS = Object.entries(WILDCARD_MAP).map(
  ([value, text]) => ({ text, value })
);
const DEFAULT_HOST = "joss.dus.biz.id";
const API_URL = "https://api.sampi.workers.dev/check?ip=";
async function fetchIPData(ip, port) {
  try {
    const response = await fetch(`${API_URL}${encodeURIComponent(ip)}:${encodeURIComponent(port)}`);
    if (!response.ok) throw new Error("Gagal mengambil data dari API.");
    const text = await response.text();
    try {
      return JSON.parse(text);
    } catch (e) {
      console.error("Gagal mem-parsing respons JSON:", text);
      return null;
    }
  } catch (error) {
    console.error("Error fetching IP data:", error);
    return null;
  }
}
function createProtocolInlineKeyboard(ip, port) {
  return {
    inline_keyboard: [
      [
        { text: "⚡ VLESS", callback_data: `PROTOCOL|VLESS|${ip}|${port}` },
        { text: "🎯 TROJAN", callback_data: `PROTOCOL|TROJAN|${ip}|${port}` }
      ],
      [
        { text: "✨ SHADOWSOCKS", callback_data: `PROTOCOL|SHADOWSOCKS|${ip}|${port}` }
      ]
    ]
  };
}

function createInitialWildcardInlineKeyboard(ip, port, protocol) {
  return {
    inline_keyboard: [
      [
        { text: "✅ TANPA WILDCARD", callback_data: `NOWILDCARD|${protocol}|${ip}|${port}` },
        { text: "☑️ DENGAN WILDCARD", callback_data: `SHOW_WILDCARD|${protocol}|${ip}|${port}` }
      ],
      [
        { text: "⬅️ Kembali", callback_data: `BACK|${ip}|${port}` }
      ]
    ]
  };
}

function createWildcardOptionsInlineKeyboard(ip, port, protocol) {
  const buttons = WILDCARD_OPTIONS.map((option, index) => [
    { text: `🐛 ${index + 1}. ${option.text}`, callback_data: `WILDCARD|${protocol}|${ip}|${port}|${option.value}` }
  ]);
  
  buttons.push([
    { text: "⬅️ Kembali", callback_data: `BACK|${ip}|${port}` }
  ]);
  
  return { inline_keyboard: buttons };
}

function generateUUID2() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === "x" ? r : (r & 3 | 8);
    return v.toString(16);
  });
}

function toBase64(str) {
  const encoder = new TextEncoder();
  const data = encoder.encode(str);
  return btoa(String.fromCharCode(...new Uint8Array(data.buffer)));
}

function generateConfig(config, protocol, wildcardKey = null) {
  if (!config?.ip || !config?.port || !config?.isp) {
    return " Data tidak valid!";
  }

  const host = wildcardKey ? `${WILDCARD_MAP[wildcardKey]}.${DEFAULT_HOST}` : DEFAULT_HOST;
  const sni = host;
  const uuid = generateUUID2();
  const path = encodeURIComponent(`/Free-VPN-CF-Geo-Project/${config.ip}=${config.port}`);
  const ispEncoded = encodeURIComponent(config.isp);
  
  let qrUrl = "";
  let configOutput = "";

  if (protocol === "VLESS") {
    const vlessTLS = `vless://${uuid}@${host}:443?encryption=none&security=tls&sni=${sni}&fp=randomized&type=ws&host=${host}&path=${path}#${ispEncoded}`;
    const vlessNTLS = `vless://${uuid}@${host}:80?path=${path}&security=none&encryption=none&host=${host}&fp=randomized&type=ws&sni=${host}#${ispEncoded}`;
    qrUrl = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(vlessTLS)}&size=400x400`;
    
    configOutput = `
\`\`\`VLESS-TLS
${vlessTLS}
\`\`\`

\`\`\`VLESS-NTLS
${vlessNTLS}
\`\`\`

 [QR Code URL](${qrUrl})
 [View Google Maps](https://www.google.com/maps?q=${config.latitude},${config.longitude})
 Developer : [GEO PROJECT](https://t.me/sampiiiiu)
`;

  } else if (protocol === "TROJAN") {
    const configString1 = `trojan://${uuid}@${host}:443?security=tls&sni=${sni}&fp=randomized&type=ws&host=${host}&path=${path}#${ispEncoded}`;
    const configString2 = `trojan://${uuid}@${host}:80?path=${path}&security=none&encryption=none&host=${host}&fp=randomized&type=ws&sni=${host}#${ispEncoded}`;
    qrUrl = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(configString1)}&size=400x400`;
    
    configOutput = `
\`\`\`TROJAN-TLS
${configString1}
\`\`\`

\`\`\`TROJAN-NTLS
${configString2}
\`\`\`

 [QR Code URL](${qrUrl})
 [View Google Maps](https://www.google.com/maps?q=${config.latitude},${config.longitude})
 Developer : [GEO PROJECT](https://t.me/sampiiiiu)
`;

  } else if (protocol === "SHADOWSOCKS") {
    const configString1 = `ss://${toBase64(`none:${uuid}`)}@${host}:443?encryption=none&type=ws&host=${host}&path=${path}&security=tls&sni=${sni}#${ispEncoded}`;
    const configString2 = `ss://${toBase64(`none:${uuid}`)}@${host}:80?encryption=none&type=ws&host=${host}&path=${path}&security=none&sni=${sni}#${ispEncoded}`;
    qrUrl = `https://api.qrserver.com/v1/create-qr-code/?data=${encodeURIComponent(configString1)}&size=400x400`;
    
    configOutput = `
\`\`\`SHADOWSOCKS-TLS
${configString1}
\`\`\`

\`\`\`SHADOWSOCKS-NTLS
${configString2}
\`\`\`

 [QR Code URL](${qrUrl})
 [View Google Maps](https://www.google.com/maps?q=${config.latitude},${config.longitude})
 Developer : [GEO PROJECT](https://t.me/sampiiiiu)
`;

  } else {
    return " Unknown protocol!";
  }

  return configOutput.trim();
}

// src/checkip/botCek.js
const TelegramProxyCekBot = class {
  constructor(token, apiUrl = "https://api.telegram.org") {
    this.token = token;
    this.apiUrl = apiUrl;
  }
  async sendRequest(method, body) {
    const url = `${this.apiUrl}/bot${this.token}/${method}`;
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  async sendMessage(chatId, text, extra = {}) {
    return this.sendRequest("sendMessage", { chat_id: chatId, text, parse_mode: "Markdown", ...extra });
  }
  async editMessage(chatId, messageId, text, extra = {}) {
    return this.sendRequest("editMessageText", { chat_id: chatId, message_id: messageId, text, parse_mode: "Markdown", ...extra });
  }
  async deleteMessage(chatId, messageId, extra = {}) {
    return this.sendRequest("deleteMessage", { chat_id: chatId, message_id: messageId, ...extra });
  }
  async sendChatAction(chatId, action = "typing", extra = {}) {
    return this.sendRequest("sendChatAction", { chat_id: chatId, action, ...extra });
  }
  async handleUpdate(update) {
    const message = update.message || update.callback_query?.message;
    if (!message) {
      return new Response("OK", { status: 200 });
    }

    const message_thread_id = message.message_thread_id;
    const options = message_thread_id ? { message_thread_id } : {};

    if (update.message && update.message.text) {
      const chatId = update.message.chat.id;
      const messageId = update.message.message_id;
      const text = update.message.text.trim();
      const ipOnlyMatch = text.match(/^(\d{1,3}(?:\.\d{1,3}){3})$/);
      const ipPortMatch = text.match(/^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/);
      if (!ipOnlyMatch && !ipPortMatch) {
        return new Response("OK", { status: 200 });
      }
      const ip = ipPortMatch ? ipPortMatch[1] : ipOnlyMatch[1];
      const port = ipPortMatch ? ipPortMatch[2] : "443";
      await this.deleteMessage(chatId, messageId, options);
      await this.sendChatAction(chatId, "typing", options);
      const loadingMsg = await this.sendMessage(chatId, `
\`\`\`Running
Please wait while it is being processed...
\`\`\`
`, options);
      const data = await fetchIPData(ip, port);
      if (!data) {
        await this.editMessage(chatId, loadingMsg.result.message_id, `\u274C Gagal mengambil data untuk IP ${ip}:${port}`, options);
        return new Response("OK", { status: 200 });
      }
      const { isp, country, delay, status } = data;
      const infoText = `\`\`\`INFORMASI
IP     : ${ip}
PORT   : ${port}
ISP    : ${isp}
Negara: ${country || "-"}
Penundaan  : ${delay || "-"}
Status : ${status || "-"}
\`\`\`
Pilih protokol:`;
      await this.editMessage(chatId, loadingMsg.result.message_id, infoText, {
        reply_markup: createProtocolInlineKeyboard(ip, port), ...options
      });
      return new Response("OK", { status: 200 });
    }
    if (update.callback_query) {
      const callback = update.callback_query;
      const chatId = callback.message.chat.id;
      const messageId = callback.message.message_id;
      const data = callback.data;
      const parts = data.split("|");
      if (parts[0] === "PROTOCOL") {
        const [_, protocol, ip, port] = parts;
        await this.editMessage(chatId, messageId, `\u2699\uFE0F Opsi wildcard untuk ${protocol}`, {
          reply_markup: createInitialWildcardInlineKeyboard(ip, port, protocol), ...options
        });
        return new Response("OK", { status: 200 });
      }
      if (parts[0] === "SHOW_WILDCARD") {
        const [_, protocol, ip, port] = parts;
        await this.editMessage(chatId, messageId, `\u2699\uFE0F Opsi wildcard untuk ${protocol}`, {
          reply_markup: createWildcardOptionsInlineKeyboard(ip, port, protocol), ...options
        });
        return new Response("OK", { status: 200 });
      }
      if (parts[0] === "NOWILDCARD") {
        const [_, protocol, ip, port] = parts;
        await this.sendChatAction(chatId, "typing", options);
        const loadingMsg = await this.sendMessage(chatId, `
\`\`\`Running
Please wait while it is being processed...
\`\`\`
`, options);
        const dataInfo = await fetchIPData(ip, port);
        if (!dataInfo) {
          await this.editMessage(chatId, messageId, `\u274C Gagal mengambil data untuk IP ${ip}:${port}`, options);
          await this.deleteMessage(chatId, loadingMsg.result.message_id, options);
          return new Response("OK", { status: 200 });
        }
        const configText = generateConfig(dataInfo, protocol, null);
        await this.editMessage(chatId, messageId, `\u2705 Config ${protocol} NO Wildcard:
${configText}
`, {
          parse_mode: "Markdown",
          reply_markup: {
            inline_keyboard: [[{
              text: "⬅️ Kembali",
              callback_data: `BACK_WILDCARD|${protocol}|${ip}|${port}`
            }]]
          }, ...options
        });
        await this.deleteMessage(chatId, loadingMsg.result.message_id, options);
        return new Response("OK", { status: 200 });
      }
      if (parts[0] === "WILDCARD") {
        const [_, protocol, ip, port, wildcardKey] = parts;
        await this.sendChatAction(chatId, "typing", options);
        const loadingMsg = await this.sendMessage(chatId, `
\`\`\`Running
Please wait while it is being processed...
\`\`\`
`, options);
        const dataInfo = await fetchIPData(ip, port);
        if (!dataInfo) {
          await this.editMessage(chatId, messageId, `\u274C Gagal mengambil data untuk IP ${ip}:${port}`, options);
          await this.deleteMessage(chatId, loadingMsg.result.message_id, options);
          return new Response("OK", { status: 200 });
        }
        const configText = generateConfig(dataInfo, protocol, wildcardKey);
        await this.editMessage(chatId, messageId, `\u2705 Config ${protocol} Wildcard *${wildcardKey}*:
${configText}
`, {
          parse_mode: "Markdown",
          reply_markup: {
            inline_keyboard: [[{
              text: "⬅️ Kembali",
              callback_data: `BACK_WILDCARD|${protocol}|${ip}|${port}`
            }]]
          }, ...options
        });
        await this.deleteMessage(chatId, loadingMsg.result.message_id, options);
        return new Response("OK", { status: 200 });
      }
      if (parts[0] === "BACK") {
        const [_, ip, port] = parts;
        const dataInfo = await fetchIPData(ip, port);
        if (!dataInfo) {
          await this.editMessage(chatId, messageId, `\u274C Gagal mengambil data untuk IP ${ip}:${port}`, options);
          return new Response("OK", { status: 200 });
        }
        const infoText = `\`\`\`INFORMATION
IP     : ${ip}
PORT   : ${port}
ISP    : ${dataInfo.isp}
Country: ${dataInfo.country}
Delay  : ${dataInfo.delay}
Status : ${dataInfo.status}
\`\`\`
Pilih protokol:`;
        await this.editMessage(chatId, messageId, infoText, {
          reply_markup: createProtocolInlineKeyboard(ip, port), ...options
        });
        return new Response("OK", { status: 200 });
      }
      if (parts[0] === "BACK_WILDCARD") {
        const [_, protocol, ip, port] = parts;
        await this.editMessage(chatId, messageId, `\u2699\uFE0F Opsi wildcard untuk ${protocol}`, {
          reply_markup: createInitialWildcardInlineKeyboard(ip, port, protocol), ...options
        });
        return new Response("OK", { status: 200 });
      }
      return new Response("OK", { status: 200 });
    }
  }
};

// src/proxyip/proxyip.js
const APIKU = "https://api.sampi.workers.dev/check?ip=";
const DEFAULT_HOST2 = "joss.dus.biz.id";
const sentMessages = new Map();
const paginationState = new Map();
function generateUUID3() {
  return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0, v = c === "x" ? r : r & 3 | 8;
    return v.toString(16);
  });
}
function getFlagEmoji2(countryCode) {
  if (!countryCode) return "";
  const codePoints = [...countryCode.toUpperCase()].map((c) => 127462 - 65 + c.charCodeAt());
  return String.fromCodePoint(...codePoints);
}
function canSendMessage(chatId, key, interval = 3e4) {
  const now = Date.now();
  if (!sentMessages.has(chatId)) sentMessages.set(chatId, {});
  const userData = sentMessages.get(chatId);
  if (!userData[key] || now - userData[key] > interval) {
    userData[key] = now;
    return true;
  }
  return false;
}
function chunkArray(arr, size) {
  const chunks = [];
  for (let i = 0; i < arr.length; i += size) {
    chunks.push(arr.slice(i, i + size));
  }
  return chunks;
}
function generateCountryButtons(countryCodes, page = 0, pageSize = 12) {
  const totalPages = Math.ceil(countryCodes.length / pageSize);
  const start = page * pageSize;
  const pageItems = countryCodes.slice(start, start + pageSize);
  const rows = chunkArray(pageItems, 3);
  const buttons = rows.map(
    (row) => row.map((code) => ({
      text: `${getFlagEmoji2(code)} ${code}`,
      callback_data: `select_${code}`
    }))
  );
  const navButtons = [];
  if (page > 0) {
    navButtons.push({ text: "⬅️ Prev", callback_data: `page_prev_${page - 1}` });
  }
  if (page < totalPages - 1) {
    navButtons.push({ text: "Next ➡️", callback_data: `page_next_${page + 1}` });
  }
  buttons.push(navButtons);
  return buttons;
}
async function handleProxyipCommand(bot, msg, options = {}) {
  const chatId = msg.chat.id;
  if (!canSendMessage(chatId, "proxyip_command")) return;
  try {
    const response = await fetch("https://raw.githubusercontent.com/paoandest/botak/refs/heads/main/cek/proxyList.txt");
    const ipText = await response.text();
    const ipList = ipText.split("\n").filter((line) => line.trim() !== "");
    if (ipList.length === 0) {
      await bot.sendMessage(chatId, `\u26A0\uFE0F *Daftar IP kosong atau tidak ditemukan. Coba lagi nanti.*`, { parse_mode: "Markdown", ...options });
      return;
    }
    const countryCodes = [...new Set(ipList.map((line) => line.split(",")[2]))].sort();
    paginationState.set(chatId, { countryCodes, page: 0 });
    const buttons = generateCountryButtons(countryCodes, 0);
    await bot.sendMessage(chatId, "\u{1F30D} *Pilih negara:*", {
      parse_mode: "Markdown",
      reply_markup: { inline_keyboard: buttons },
      ...options
    });
  } catch (error) {
    console.error("Error fetching IP list:", error);
    await bot.sendMessage(chatId, `\u26A0\uFE0F *Terjadi kesalahan saat mengambil daftar IP: ${error.message}*`, { parse_mode: "Markdown", ...options });
  }
}
async function handleCallbackQuery2(bot, callbackQuery, options = {}) {
  const chatId = callbackQuery.message.chat.id;
  const data = callbackQuery.data;
  if (data.startsWith("page_")) {
    if (!paginationState.has(chatId)) {
      await bot.answerCallbackQuery(callbackQuery.id, { text: "Session expired, silakan ulangi perintah." });
      return;
    }
    const { countryCodes } = paginationState.get(chatId);
    let page = paginationState.get(chatId).page;
    if (data.startsWith("page_prev_")) {
      const newPage = parseInt(data.split("_")[2], 10);
      if (newPage >= 0) {
        page = newPage;
        paginationState.set(chatId, { countryCodes, page });
        const buttons = generateCountryButtons(countryCodes, page);
        await bot.editMessageReplyMarkup({
          chat_id: chatId,
          message_id: callbackQuery.message.message_id,
          reply_markup: { inline_keyboard: buttons },
          ...options
        });
      }
      await bot.answerCallbackQuery(callbackQuery.id);
      return;
    }
    if (data.startsWith("page_next_")) {
      const newPage = parseInt(data.split("_")[2], 10);
      const maxPage = Math.ceil(countryCodes.length / 12) - 1;
      if (newPage <= maxPage) {
        page = newPage;
        paginationState.set(chatId, { countryCodes, page });
        const buttons = generateCountryButtons(countryCodes, page);
        await bot.editMessageReplyMarkup({
          chat_id: chatId,
          message_id: callbackQuery.message.message_id,
          reply_markup: { inline_keyboard: buttons },
          ...options
        });
      }
      await bot.answerCallbackQuery(callbackQuery.id);
      return;
    }
  }
  if (data.startsWith("select_")) {
    if (!canSendMessage(chatId, `select_${data}`)) {
      await bot.answerCallbackQuery(callbackQuery.id);
      return;
    }
    const countryCode = data.split("_")[1];
    try {
      const response = await fetch("https://raw.githubusercontent.com/paoandest/botak/refs/heads/main/cek/proxyList.txt");
      const ipText = await response.text();
      const ipList = ipText.split("\n").filter((line) => line.trim() !== "");
      const filteredIPs = ipList.filter((line) => line.split(",")[2] === countryCode);
      if (filteredIPs.length === 0) {
        await bot.sendMessage(chatId, `\u26A0\uFE0F *Tidak ada IP tersedia untuk negara ${countryCode}.*`, { parse_mode: "Markdown", ...options });
        await bot.answerCallbackQuery(callbackQuery.id);
        return;
      }
      const randomProxy = filteredIPs[Math.floor(Math.random() * filteredIPs.length)];
      const [ip, port, , provider] = randomProxy.split(",");
      const statusResponse = await fetch(`${APIKU}${ip}:${port}`);
        const text = await statusResponse.text();
        let ipData;
        try {
            ipData = JSON.parse(text);
        } catch (e) {
            await bot.sendMessage(chatId, `\u26A0\uFE0F Gagal mem-parsing respons dari server untuk IP ${ip}:${port}. Respons: ${text}`, {
                parse_mode: "Markdown",
                ...options
            });
            await bot.answerCallbackQuery(callbackQuery.id);
            return;
        }
      const status = ipData.status === "ACTIVE" ? "\u2705 ACTIVE" : "\u274C DEAD";
      const safeProvider = provider.replace(/[^a-zA-Z0-9]/g, "").slice(0, 10);
      const buttons = [
        [
          { text: "⚡ VLESS", callback_data: `config_vless_${ip}_${port}_${countryCode}_${safeProvider}` },
          { text: "🎯 TROJAN", callback_data: `config_trojan_${ip}_${port}_${countryCode}_${safeProvider}` }
        ],
        [
          { text: "✨ SHADOWSOCKS", callback_data: `config_ss_${ip}_${port}_${countryCode}_${safeProvider}` }
        ]
      ];
      let messageText = `\u2705 *Info IP untuk ${getFlagEmoji2(countryCode)} ${countryCode} :*
\`\`\`
INFORMATION
IP      : ${ip}
PORT    : ${port}
ISP     : ${provider}
COUNTRY : ${ipData.country}
STATUS  : ${status}
\`\`\``;
      if (ipData.latitude && ipData.longitude) {
        messageText += `
\u{1F449} \u{1F30D} [View Google Maps](https://www.google.com/maps?q=${ipData.latitude},${ipData.longitude})`;
      }
      await bot.sendMessage(chatId, messageText, {
        parse_mode: "Markdown",
        reply_markup: { inline_keyboard: buttons },
        ...options
      });
    } catch (error) {
      console.error("\u274C Error fetching IP status:", error);
      await bot.sendMessage(chatId, `\u26A0\uFE0F *Terjadi kesalahan saat memverifikasi IP.*`, { parse_mode: "Markdown", ...options });
    }
    await bot.answerCallbackQuery(callbackQuery.id);
    return;
  }
  if (data.startsWith("config_")) {
    if (!canSendMessage(chatId, `config_${data}`)) {
      await bot.answerCallbackQuery(callbackQuery.id);
      return;
    }
    try {
      const [_, type, ip, port, countryCode, provider] = data.split("_");
      const uuid = generateUUID3();
      const path = encodeURIComponent(`/Free-VPN-CF-Geo-Project/${ip}=${port}`);
      const prov = encodeURIComponent(`${provider} ${getFlagEmoji2(countryCode)}`);
      const toBase642 = (str) => {
        if (typeof btoa === "function") {
          return btoa(unescape(encodeURIComponent(str)));
        } else if (typeof Buffer !== "undefined") {
          return Buffer.from(str, "utf-8").toString("base64");
        } else {
          return encodeURIComponent(str);
        }
      };
      let configText = "";
      if (type === "vless") {
        configText = `\`\`\`VLESS-TLS
vless://${uuid}@${DEFAULT_HOST2}:443?encryption=none&security=tls&sni=${DEFAULT_HOST2}&fp=randomized&type=ws&host=${DEFAULT_HOST2}&path=${path}#${prov}
\`\`\`\`\`\`VLESS-NTLS
vless://${uuid}@${DEFAULT_HOST2}:80?path=${path}&security=none&encryption=none&host=${DEFAULT_HOST2}&fp=randomized&type=ws&sni=${DEFAULT_HOST2}#${prov}
\`\`\``;
      } else if (type === "trojan") {
        configText = `\`\`\`TROJAN-TLS
trojan://${uuid}@${DEFAULT_HOST2}:443?encryption=none&security=tls&sni=${DEFAULT_HOST2}&fp=randomized&type=ws&host=${DEFAULT_HOST2}&path=${path}#${prov}
\`\`\`\`\`\`TROJAN-NTLS
trojan://${uuid}@${DEFAULT_HOST2}:80?path=${path}&security=none&encryption=none&host=${DEFAULT_HOST2}&fp=randomized&type=ws&sni=${DEFAULT_HOST2}#${prov}
\`\`\``;
      } else if (type === "ss") {
        configText = `\`\`\`SHADOWSOCKS-TLS
ss://${toBase642(`none:${uuid}`)}@${DEFAULT_HOST2}:443?encryption=none&type=ws&host=${DEFAULT_HOST2}&path=${path}&security=tls&sni=${DEFAULT_HOST2}#${prov}
\`\`\`\`\`\`SHADOWSOCKS-NTLS
ss://${toBase642(`none:${uuid}`)}@${DEFAULT_HOST2}:80?encryption=none&type=ws&host=${DEFAULT_HOST2}&path=${path}&security=none&sni=${DEFAULT_HOST2}#${prov}
\`\`\``;
      }
      await bot.sendMessage(chatId, configText, {
        parse_mode: "Markdown",
        ...options,
        reply_markup: {
          inline_keyboard: [[backToMenuButton]]
        }
      });
    } catch (err) {
      console.error("\u274C Error generating config:", err);
      await bot.sendMessage(chatId, `\u26A0\uFE0F *Gagal membuat konfigurasi.*`, { parse_mode: "Markdown", ...options });
    }
    await bot.answerCallbackQuery(callbackQuery.id);
    return;
  }
  await bot.answerCallbackQuery(callbackQuery.id);
}

// src/wildcard/botwild.js
const KonstantaGlobalbot = class {
  constructor({ apiKey, rootDomain, accountID, zoneID, apiEmail, serviceName }) {
    this.apiKey = apiKey;
    this.rootDomain = rootDomain;
    this.accountID = accountID;
    this.zoneID = zoneID;
    this.apiEmail = apiEmail;
    this.serviceName = serviceName;
    this.headers = {
      "Authorization": `Bearer ${this.apiKey}`,
      "X-Auth-Email": this.apiEmail,
      "X-Auth-Key": this.apiKey,
      "Content-Type": "application/json"
    };
  }
  escapeMarkdownV2(text) {
    return text.replace(/([_*\[\]()~`>#+=|{}.!\\-])/g, "\\$1");
  }
  // Menambahkan metode baru untuk menangani format domain.
  buildDomain(subdomain) {
    return `${subdomain}.${this.serviceName}.${this.rootDomain}`.toLowerCase();
  }
  extractSubdomain(domain) {
    const fullSuffix = `.${this.serviceName}.${this.rootDomain}`;
    if (domain.toLowerCase().endsWith(fullSuffix)) {
      return domain.slice(0, -fullSuffix.length);
    }
    const rootSuffix = `.${this.rootDomain}`;
    if (domain.toLowerCase().endsWith(rootSuffix)) {
      return domain.slice(0, -rootSuffix.length);
    }
    return null;
  }
  // Cloudflare API: ambil daftar domain Workers
  async getDomainList() {
    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const res = await fetch(url, { headers: this.headers });
    if (!res.ok) return [];
    const json = await res.json();
    return json.result.filter((d) => d.service === this.serviceName).map((d) => d.hostname);
  }
  // Cloudflare API: tambahkan subdomain
  async addSubdomain(subdomain) {
    const domain = this.buildDomain(subdomain);
    const registered = await this.getDomainList();
    if (registered.includes(domain)) return 409;
    try {
      const testRes = await fetch(`https://${subdomain}`);
      if (testRes.status === 530) return 530;
    } catch {
      return 400;
    }
    const url = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const body = {
      environment: "production",
      hostname: domain,
      service: this.serviceName,
      zone_id: this.zoneID
    };
    const res = await fetch(url, {
      method: "PUT",
      headers: this.headers,
      body: JSON.stringify(body)
    });
    return res.status;
  }
  // Cloudflare API: hapus subdomain
  async deleteSubdomain(subdomain) {
    const domain = this.buildDomain(subdomain);
    const listUrl = `https://api.cloudflare.com/client/v4/accounts/${this.accountID}/workers/domains`;
    const listRes = await fetch(listUrl, { headers: this.headers });
    if (!listRes.ok) return listRes.status;
    const json = await listRes.json();
    const obj = json.result.find((d) => d.hostname === domain);
    if (!obj) return 404;
    const res = await fetch(`${listUrl}/${obj.id}`, {
      method: "DELETE",
      headers: this.headers
    });
    return res.status;
  }
  saveDomainRequest(request) {
    globalThis.subdomainRequests.push(request);
  }
  findPendingRequest(subdomain, requesterId = null) {
    return globalThis.subdomainRequests.find(
      (r) => r.subdomain === subdomain && r.status === "pending" && (requesterId === null || r.requesterId === requesterId)
    );
  }
  updateRequestStatus(subdomain, status) {
    const r = globalThis.subdomainRequests.find(
      (r2) => r2.subdomain === subdomain && r2.status === "pending"
    );
    if (r) r.status = status;
  }
  getAllRequests() {
    return globalThis.subdomainRequests.slice();
  }
  getRandomHost() {
    return "joss.dus.biz.id";
  }
};
const TelegramWildcardBot = class {
  constructor(token, apiUrl, ownerId, globalBot) {
    this.token = token;
    this.apiUrl = apiUrl || "https://api.telegram.org";
    this.ownerId = ownerId;
    this.globalBot = globalBot;
    this.awaitingDeleteList = {};
    this.handleUpdate = this.handleUpdate.bind(this);
  }
  escapeMarkdownV2(text) {
    return this.globalBot.escapeMarkdownV2(text);
  }
  async handleUpdate(update) {
    if (!update.message) return new Response("OK", { status: 200 });
    const chatId = update.message.chat.id;
    const from = update.message.from;
    const username = from.username || from.first_name || "Unknown";
    const text = update.message.text || "";
    const isOwner = from.id === this.ownerId;
    const now = (/* @__PURE__ */ new Date()).toLocaleString("id-ID", { timeZone: "Asia/Jakarta" });
    const message_thread_id = update.message.message_thread_id;
    const options = message_thread_id ? { message_thread_id } : {};
    if (awaitingAddList.has(chatId) && text && !text.startsWith("/")) {
      const subdomains = text.split(/\s+/).map((s) => s.trim()).filter(Boolean);
      awaitingAddList.delete(chatId);
      const targetMessageId = menuMessageIds.get(chatId) || update.message.message_id;
      if (subdomains.length === 0) {
        await this.sendMessage(chatId, "No valid subdomains provided. Operation cancelled.", { ...options,
          reply_to_message_id: targetMessageId,
          reply_markup: {
            inline_keyboard: [[backToMenuButton]]
          }
        });
        return new Response("OK", { status: 200 });
      }
      const results = [];
      for (const sd of subdomains) {
        const cleanSd = sd.trim();
        const full = this.globalBot.buildDomain(cleanSd);
        let st = 500;
        try {
          st = await this.globalBot.addSubdomain(cleanSd);
        } catch {
        }
        results.push(
          st === 200 ? "```✅-Wildcard\n" + full + " added successfully.```" : `❌ Failed to add domain *${full}*, status: ${st}`
        );
      }
      await this.sendMessage(chatId, results.join("\n\n"), { parse_mode: "Markdown", ...options,
        reply_to_message_id: targetMessageId,
        reply_markup: {
          inline_keyboard: [[backToMenuButton]]
        }
      });
      return new Response("OK", { status: 200 });
    }
    if (/^\/add(@\w+)?/.test(text)) {
      const targetMessageId = menuMessageIds.get(chatId) || update.message.message_id;
      const lines = text.split("\n").map((l) => l.trim()).filter(Boolean);
      const firstLine = lines[0];
      const restLines = lines.slice(1);
      let subdomains = [];
      if (firstLine.includes(" ") && restLines.length === 0) {
        subdomains = firstLine.split(" ").slice(1).map((s) => s.trim()).filter(Boolean);
      } else if (restLines.length > 0) {
        subdomains = restLines;
      }
      if (subdomains.length === 0) {
        awaitingAddList.set(chatId, true);
        await this.sendMessage(
          chatId,
          "Please enter the subdomain you want to add.",
          { parse_mode: "Markdown", ...options,
            reply_to_message_id: targetMessageId,
            reply_markup: {
              inline_keyboard: [[backToMenuButton]]
            }
          }
        );
        return new Response("OK", { status: 200 });
      }
      const results = [];
      for (const sd of subdomains) {
        const cleanSd = sd.trim();
        const full = this.globalBot.buildDomain(cleanSd);
        let st = 500;
        try {
          st = await this.globalBot.addSubdomain(cleanSd);
        } catch {
        }
        results.push(
          st === 200 ? "```\u2705-Wildcard\n" + full + " added successfully.```" : `\u274C Failed to add domain *${full}*, status: ${st}`
        );
      }
      await this.sendMessage(chatId, results.join("\n\n"), { parse_mode: "Markdown", ...options,
        reply_to_message_id: targetMessageId,
        reply_markup: {
          inline_keyboard: [[backToMenuButton]]
        }
      });
      return new Response("OK", { status: 200 });
    }
    if (/^\/del(@\w+)?/.test(text)) {
      const targetMessageId = menuMessageIds.get(chatId) || update.message.message_id;
      if (!isOwner) {
        await this.sendMessage(chatId, "\u26D4 You are not authorized to use this command.", { ...options,
          reply_to_message_id: targetMessageId,
          reply_markup: {
            inline_keyboard: [[backToMenuButton]]
          }
        });
        return new Response("OK", { status: 200 });
      }

      const args = text.split(" ").slice(1);

      if (args.length === 0) {
        await this.sendMessage(
          chatId,
          `\u{1F4DD} *How to use /del:*\n\n` +
          `1. Delete by subdomain:\n` +
          `   \`/del sub1 sub2\`\n\n` +
          `2. Delete by number from /listwildcard:\n` +
          `   \`/del 1 2 3\`\n\n` +
          `\u26A0\uFE0F You can combine both, but it is not recommended.`,
          { parse_mode: "Markdown", ...options,
            reply_to_message_id: targetMessageId,
            reply_markup: {
              inline_keyboard: [[backToMenuButton]]
            }
          }
        );
        return new Response("OK", { status: 200 });
      }

      const areAllNumbers = args.every(arg => /^\d+$/.test(arg));
      let domainsToDelete = [];
      const errorMessages = [];

      if (areAllNumbers) {
        try {
          const domains = await this.globalBot.getDomainList();
          const indices = args.map(n => parseInt(n, 10) - 1);
          const validIndices = new Set();
          
          indices.forEach(index => {
            if (index >= 0 && index < domains.length) {
              validIndices.add(index);
            } else {
              errorMessages.push(`\u274C Invalid number *${index + 1}*.`);
            }
          });
          
          domainsToDelete = [...validIndices].map(index => domains[index]);

        } catch (e) {
          await this.sendMessage(chatId, `\u274C Failed to get domain list: ${e.message}`, { ...options, reply_to_message_id: targetMessageId });
          return new Response("OK", { status: 200 });
        }
      } else {
        domainsToDelete = args;
      }

      const results = [];
      for (const item of domainsToDelete) {
        const subdomain = this.globalBot.extractSubdomain(item.toLowerCase().trim());
        if (!subdomain) {
          results.push(`\u274C Invalid domain format: *${item}*`);
          continue;
        }

        const fullDomain = this.globalBot.buildDomain(subdomain);
        let status;
        try {
          status = await this.globalBot.deleteSubdomain(subdomain);
        } catch (e) {
          status = 500; 
        }

        if (status === 200) {
          results.push(`\u2705 Wildcard *${fullDomain}* deleted successfully.`);
        } else if (status === 404) {
          results.push(`\u26A0\uFE0F Wildcard *${fullDomain}* not found.`);
        } else {
          results.push(`\u274C Failed to delete *${fullDomain}* (status: ${status}).`);
        }
      }
      
      const finalMessage = [...errorMessages, ...results].join("\n");
      if (finalMessage) {
        await this.sendMessage(chatId, finalMessage, { parse_mode: "Markdown", ...options,
          reply_to_message_id: targetMessageId,
          reply_markup: {
            inline_keyboard: [[backToMenuButton]]
          }
        });
      }
      
      return new Response("OK", { status: 200 });
    }
    if (/^\/listwildcard(@\w+)?$/.test(text)) {
      const targetMessageId = menuMessageIds.get(chatId) || update.message.message_id;
      let domains = [];
      try {
        domains = await this.globalBot.getDomainList();
      } catch {
      }
      if (!domains.length) {
        await this.sendMessage(chatId, "*No subdomains registered yet.*", { parse_mode: "MarkdownV2", ...options,
          reply_to_message_id: targetMessageId,
          reply_markup: {
            inline_keyboard: [[backToMenuButton]]
          }
        });
      } else {
        const listText = domains.map(
          (d, i) => `${i + 1}\\. \`${this.escapeMarkdownV2(d)}\``
          // Only the domain is backticked
        ).join("\n");
        await this.sendMessage(
          chatId,
          `\u{1F310} CUSTOM DOMAIN LIST:

${listText}

\u{1F4CA} Total: *${domains.length}* subdomain${domains.length > 1 ? "s" : ""}`,
          { parse_mode: "MarkdownV2", ...options,
            reply_to_message_id: targetMessageId,
            reply_markup: {
              inline_keyboard: [[backToMenuButton]]
            }
          }
        );
        const fileContent = domains.map((d, i) => `${i + 1}. ${d}`).join("\n");
        await this.sendDocument(chatId, fileContent, "wildcard-list.txt", "text/plain", { ...options, reply_to_message_id: targetMessageId });
      }
      return new Response("OK", { status: 200 });
    }
    if (/^\/approve(@\w+)?\s+\S+/.test(text)) {
      if (!isOwner) {
        await this.sendMessage(chatId, `
\`\`\`
\u26D4 You are not authorized to use this command.
\`\`\`
`, options);
        return new Response("OK", { status: 200 });
      }
      const sd = text.split(" ")[1]?.trim();
      if (!sd) return new Response("OK", { status: 200 });
      const full = `${sd}.${this.globalBot.rootDomain}`;
      const req = this.globalBot.findPendingRequest(sd);
      if (!req) {
        await this.sendMessage(chatId, `\u26A0\uFE0F No pending request for subdomain *${full}*.`, { parse_mode: "Markdown", ...options });
      } else {
        let st = 500;
        try {
          st = await this.globalBot.addSubdomain(sd);
        } catch {
        }
        if (st === 200) {
          this.globalBot.updateRequestStatus(sd, "approved");
          await this.sendMessage(chatId, `\`\`\`
\u2705 Wildcard ${full} approved and added.
\`\`\``, { parse_mode: "Markdown", ...options });
          await this.sendMessage(req.requesterId, `\`\`\`
\u2705 Your Wildcard request for ${full} has been approved at:
${now}
\`\`\``, { parse_mode: "Markdown", ...options });
        } else {
          await this.sendMessage(chatId, `\u274C Failed to add domain *${full}*, status: ${st}`, { parse_mode: "Markdown", ...options });
        }
      }
      return new Response("OK", { status: 200 });
    }
    if (/^\/reject(@\w+)?\s+\S+/.test(text)) {
      if (!isOwner) {
        await this.sendMessage(chatId, "```\n\u26D4 You are not authorized to use this command.\n```", options);
        return new Response("OK", { status: 200 });
      }
      const sd = text.split(" ")[1]?.trim();
      if (!sd) return new Response("OK", { status: 200 });
      const full = `${sd}.${this.globalBot.rootDomain}`;
      const req = this.globalBot.findPendingRequest(sd);
      if (!req) {
        await this.sendMessage(chatId, `\u26A0\uFE0F No pending request for subdomain *${full}*.`, { parse_mode: "Markdown", ...options });
      } else {
        this.globalBot.updateRequestStatus(sd, "rejected");
        await this.sendMessage(
          chatId,
          "```\n\u274C Wildcard " + full + " has been rejected.\n```",
          { parse_mode: "Markdown", ...options }
        );
        await this.sendMessage(
          req.requesterId,
          "```\n\u274C Your Wildcard request for " + full + " has been rejected at:\n" + now + "\n```",
          { parse_mode: "Markdown", ...options }
        );
      }
      return new Response("OK", { status: 200 });
    }
    if (/^\/req(@\w+)?$/.test(text)) {
      if (!isOwner) {
        await this.sendMessage(chatId, "\u26D4 You are not authorized to view the request list.", { parse_mode: "MarkdownV2", ...options });
        return new Response("OK", { status: 200 });
      }
      const all = this.globalBot.getAllRequests();
      if (!all.length) {
        await this.sendMessage(chatId, "\u{1F4ED} No subdomain requests have been received yet.", { parse_mode: "MarkdownV2", ...options });
      } else {
        let lines = "";
        all.forEach((r, i) => {
          const domain = this.escapeMarkdownV2(r.domain);
          const status = this.escapeMarkdownV2(r.status);
          const requester = this.escapeMarkdownV2(r.requesterUsername);
          const requesterId = this.escapeMarkdownV2(r.requesterId.toString());
          const time = this.escapeMarkdownV2(r.requestTime);
          lines += `*${i + 1}\\. ${domain}* \u2014 _${status}_
`;
          lines += `   requester: @${requester} \\(ID: ${requesterId}\\)
`;
          lines += `   time: ${time}

`;
        });
        const message = `\u{1F4CB} *All Requests List:*

${lines}`;
        await this.sendMessage(chatId, message, { parse_mode: "MarkdownV2", ...options });
      }
      return new Response("OK", { status: 200 });
    }
    return new Response("OK", { status: 200 });
  }
  async sendMessage(chatId, text, options = {}) {
    const payload = { chat_id: chatId, text, ...options };
    await fetch(`${this.apiUrl}/bot${this.token}/sendMessage`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
  }
  async sendDocument(chatId, content, filename, mimeType, options = {}) {
    const formData = new FormData();
    formData.append("chat_id", chatId.toString());
    formData.append("document", new Blob([content], { type: mimeType }), filename);

    for (const key in options) {
      if (options.hasOwnProperty(key)) {
        formData.append(key, options[key].toString());
      }
    }

    await fetch(`${this.apiUrl}/bot${this.token}/sendDocument`, {
      method: "POST",
      body: formData
    });
  }
};

// src/bot.js
const HOSTKU = "joss.dus.biz.id";
const TelegramBot = class {
  constructor(token, apiUrl, ownerId) {
    this.token = token;
    this.apiUrl = apiUrl || "https://api.telegram.org";
    this.ownerId = ownerId;
  }
  async handleUpdate(update) {
    if (!update.message && !update.callback_query) {
      return new Response("OK", { status: 200 });
    }
    if (update.callback_query) {
      const { message, data } = update.callback_query;
      const chatId = message.chat.id;
      const messageId = message.message_id;
      return new Response("OK", { status: 200 });
    }
    if (update.message) {
      const { chat, text: messageText } = update.message;
      const chatId = chat.id;
      const text = messageText?.trim() || "";
      const message_thread_id = update.message.message_thread_id;
      const options = message_thread_id ? { message_thread_id } : {};
      
      if (/^\/ping(@\w+)?$/.test(text)) {
    const targetMessageId = menuMessageIds.get(chatId) || messageId;
    
    // Generate random latency kelipatan 10 antara 10-90ms
    const latencyOptions = [10, 20, 30, 40, 50, 60, 70, 80, 90];
    const randomLatency = latencyOptions[Math.floor(Math.random() * latencyOptions.length)];
    
    // Pilih emoji berdasarkan latency
    let emoji = '⚡';
    if (randomLatency <= 30) emoji = '🚀';
    else if (randomLatency <= 60) emoji = '⚡';
    else emoji = '💨';
    
    const firstMessage = 'Pong!🏓';
    const secondMessage = `Latency: ${randomLatency}ms ${emoji}`;
    const replyMarkup = {
        inline_keyboard: [
            [{ text: "👨‍💻 Contact Developer", url: "https://t.me/sampiiiiu" }],
            [backToMenuButton]
        ]
    };
    
    await this.sendMessage(chatId, firstMessage, { reply_to_message_id: targetMessageId, ...options });
    await this.sendMessage(chatId, secondMessage, { reply_markup: replyMarkup, reply_to_message_id: targetMessageId, ...options });
    
    return new Response("OK", { status: 200 });
}
    
      if (/^\/config(@\w+)?$/.test(text)) {
        const targetMessageId = menuMessageIds.get(chatId) || messageId;
        const helpMsg = `\u{1F31F} *ROTATE CONFIG GUIDE* \u{1F31F}

Type the following command to get a rotated config based on the country:

\`rotate + country_code\`

Available countries:
id, sg, my, us, ca, in, gb, ir, ae, fi, tr, md, tw, ch, se, nl, es, ru, ro, pl, al, nz, mx, it, de, fr, am, cy, dk, br, kr, vn, th, hk, cn, jp.

Example:
\`rotate id\`
\`rotate sg\`
\`rotate my\`

The bot will randomly select an IP from that country and send its config.`;
        await this.sendMessage(chatId, helpMsg, {
          parse_mode: "Markdown",
            reply_to_message_id: targetMessageId,
            ...options,
            reply_markup: {
              inline_keyboard: [[backToMenuButton]]
            }
        });
        return new Response("OK", { status: 200 });
      }
      if (/^rotate(@\w+)?\s+\w+$/.test(text)) {
        await rotateconfig.call(this, chatId, text, options);
        return new Response("OK", { status: 200 });
      }
    }
  }
  async sendMessage(chatId, text, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/sendMessage`;
    const body = {
      chat_id: chatId,
      text,
      parse_mode: "Markdown",
      ...options
    };
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  async editMessage(chatId, messageId, text, replyMarkup) {
    const url = `${this.apiUrl}/bot${this.token}/editMessageText`;
    const body = {
      chat_id: chatId,
      message_id: messageId,
      text,
      parse_mode: "Markdown"
    };
    if (replyMarkup) {
      body.reply_markup = replyMarkup;
    }
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
    return response.json();
  }
  async sendMessageWithDelete(chatId, text, options = {}) {
    try {
      const res = await this.sendMessage(chatId, text, options);
      return res.result;
    } catch (e) {
      console.error("Gagal mengirim pesan:", e);
      return null;
    }
  }
  async deleteMessage(chatId, messageId, options = {}) {
    const url = `${this.apiUrl}/bot${this.token}/deleteMessage`;
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        chat_id: chatId,
        message_id: messageId,
        ...options
      })
    });
    return res.json();
  }
};

// src/kuota.js
const CekkuotaBotku = class {
  constructor(token, apiUrl = "https://api.telegram.org") {
    this.token = token;
    this.apiUrl = apiUrl;
    this.baseUrl = `${this.apiUrl}/bot${this.token}`;
  }

  async sendMessage(chatId, text, options = {}) {
    const url = `${this.baseUrl}/sendMessage`;
    const body = { chat_id: chatId, text, ...options };
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!res.ok) {
        const errorData = await res.json();
        throw new Error(`Telegram API error: ${errorData.description || res.statusText}`);
      }
      return res.json();
    } catch (err) {
      console.error(`[ERROR] Gagal mengirim pesan ke ${chatId}:`, err.message);
      return null;
    }
  }

  async _handleQuotaCheck(chatId, number, targetMessageId, options) {
    const phoneRegex = /^08[1-9][0-9]{7,10}$/;
    if (!phoneRegex.test(number)) {
      await this.sendMessage(chatId,
        "  *INVALID NUMBER FORMAT*\n\n" +
        "Correct format:\n" +
        " 08xxxxxxxxxx\n" +
        " 10-13 digits\n\n" +
        "Example: `087812345678`", {
          parse_mode: "Markdown",
          reply_to_message_id: targetMessageId,
          ...options
        }
      );
      return;
    }

    const loadingMessage = await this.sendMessage(chatId,
      "🔄 *Checking Quota...*\n\n" +
      `📞 Number: \`${number}\`\n` +
      "⏳ Please wait a moment...", {
        parse_mode: "Markdown",
        ...options
      }
    );
    const messageIdToDelete = loadingMessage && loadingMessage.result ? loadingMessage.result.message_id : null;

    try {
      const response = await fetch(`https://api.allorigins.win/raw?url=https://dompul.sampi.workers.dev/?msisdn=${number}`, {
        headers: {
          'User-Agent': 'curl/7.81.0'
        }
      });
      const responseText = await response.text();

      try {
        const data = JSON.parse(responseText);

        if (data.statusCode === 200 && data.status) {
          let resultText = data.data.hasil.replace(/<br>/g, "\n");

          const lines = resultText.split('\n');
          let formattedMessage =
            "📊 *DATA PLAN QUOTA INFORMATION*\n\n" +
            `📱 *Number:* \`${number}\`\n` +
            "┅┅┅┅┅┅┅┅┅┅┅┅\n\n";

          if (lines?.length) {
            for (const line of lines) {
              if (line.trim()) {
                let trimmedLine = line.trim();

                trimmedLine = trimmedLine.replace(/SISA PULSA/i, 'REMAINING BALANCE');
                trimmedLine = trimmedLine.replace(/SISA KUOTA/i, 'REMAINING QUOTA');
                trimmedLine = trimmedLine.replace(/MASA AKTIF/i, 'ACTIVE PERIOD');

                if (trimmedLine.includes('REMAINING BALANCE')) {
                  formattedMessage += `💵 *${trimmedLine}*\n`;
                } else if (trimmedLine.includes('REMAINING QUOTA')) {
                  formattedMessage += `📦 *${trimmedLine}*\n`;
                } else if (trimmedLine.includes('ACTIVE PERIOD')) {
                  formattedMessage += `⏰ *${trimmedLine}*\n`;
                } else if (trimmedLine.includes(':')) {
                  const [key, value] = trimmedLine.split(':');
                  formattedMessage += `• *${key.trim()}:* \`${value?.trim() || 'Not available'}\`\n`;
                } else {
                  formattedMessage += `📌 ${trimmedLine}\n`;
                }
              }
            }
          }

          formattedMessage += "\n┅┅┅┅┅┅┅┅┅┅┅┅\n" +
            `🕐 *Update:* ${new Date().toLocaleString('en-US')}\n` +
            "💡 *Info:* Data might be delayed by a few minutes";

          await this.sendMessage(chatId, formattedMessage, {
            parse_mode: "Markdown",
            ...options
          });

        } else {
          const errorData = {
            success: false,
            message: data.message || 'No additional information',
            possibleCauses: [
              "Number not registered",
              "Operator system disruption",
              "Data not available"
            ]
          };

          if (errorData?.success === false) {
            let errorMessage =
              "❌ *FAILED TO RETRIEVE DATA*\n\n" +
              `📱 Number: \`${number}\`\n\n` +
              "⚠️ *Possible causes:*\n";

            for (const cause of errorData.possibleCauses) {
              errorMessage += `• ${cause}\n`;
            }

            errorMessage += `\n📝 *Error Message:* ${errorData.message}`;

            await this.sendMessage(chatId, errorMessage, {
              parse_mode: "Markdown",
              ...options
            });
          }
        }
      } catch (jsonError) {
        const errorCases = [
          "Invalid JSON format",
          "API response issue",
          "Corrupted data"
        ];

        let errorMessage =
          "❌ *INVALID RESPONSE*\n\n" +
          "An error occurred while processing the data.\n\n" +
          "🔧 *Possible issues:*\n";

        for (const errorCase of errorCases) {
          errorMessage += `• ${errorCase}\n`;
        }

        errorMessage += "\nPlease try again in a moment";

        await this.sendMessage(chatId, errorMessage, {
          parse_mode: "Markdown",
          ...options
        });
      }
    } catch (fetchError) {
      const fetchErrors = [
        "Could not connect to the server",
        "Connection timeout",
        "Network disruption"
      ];

      let errorMessage =
        "❌ *CONNECTION FAILED*\n\n" +
        "Could not connect to the server.\n\n" +
        "🔧 *Possible causes:*\n";

      for (const error of fetchErrors) {
        errorMessage += `• ${error}\n`;
      }

      errorMessage += `\n📝 *Error Details:* ${fetchError.message}`;

      await this.sendMessage(chatId, errorMessage, {
        parse_mode: "Markdown",
        ...options
      });
    } finally {
      if (messageIdToDelete) {
        await this.deleteMessage(chatId, messageIdToDelete);
      }
    }
  }

  async handleUpdate(update) {
    const msg = update.message;
    const chatId = msg?.chat?.id;
    const text = msg?.text?.trim() || "";
    const message_thread_id = msg?.message_thread_id;
    const options = message_thread_id ? {
      message_thread_id
    } : {};

    if (awaitingKuotaNumber.has(chatId) && text && !text.startsWith("/")) {
      awaitingKuotaNumber.delete(chatId);
      const number = text;
      const targetMessageId = menuMessageIds.get(chatId) || msg.message_id;
      await this._handleQuotaCheck(chatId, number, targetMessageId, options);
      return new Response("OK", {
        status: 200
      });
    }

    if (!chatId || !text) {
      return new Response("OK", {
        status: 200
      });
    }

    if (/^\/kuota(@\w+)?/.test(text)) {
      const args = text.split(" ");
      const number = args[1];

      if (!number) {
        const targetMessageId = menuMessageIds.get(chatId) || msg.message_id;
        awaitingKuotaNumber.set(chatId, true);
        await this.sendMessage(chatId,
          "  *CHECK DATA PLAN QUOTA*\n\n" +
          "Please enter your phone number:", {
            parse_mode: "Markdown",
            reply_to_message_id: targetMessageId,
            ...options
          }
        );
        return new Response("OK", {
          status: 200
        });
      }

      const targetMessageId = menuMessageIds.get(chatId) || msg.message_id;
      await this._handleQuotaCheck(chatId, number, targetMessageId, options);
      return new Response("OK", {
        status: 200
      });
    }
  }
};

// src/sublink/sublink.js

// Daftar negara akan di-load dari proxyList.txt
let COUNTRIES = [];

// Fungsi untuk load countries dari proxyList.txt
async function loadCountries() {
    try {
        console.log('Loading countries from proxyList.txt...');
        
        const response = await fetch('https://raw.githubusercontent.com/paoandest/botak/refs/heads/main/cek/proxyList.txt');
        
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        const proxyData = await response.text();
        
        // Parse proxyList.txt dan ekstrak kode negara unik
        const countrySet = new Set();
        const lines = proxyData.split('\n').filter(line => line.trim());
        
        lines.forEach(line => {
            const parts = line.split(',');
            if (parts.length >= 3) {
                const countryCode = parts[2].trim(); // Kolom ketiga adalah kode negara
                if (countryCode && countryCode.length === 2) {
                    countrySet.add(countryCode.toUpperCase());
                }
            }
        });
        
        // Konversi ke array dan buat objek countries
        COUNTRIES = Array.from(countrySet).map(code => ({
            code: code,
            name: code // Untuk nama, kita gunakan kode negara saja
        })).sort((a, b) => a.code.localeCompare(b.code));
        
        console.log(`Successfully loaded ${COUNTRIES.length} unique countries from proxy list`);
        
    } catch (error) {
        console.error('Failed to load countries from proxy list:', error);
        COUNTRIES = [];
    }
}

// Panggil loadCountries saat module di-load
loadCountries().catch(error => {
    console.error('Failed to initialize countries:', error);
});

// Fungsi untuk mendapatkan countries (dengan promise jika belum ready)
async function getCountries() {
    // Jika COUNTRIES masih kosong, tunggu sebentar dan coba lagi
    if (COUNTRIES.length === 0) {
        await new Promise(resolve => setTimeout(resolve, 500));
        // Jika masih kosong setelah wait, coba load ulang
        if (COUNTRIES.length === 0) {
            await loadCountries();
        }
    }
    return COUNTRIES;
}

const ITEMS_PER_PAGE = 15;

function flag(code) {
    // Fungsi untuk mendapatkan emoji bendera dari kode negara ISO 3166-1 alpha-2
    return code
        .toUpperCase()
        .replace(/./g, char => String.fromCodePoint(char.charCodeAt(0) + 127397));
}

// Modifikasi getCountryKeyboard untuk handle async
async function getCountryKeyboard(page = 0) {
    const countries = await getCountries();
    
    // Jika masih tidak ada countries, return keyboard kosong dengan pesan error
    if (countries.length === 0) {
        return {
            inline_keyboard: [
                [{ text: "❌ Failed to load countries", callback_data: "sublink_ignore" }],
                [{ text: "🔄 Retry", callback_data: "sublink_retry_countries" }]
            ]
        };
    }
    
    const start = page * ITEMS_PER_PAGE;
    const end = start + ITEMS_PER_PAGE;
    const paginatedCountries = countries.slice(start, end);
    const totalPages = Math.ceil(countries.length / ITEMS_PER_PAGE);

    // 1. Baris Opsi Khusus (All Countries & Random)
    const specialOptions = [
        [{ text: "🌍 All Countries", callback_data: "sublink_country_all" }],
        [{ text: "🎲 Random", callback_data: "sublink_country_random" }]
    ];

    // 2. Baris Pilihan Negara (15 per halaman, 4 per baris)
    const countryRows = [];
    for (let i = 0; i < paginatedCountries.length; i += 4) { 
        const row = paginatedCountries.slice(i, i + 4).map(country => ({
            text: `${flag(country.code)} (${country.code})`,
            callback_data: `sublink_country_${country.code.toLowerCase()}`
        }));
        countryRows.push(row);
    }

    // 3. Baris Navigasi (Pagination)
    const navigationRow = [];
    if (page > 0) {
        navigationRow.push({ text: "◀ Prev", callback_data: `sublink_page_${page - 1}` });
    }
    navigationRow.push({ text: `Page ${page + 1}/${totalPages}`, callback_data: "sublink_ignore" }); 
    if (page < totalPages - 1) {
        navigationRow.push({ text: "Next ▶", callback_data: `sublink_page_${page + 1}` });
    }

    return {
        inline_keyboard: [
            ...specialOptions,
            ...countryRows,
            navigationRow.length > 0 ? navigationRow : []
        ].filter(row => row.length > 0)
    };
}

const sublinkState = new Map();
const SublinkBuilderBot = class {
 constructor(token, apiUrl = "https://api.telegram.org", ownerId, globalBot) {
  this.token = token;
  this.apiUrl = apiUrl;
  this.globalBot = globalBot;
 }
 
 async handleUpdate(update, ctx) {
  if (update.message && update.message.text) {
   const chatId = update.message.chat.id;
        const messageId = update.message.message_id;
   const text = update.message.text.trim();
   const message_thread_id = update.message.message_thread_id;
        const targetMessageId = menuMessageIds.get(chatId) || messageId;
   const options = message_thread_id ? { message_thread_id } : {};
   if (/^\/sublink(@\w+)?$/.test(text)) {
    return this.start(chatId, targetMessageId, options);
   }
   const state = sublinkState.get(chatId);
   if (state) {
    if (state.step === "bug") {
     state.bug = text;
     state.step = "limit";
     await this.sendMessage(chatId, "Masukkan batas (angka antara 1-20):", { reply_to_message_id: state.targetMessageId, ...options });
    } else if (state.step === "limit") {
     const limit = parseInt(text, 10);
     if (isNaN(limit) || limit < 1 || limit > 20) {
      await this.sendMessage(chatId, "Masukan tidak valid. Silakan masukkan angka antara 1 dan 20.", { reply_to_message_id: state.targetMessageId, ...options });
     } else {
      state.limit = limit;
      state.step = "country";
                state.countryPage = 0; 
      const keyboard = await getCountryKeyboard(state.countryPage);
      await this.sendMessage(chatId, "Pilih negara:", { reply_markup: keyboard, reply_to_message_id: state.targetMessageId, ...options });
     }
    }
   }
  }
  
  if (update.callback_query) {
   const chatId = update.callback_query.message.chat.id;
   const messageId = update.callback_query.message.message_id;
   const data = update.callback_query.data;
   const message_thread_id = update.callback_query.message.message_thread_id;
   const options = message_thread_id ? { message_thread_id } : {};
   const state = sublinkState.get(chatId);
   await this.answerCallbackQuery(update.callback_query.id); 
   
   if (data === "sublink_start_over") {
    return this.start(chatId, messageId, options);
   }

   if (!state || !data.startsWith("sublink_")) {
    return new Response("OK", { status: 200 });
   }
   
   const [_, step, value] = data.split("_");

   // Handle retry countries
   if (data === "sublink_retry_countries") {
        await loadCountries();
        const keyboard = await getCountryKeyboard(state.countryPage || 0);
        await this.editMessageText(chatId, messageId, "Pilih negara:", { reply_markup: keyboard, ...options });
        return new Response("OK", { status: 200 });
    }

   // --- Handle Navigasi Halaman Negara ---
        if (step === "page" && state.step === "country") {
            const newPage = parseInt(value, 10);
            const countries = await getCountries();
            const totalPages = Math.ceil(countries.length / ITEMS_PER_PAGE);
            
            if (!isNaN(newPage) && newPage >= 0 && newPage < totalPages) {
                state.countryPage = newPage;
                const keyboard = await getCountryKeyboard(newPage);
                await this.editMessageText(chatId, messageId, "Pilih negara:", { reply_markup: keyboard, ...options });
            }
            return new Response("OK", { status: 200 });
        }
        
   if (step === "app" && state.step === "app") {
    state.app = value;
    state.step = "type";
    const keyboard = {
        inline_keyboard: [
            [
                { text: "⚡ VLESS", callback_data: "sublink_type_vless" },
                { text: "🎯 Trojan", callback_data: "sublink_type_trojan" }
            ],
            [
                { text: "✨ Shadowsocks", callback_data: "sublink_type_shadowsocks" }
            ]
        ]
    };
    await this.editMessageText(chatId, messageId, "Pilih tipe protokol:", { reply_markup: keyboard, ...options });
   } else if (step === "type" && state.step === "type") {
    state.type = value;
    state.step = "tls";
    const keyboard = {
     inline_keyboard: [
      [{ text: "True", callback_data: "sublink_tls_true" }, { text: "False", callback_data: "sublink_tls_false" }]
     ]
    };
    await this.editMessageText(chatId, messageId, "Gunakan TLS?", { reply_markup: keyboard, ...options });
   } else if (step === "tls" && state.step === "tls") {
    state.tls = value;
    state.step = "wildcard";
    const keyboard = {
     inline_keyboard: [
      [{ text: "True", callback_data: "sublink_wildcard_true" }, { text: "False", callback_data: "sublink_wildcard_false" }]
     ]
    };
    await this.editMessageText(chatId, messageId, "Use Wildcards?", { reply_markup: keyboard, ...options });
   } else if (step === "wildcard" && state.step === "wildcard") {
    state.wildcard = value;
    state.step = "bug";
    await this.editMessageText(chatId, messageId, "Please submit your host bug (example: ava.game.naver.com):", options);
   } else if (step === "country" && state.step === "country") {
    state.country = value;
    state.processingMessageId = messageId;
    await this.editMessageText(chatId, messageId, "Processing your request...", options);
    const randomHost = this.globalBot.getRandomHost();
    let url;
    if (state.country === "all") {
     url = `https://${randomHost}/vpn/${state.app}?type=${state.type}&bug=${state.bug}&tls=${state.tls}&wildcard=${state.wildcard}&limit=${state.limit}`;
    } else if (state.country === "random") {
     url = `https://${randomHost}/vpn/${state.app}?type=${state.type}&bug=${state.bug}&tls=${state.tls}&wildcard=${state.wildcard}&limit=${state.limit}&country=random`;
    } else {
     url = `https://${randomHost}/vpn/${state.app}?type=${state.type}&bug=${state.bug}&tls=${state.tls}&wildcard=${state.wildcard}&limit=${state.limit}&country=${state.country}`;
    }
    console.log(`Mengakses URL: ${url}`);
    try {
     const response = await fetch(url);
     if (!response.ok) {
      throw new Error(`Gagal mengambil data dari URL: ${response.statusText}`);
     }
     const content = await response.text();
     if (!content || content.trim() === "") {
      throw new Error("Tidak ada data yang diterima dari server");
     }
     let countryDisplay;
     const countries = await getCountries();
     const selectedCountry = countries.find(c => c.code.toLowerCase() === state.country);
            
     if (state.country === "all") {
      countryDisplay = "All Countries";
     } else if (state.country === "random") {
      countryDisplay = "Random Country";
     } else if (selectedCountry) {
        // Tampilkan emoji dan kode negara di caption hasil akhir
        countryDisplay = `${flag(selectedCountry.code)} ${selectedCountry.code}`;
     } else {
        countryDisplay = state.country.toUpperCase();
     }

     const caption = `🔗 Sublink Created Successfully!
 
┅┅┅┅┅┅┅┅┅┅┅┅ 
📱 App: ${state.app} 
⚙️ Type: ${state.type} 
🐛 Bug: ${state.bug} 
🔒 TLS: ${state.tls} 
🎯 Wildcard: ${state.wildcard} 
📊 Limit: ${state.limit} 
🌍 Country: ${countryDisplay} 
┅┅┅┅┅┅┅┅┅┅┅ 

👇 Click the link below to copy:

${url}`;
     await this.deleteMessage(chatId, state.processingMessageId);
     await this.sendDocument(chatId, content, "sublink.txt", "text/plain", {
      caption,
      parse_mode: "HTML",
              reply_to_message_id: state.targetMessageId,
              reply_markup: {
                  inline_keyboard: [[{ text: "⬅️ Back to sublink", callback_data: "sublink_start_over" }]]
              },
      ...options
     });
    } catch (error) {
     console.error("Error:", error);
     await this.deleteMessage(chatId, state.processingMessageId);
     await this.sendMessage(chatId, `\u274C Terjadi Kesalahan

${error.message}

Silakan coba lagi dengan parameter yang berbeda.`, {
      parse_mode: "HTML",
            reply_to_message_id: state.targetMessageId,
      ...options
     });
    }
   }
  }
  return new Response("OK", { status: 200 });
 }

 // ... method-method lainnya tetap sama
 async answerCallbackQuery(callbackQueryId) {
    const url = `${this.apiUrl}/bot${this.token}/answerCallbackQuery`;
    const body = { callback_query_id: callbackQueryId };
    await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body)
    });
  }

 async start(chatId, targetMessageId, options = {}) {
  sublinkState.set(chatId, { 
    step: "app", 
    targetMessageId: targetMessageId 
  });
  
  const keyboard = {
    inline_keyboard: [
      [
        { text: "🚀 V2Ray", callback_data: "sublink_app_v2ray" }, 
        { text: "⚡ Clash", callback_data: "sublink_app_clash" }
      ],
      [
        { text: "📱 Nekobox", callback_data: "sublink_app_nekobox" }, 
        { text: "🔧 Singbox", callback_data: "sublink_app_singbox" }
      ],
      [
        { text: "🏄 Surfboard", callback_data: "sublink_app_surfboard" }
      ],
      [
        backToMenuButton
      ]
    ]
  };
  
  await this.sendMessage(chatId, "📲 Silakan pilih aplikasi:", { 
    reply_markup: keyboard, 
    reply_to_message_id: targetMessageId, 
    ...options 
  });
  
  return new Response("OK", { status: 200 });
}
 
 // ... method-method lainnya (sendMessage, editMessageText, sendDocument, deleteMessage) tetap sama
 async sendMessage(chatId, text, options = {}) {
  const url = `${this.apiUrl}/bot${this.token}/sendMessage`;
  const body = {
   chat_id: chatId,
   text,
   parse_mode: "Markdown",
   ...options
  };
  const response = await fetch(url, {
   method: "POST",
   headers: { "Content-Type": "application/json" },
   body: JSON.stringify(body)
  });
  return response.json();
 }
 
 async editMessageText(chatId, messageId, text, options = {}) {
  const url = `${this.apiUrl}/bot${this.token}/editMessageText`;
  const body = {
   chat_id: chatId,
   message_id: messageId,
   text,
   parse_mode: "Markdown",
   ...options
  };
  const response = await fetch(url, {
   method: "POST",
   headers: { "Content-Type": "application/json" },
   body: JSON.stringify(body)
  });
  return response.json();
 }
 
 async sendDocument(chatId, content, filename, mimeType, options = {}) {
  const formData = new FormData();
  const blob = new Blob([content], { type: mimeType });
  formData.append("document", blob, filename);
  formData.append("chat_id", String(chatId));
  if (options.message_thread_id) {
   formData.append("message_thread_id", String(options.message_thread_id));
  }
  if (options.caption) {
   formData.append("caption", options.caption);
  }
  if (options.parse_mode) {
   formData.append("parse_mode", options.parse_mode);
  }
  if (options.reply_to_message_id) {
   formData.append("reply_to_message_id", String(options.reply_to_message_id));
  }
  if (options.reply_markup) {
   formData.append("reply_markup", JSON.stringify(options.reply_markup));
  }
  const response = await fetch(`${this.apiUrl}/bot${this.token}/sendDocument`, {
   method: "POST",
   body: formData
  });
  return response.json();
 }
 
 async deleteMessage(chatId, messageId) {
  try {
   const url = `${this.apiUrl}/bot${this.token}/deleteMessage`;
   const body = { chat_id: chatId, message_id: messageId };
   const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
   });
   const result = await response.json();
   if (!result.ok) {
    console.warn("Gagal menghapus pesan:", result);
   }
   return result;
  } catch (error) {
   console.error("Error saat menghapus pesan:", error);
  }
 }
};

// src/worker.js
const worker_default = {
  async fetch(request, env, ctx) {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }
    try {
      let update = await request.json();
      const token = "7664381872:AAFBZquRrIqh7jALwv6-hkcb-ZXMrjqLMB0";
      const ownerId = 1467883032;

      // Centralized group membership check
      const checkerBot = new Converterbot(token, "https://api.telegram.org", ownerId, env);
      const isMember = await checkerBot._checkGroupMembership(update);
      if (!isMember) {
        return new Response("OK", { status: 200 }); // Stop processing if not a member
      }

      const apiKey = "28595cd826561d8014059ca54712d3ca3332c";
      const accountID = "716746bfb7638b3aaa909b55740fbc60";
      const zoneID = "3be1ebf3d8d2e93efaf8851e6f5b5339";
      const apiEmail = "pihajamal@gmail.com";
      const serviceName = "joss";
      const rootDomain = "dus.biz.id";
      const globalBot = new KonstantaGlobalbot({
        apiKey,
        accountID,
        zoneID,
        apiEmail,
        serviceName,
        rootDomain
      });
      
      // Centralized Callback Query Handling
      if (update.callback_query) {
        const originalCallbackQuery = update.callback_query; // Store the original callback
        const data = originalCallbackQuery.data;

        if (data.startsWith("menu_cmd_")) {
          const command = data.substring("menu_cmd_".length);
          // Create a new, fake update object that mimics a text command
          const fakeUpdate = {
            message: {
              ...originalCallbackQuery.message, // Use the stored callback
              text: `/${command}`,
              from: originalCallbackQuery.from // Use the stored callback
            }
          };
          // Overwrite the original update with our fake one
          update = fakeUpdate;
        }

        // Answer the callback query here using the original, stored object
        const botForCallback = new Converterbot(token, "https://api.telegram.org", ownerId, env);
        ctx.waitUntil(botForCallback.answerCallbackQuery(originalCallbackQuery.id));
      }

      const bot1 = new TelegramBot(token, "https://api.telegram.org", ownerId, globalBot);
      const bot2 = new TelegramBotku(token, "https://api.telegram.org", ownerId, globalBot);
      const bot3 = new TelegramProxyCekBot(token, "https://api.telegram.org", ownerId, globalBot);
      const bot5 = new TelegramWildcardBot(token, "https://api.telegram.org", ownerId, globalBot);
      const bot6 = new CekkuotaBotku(token, "https://api.telegram.org");
      const bot7 = new Converterbot(token, "https://api.telegram.org", ownerId, env);
      const sublinkBot = new SublinkBuilderBot(token, "https://api.telegram.org", ownerId, globalBot);

      ctx.waitUntil(Promise.allSettled([
        bot1.handleUpdate(update),
        bot2.handleUpdate(update),
        bot3.handleUpdate(update),
        bot5.handleUpdate(update),
        bot6.handleUpdate(update),
        bot7.handleUpdate(update),
        sublinkBot.handleUpdate(update)
      ]));
      
      return new Response("OK", { status: 200 });
    } catch (error) {
      console.error("Error in fetch handler:", error);
      return new Response(
        JSON.stringify({ error: error.message, stack: error.stack }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" }
        }
      );
    }
  }
};
export {
  worker_default as default
};
 
