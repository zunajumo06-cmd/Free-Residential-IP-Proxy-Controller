// ====== 免费住宅IP智能调度系统 (单端口自定义 + 智能区域双重熔断释放 + 全球全量国家版) ======

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const domain = url.origin;

    // --- 提取并处理云端安全隔离变量 ---
    const WEB_USER = env.WEB_USER || "admin";        
    const WEB_PASS = env.WEB_PASS;
    const PROXY_USER = env.PROXY_USER || "proxyuser";   
    const PROXY_PASS = env.PROXY_PASS;
    if (!WEB_PASS || !PROXY_PASS) {
      return new Response("Set WEB_PASS and PROXY_PASS secrets before using this service.", { status: 503 });
    }
    const configuredProxyPort = env.PROXY_PORT ? parseInt(env.PROXY_PORT, 10) : 10001;
    const PROXY_PORT = Number.isInteger(configuredProxyPort) && configuredProxyPort >= 1 && configuredProxyPort <= 65535 ? configuredProxyPort : 10001;

    // ====================================================
    // [基础防御] 浏览器与安全节点 Basic Auth 鉴权函数
    // ====================================================
    const authenticate = (request) => {
      const authHeader = request.headers.get("Authorization");
      if (!authHeader) return false;
      const [scheme, encoded] = authHeader.split(" ");
      if (scheme !== "Basic") return false;
      try {
        const decoded = atob(encoded);
        const [username, password] = decoded.split(":");
        return username === WEB_USER && password === WEB_PASS;
      } catch (e) {
        return false;
      }
    };

    const unauthorizedResponse = () => {
      return new Response("Unauthorized Access. Scanner Blocked.", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="Residential Proxy Security Control"',
          "Content-Type": "text/plain;charset=UTF-8"
        }
      });
    };

    // Installer and generated scripts contain credentials and require panel authentication.
    if (url.pathname === "/agent" || url.pathname === "/scripts/lite_manager.py" || url.pathname === "/scripts/proxy_server.py") {
      if (!authenticate(request)) return unauthorizedResponse();
    }

    // ====================================================
    // [1] 数据库建表 (D1)
    // ====================================================
      await env.DB.prepare(`
        CREATE TABLE IF NOT EXISTS servers (
          ip TEXT PRIMARY KEY,
          details TEXT,
          log TEXT DEFAULT '',
          candidates TEXT DEFAULT '[]',
          last_seen INTEGER
        )
      `).run();
      try { await env.DB.prepare(`ALTER TABLE servers ADD COLUMN log TEXT DEFAULT ''`).run(); } catch (e) {}
      try { await env.DB.prepare(`ALTER TABLE servers ADD COLUMN candidates TEXT DEFAULT '[]'`).run(); } catch (e) {}

    await env.DB.prepare(`
      CREATE TABLE IF NOT EXISTS global_config (
        key TEXT PRIMARY KEY,
        value TEXT
      )
    `).run();

    // ====================================================
    // [2] 动态分发：Proxy Server 引擎源码
    // ====================================================
    if (url.pathname === "/scripts/proxy_server.py") {
      const PROXY_CODE = `#!/usr/bin/env python3
from __future__ import annotations
import select, socket, threading, urllib.parse, time, base64
from typing import Any

PROXY_USER = b"${PROXY_USER}"
PROXY_PASS = b"${PROXY_PASS}"

def parse_int(value: Any) -> int:
    try: return int(value)
    except: return 0

def recv_exact(sock: socket.socket, size: int) -> bytes:
    data = b""
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk: raise ConnectionError("Unexpected disconnect.")
        data += chunk
    return data

def create_connection(address: tuple[str, int], bind_interface: str, timeout: float = 20) -> socket.socket:
    host, port = address
    err = None
    for res in socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM):
        af, socktype, proto, canonname, sa = res
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            sock.settimeout(timeout)
            if bind_interface:
                sock.setsockopt(socket.SOL_SOCKET, 25, bind_interface.encode('utf-8'))
            sock.connect(sa)
            return sock
        except OSError as e:
            err = e
            if sock: sock.close()
    raise err or OSError("getaddrinfo empty")

def relay(left: socket.socket, right: socket.socket) -> None:
    sockets = [left, right]
    while True:
        readable, _, errored = select.select(sockets, [], sockets, 120)
        if errored: return
        for source in readable:
            target = right if source is left else left
            data = source.recv(65536)
            if not data: return
            target.sendall(data)

def socks5_client(client: socket.socket, first_byte: bytes, bind_interface: str) -> None:
    upstream = None
    try:
        methods_count = recv_exact(client, 1)[0]
        methods = recv_exact(client, methods_count)
        
        if b"\\x02" not in methods:
            client.sendall(b"\\x05\\xFF") 
            return
        client.sendall(b"\\x05\\x02")
        
        auth_req = recv_exact(client, 2)
        if auth_req[0] != 1: return
        ulen = auth_req[1]
        uname = recv_exact(client, ulen)
        plen = recv_exact(client, 1)[0]
        upass = recv_exact(client, plen)
        
        if uname != PROXY_USER or upass != PROXY_PASS:
            client.sendall(b"\\x01\\x01") 
            return
        client.sendall(b"\\x01\\x00") 

        version, command, _, address_type = recv_exact(client, 4)
        if version != 5 or command != 1: return
        if address_type == 1: host = socket.inet_ntoa(recv_exact(client, 4))
        elif address_type == 3: host = recv_exact(client, recv_exact(client, 1)[0]).decode("idna")
        elif address_type == 4: host = socket.inet_ntop(socket.AF_INET6, recv_exact(client, 16))
        else: return
        port = int.from_bytes(recv_exact(client, 2), "big")
        
        upstream = create_connection((host, port), bind_interface, timeout=20)
        client.sendall(b"\\x05\\x00\\x00\\x01\\x00\\x00\\x00\\x00\\x00\\x00")
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def http_client(client: socket.socket, first_byte: bytes, bind_interface: str) -> None:
    upstream = None
    try:
        data = first_byte
        while b"\\r\\n\\r\\n" not in data and len(data) < 65536:
            chunk = client.recv(4096)
            if not chunk: break
            data += chunk
        head, rest = data.split(b"\\r\\n\\r\\n", 1)
        lines = head.decode("iso-8859-1", errors="replace").split("\\r\\n")
        
        expected_auth = "Basic " + base64.b64encode(PROXY_USER + b":" + PROXY_PASS).decode("ascii")
        auth_passed = False
        for line in lines[1:]:
            if line.lower().startswith("proxy-authorization:"):
                if line.split(":", 1)[1].strip() == expected_auth:
                    auth_passed = True
                    break
                    
        if not auth_passed:
            client.sendall(b"HTTP/1.1 407 Proxy Authentication Required\\r\\nProxy-Authenticate: Basic realm=\\"Proxy\\"\\r\\n\\r\\n")
            return

        method, target, version = lines[0].split(" ", 2)
        if method.upper() == "CONNECT":
            host, _, port_text = target.partition(":")
            upstream = create_connection((host, parse_int(port_text) or 443), bind_interface, timeout=20)
            client.sendall(b"HTTP/1.1 200 Connection Established\\r\\n\\r\\n")
            if rest: upstream.sendall(rest)
            relay(client, upstream)
            return
        parsed = urllib.parse.urlsplit(target)
        if not parsed.hostname: return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        path = urllib.parse.urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
        headers = [line for line in lines[1:] if not line.lower().startswith(("proxy-connection:", "connection:", "proxy-authorization:"))]
        request = f"{method} {path} {version}\\r\\n" + "\\r\\n".join(headers) + "\\r\\nConnection: close\\r\\n\\r\\n"
        upstream = create_connection((parsed.hostname, port), bind_interface, timeout=20)
        upstream.sendall(request.encode("iso-8859-1") + rest)
        relay(client, upstream)
    except: pass
    finally:
        client.close()
        if upstream: upstream.close()

def proxy_client(client: socket.socket, address: tuple[str, int], bind_interface: str) -> None:
    try:
        client.settimeout(30)
        first = recv_exact(client, 1)
        if first == b"\\x05": socks5_client(client, first, bind_interface)
        else: http_client(client, first, bind_interface)
    except:
        try: client.close()
        except: pass

def start_proxy_server(host: str, port: int, bind_interface: str = "tun0") -> None:
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(256)
    except Exception as e: return
    while True:
        try:
            client, address = server.accept()
            threading.Thread(target=proxy_client, args=(client, address, bind_interface), daemon=True).start()
        except: time.sleep(0.5)
`;
      return new Response(PROXY_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    // ====================================================
    // [3] 动态分发：Lite Manager 调度引擎源码 (防误杀单端口版)
    // ====================================================
    if (url.pathname === "/scripts/lite_manager.py") {
      const MANAGER_CODE = `#!/usr/bin/env python3
import base64, csv, os, subprocess, threading, time, urllib.request, json, sys
from pathlib import Path

MAX_CONCURRENT_NODES = 1
BASE_PROXY_PORT = ${PROXY_PORT}
API_URL = "https://www.vpngate.net/api/iphone/"
C2_URL = "${domain}"

WORKSPACE = Path("/opt/proxy_lite")
CONFIG_DIR = WORKSPACE / "configs"
AUTH_FILE = WORKSPACE / "auth.txt"
LOG_MAX_BYTES = 256 * 1024
REPORT_LOG_BYTES = 12 * 1024
MANAGER_LOG_FILE = WORKSPACE / "manager.log"

GOLDEN_NODES_FILE = WORKSPACE / "golden_nodes.json"
golden_nodes = {}
golden_lock = threading.Lock()

WEB_USER = "${WEB_USER}"
WEB_PASS = "${WEB_PASS}"

dynamic_slot_map = {0: "JP"}
control_mode = "auto"
manual_node_ip = ""
youtube_check_enabled = False
config_fetch_interval = 15
heartbeat_interval = 30
pool = {0: {"process": None, "ip": "", "country": "", "connected_at": 0, "connecting": False}}
pool_lock = threading.Lock()
public_ip = ""

def append_bounded_log(log_file, stream):
    try:
        with open(log_file, "a", buffering=1) as output:
            for line in iter(stream.readline, b""):
                output.write(line.decode("utf-8", errors="replace"))
                output.flush()
                if log_file.stat().st_size > LOG_MAX_BYTES:
                    content = log_file.read_bytes()[-LOG_MAX_BYTES // 2:]
                    log_file.write_bytes(b"[log truncated]\\n" + content)
    except: pass

def read_recent_log(log_file):
    try:
        return log_file.read_text(errors="replace")[-REPORT_LOG_BYTES:]
    except: return ""

def read_recent_logs():
    try:
        result = subprocess.run(
            ["journalctl", "-u", "proxy-lite.service", "-n", "120", "--no-pager", "-o", "short-iso"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5
        )
        journal = result.stdout.decode("utf-8", errors="replace").strip()
        if journal:
            return journal[-REPORT_LOG_BYTES:]
    except: pass
    manager = read_recent_log(MANAGER_LOG_FILE)
    openvpn = read_recent_log(WORKSPACE / "ovpn_err_0.log")
    return (manager + "\\n" + openvpn)[-REPORT_LOG_BYTES:]

class BoundedTee:
    def __init__(self, console, log_file):
        self.console = console
        self.log_file = log_file

    def write(self, value):
        try:
            self.console.write(value)
        except UnicodeEncodeError:
            try:
                if hasattr(self.console, "buffer"):
                    self.console.buffer.write(value.encode("utf-8", errors="replace"))
                else:
                    self.console.write(value.encode("ascii", errors="replace").decode("ascii"))
            except: pass
        try:
            self.console.flush()
        except: pass
        try:
            with open(self.log_file, "a", buffering=1) as output:
                output.write(value)
            if self.log_file.stat().st_size > LOG_MAX_BYTES:
                content = self.log_file.read_bytes()[-LOG_MAX_BYTES // 2:]
                self.log_file.write_bytes(b"[log truncated]\\n" + content)
        except: pass

    def flush(self):
        self.console.flush()

dead_ips = {} 

last_switch_timestamps = {0: 0}
global_node_reservoir = {} 
reservoir_lock = threading.Lock()

_cached_snapshot = []
_last_harvest_time = 0

def get_public_ip():
    global public_ip
    try:
        req = urllib.request.Request("https://api.ipify.org", headers={"User-Agent": "curl/7.68.0"})
        with urllib.request.urlopen(req, timeout=5) as res:
            public_ip = res.read().decode("utf-8").strip()
    except: public_ip = "Unknown_IP"

def get_c2_headers():
    auth_ptr = base64.b64encode(f"{WEB_USER}:{WEB_PASS}".encode()).decode()
    return {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Authorization": f"Basic {auth_ptr}"
    }

def is_ip_blacklisted(ip):
    if ip in dead_ips:
        if time.time() < dead_ips[ip]["expire_at"]:
            return True
        else:
            del dead_ips[ip]
    return False

def add_to_blacklist(ip, country, reason="fault", duration=60):
    dead_ips[ip] = {
        "country": country,
        "expire_at": time.time() + duration,
        "reason": reason
    }

def load_golden_nodes():
    global golden_nodes
    try:
        if GOLDEN_NODES_FILE.exists():
            with open(GOLDEN_NODES_FILE, 'r') as f: golden_nodes = json.load(f)
            print(f"[*] 📥 成功加载【黄金备用池】，当前储备历史高质节点数: {len(golden_nodes)}", flush=True)
    except: pass

def save_golden_nodes():
    try:
        with open(GOLDEN_NODES_FILE, 'w') as f: json.dump(golden_nodes, f)
    except: pass

def add_golden_node(node):
    with golden_lock:
        golden_nodes[node["ip"]] = {
            "ip": node["ip"], "country": node["country"], "config": node["config"],
            "ping": node.get("ping", 9999), "added_at": time.time()
        }
    save_golden_nodes()

def remove_golden_node(ip):
    with golden_lock:
        if ip in golden_nodes: del golden_nodes[ip]
    save_golden_nodes()

def fetch_config():
    req = urllib.request.Request(f"{C2_URL}/api/config", headers=get_c2_headers())
    with urllib.request.urlopen(req, timeout=10) as res:
        return json.loads(res.read().decode("utf-8"))

def apply_config(data):
    global dynamic_slot_map, last_switch_timestamps, BASE_PROXY_PORT, control_mode, manual_node_ip, youtube_check_enabled, config_fetch_interval, heartbeat_interval
    if "proxy_port" in data:
        new_port = int(data["proxy_port"])
        if 1 <= new_port <= 65535 and new_port != BASE_PROXY_PORT:
            print(f"[*] 检测到监听端口变更: {BASE_PROXY_PORT} -> {new_port}，准备重启服务...", flush=True)
            BASE_PROXY_PORT = new_port
            os._exit(0)
    new_mode = "manual" if data.get("mode") == "manual" else "auto"
    new_manual_node_ip = str(data.get("manual_node_ip", "")).strip()
    mode_changed = new_mode != control_mode or (new_mode == "manual" and new_manual_node_ip != manual_node_ip)
    control_mode = new_mode
    manual_node_ip = new_manual_node_ip
    youtube_check_enabled = data.get("youtube_check", False) is True
    config_fetch_interval = max(5, min(3600, int(data.get("config_fetch_interval", 15))))
    heartbeat_interval = max(10, min(3600, int(data.get("heartbeat_interval", 30))))
    if "slot_map" in data:
        new_map = {int(k): str(v).upper() for k, v in data.get("slot_map", {}).items()}
        force_switch = {int(k): int(v) for k, v in data.get("force_switch", {}).items()}
    else:
        new_map = {int(k): str(v).upper() for k, v in data.items()}
        force_switch = {}
    with pool_lock:
        for slot, desired_country in new_map.items():
            if slot >= MAX_CONCURRENT_NODES: continue
            dynamic_slot_map[slot] = desired_country
            info = pool[slot]
            cmd_ts = force_switch.get(slot, 0)
            should_switch = False
            if cmd_ts > last_switch_timestamps[slot]:
                last_switch_timestamps[slot] = cmd_ts
                should_switch = True
                print(f"[*] ⚡ 接收到母机手动干预指令: 强制刷新单端口网络层IP！", flush=True)
            if info["process"] and info["process"].poll() is None:
                current_country = info.get("country", "")
                if (current_country and current_country != desired_country) or should_switch or mode_changed:
                    if not should_switch:
                        print(f"[*] 策略变更触发: 需要从 {current_country} 切换到 {desired_country}，正在掐断旧连接...", flush=True)
                    if info["ip"]:
                        add_to_blacklist(info["ip"], info["country"], reason="manual", duration=60)
                    try: info["process"].terminate(); info["process"].wait(timeout=2)
                    except: info["process"].kill()

def update_config_loop():
    while True:
        try:
            apply_config(fetch_config())
        except: pass
        time.sleep(config_fetch_interval)

def c2_heartbeat_loop():
    if not public_ip or public_ip == "Unknown_IP": get_public_ip()
    try:
        payload = json.dumps({"ip": public_ip, "details": [], "log": read_recent_logs()}).encode('utf-8')
        req = urllib.request.Request(f"{C2_URL}/api/report", data=payload, headers=get_c2_headers(), method='POST')
        urllib.request.urlopen(req, timeout=10)
    except: pass
    while True:
        time.sleep(heartbeat_interval)
        if not public_ip or public_ip == "Unknown_IP": get_public_ip()
        details = []
        with pool_lock:
            for slot, info in pool.items():
                if info["process"] and info["process"].poll() is None:
                    uptime = time.time() - info["connected_at"]
                    if uptime > 10: 
                        actual_country = info.get("country", dynamic_slot_map.get(slot, "UN"))
                        details.append({"slot": slot, "country": actual_country, "port": BASE_PROXY_PORT, "connected_time": int(uptime), "node_ip": info["ip"]})
        log_file = WORKSPACE / "ovpn_err_0.log"
        with reservoir_lock:
            candidates = [{"ip": n["ip"], "country": n["country"], "ping": n.get("ping", 9999)} for n in global_node_reservoir.values() if n.get("ip") and not is_ip_blacklisted(n["ip"])]
        candidates.sort(key=lambda n: n["ping"])
        payload = json.dumps({"ip": public_ip, "details": details, "log": read_recent_logs(), "candidates": candidates[:500]}).encode('utf-8')
        try:
            req = urllib.request.Request(f"{C2_URL}/api/report", data=payload, headers=get_c2_headers(), method='POST')
            urllib.request.urlopen(req, timeout=10)
            print(f"[*] 成功向心跳控制塔汇报。连通率: {len(details)} / 1", flush=True)
        except: pass

def setup_env():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    sys.stdout = BoundedTee(sys.__stdout__, MANAGER_LOG_FILE)
    sys.stderr = BoundedTee(sys.__stderr__, MANAGER_LOG_FILE)
    if not AUTH_FILE.exists():
        AUTH_FILE.write_text("vpn\\nvpn\\n")
        AUTH_FILE.chmod(0o600)
    load_golden_nodes()

def harvest_snapshot_nodes() -> list:
    global _cached_snapshot, _last_harvest_time
    if time.time() - _last_harvest_time < 300 and _cached_snapshot:
        return _cached_snapshot
        
    try:
        req = urllib.request.Request(API_URL, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=15) as res: text = res.read().decode("utf-8", errors="replace")
        lines = [line for line in text.splitlines() if line and not line.startswith("*")]
        if lines and lines[0].startswith("#"): lines[0] = lines[0][1:]
        nodes = []
        for row in csv.DictReader(lines):
            ip = row.get("IP")
            if not ip or not row.get("OpenVPN_ConfigData_Base64"): continue
            raw_ping = row.get("Ping", "")
            nodes.append({
                "ip": ip, "ping": int(raw_ping) if raw_ping.isdigit() else 9999, 
                "country": row.get("CountryShort", "").upper(), 
                "config": base64.b64decode(row["OpenVPN_ConfigData_Base64"]).decode("utf-8", errors="replace"),
                "harvested_at": time.time()
            })
        if nodes:
            _cached_snapshot = nodes
            _last_harvest_time = time.time()
        return _cached_snapshot
    except: return _cached_snapshot

def setup_routing(slot: int):
    dev, table = f"tun{slot}", str(100 + slot)
    subprocess.run(["ip", "rule", "del", "table", table], capture_output=True)
    subprocess.run(["ip", "route", "flush", "table", table], capture_output=True)
    subprocess.run(["ip", "route", "add", "default", "dev", dev, "table", table], capture_output=True)
    subprocess.run(["ip", "rule", "add", "oif", dev, "table", table], capture_output=True)

def connect_slot(slot: int, node: dict):
    try:
        dev, cfg_path, log_file = f"tun{slot}", CONFIG_DIR / f"tun{slot}.ovpn", WORKSPACE / f"ovpn_err_{slot}.log"
        cfg_path.write_text(node["config"])
        ovpn_version = subprocess.run(["openvpn", "--version"], capture_output=True, text=True).stdout
        cipher_args = ["--ncp-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"] if "2.4" in ovpn_version else ["--data-ciphers", "AES-128-CBC:AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305", "--data-ciphers-fallback", "AES-128-CBC"]
        cmd = ["openvpn", "--config", str(cfg_path), "--dev", dev, "--dev-type", "tun", "--pull-filter", "ignore", "route-ipv6", "--pull-filter", "ignore", "ifconfig-ipv6", "--route-nopull", "--auth-user-pass", str(AUTH_FILE), "--auth-nocache", "--connect-timeout", "10", "--connect-retry-max", "1", "--verb", "3"] + cipher_args
        log_file.write_text("")
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        threading.Thread(target=append_bounded_log, args=(log_file, process.stdout), daemon=True).start()
        
        success = False
        for _ in range(25):
            time.sleep(1)
            if process.poll() is not None: break
            try:
                if "Initialization Sequence Completed" in log_file.read_text():
                    success = True; break
            except: pass
                
        if success and process.poll() is None:
            is_residential = True
            try:
                print(f"[*] 单端口 ({node['country']}) 隧道初步打通，鉴定是否为纯正住宅IP...", flush=True)
                req_url = f"https://ip.net.coffee/ip/{node['ip']}"
                check_req = urllib.request.Request(req_url, headers={"User-Agent": "Mozilla/5.0"})
                with urllib.request.urlopen(check_req, timeout=10) as check_res:
                    api_resp = check_res.read().decode("utf-8").lower()
                    if "residential" in api_resp or "isp" in api_resp or "住宅" in api_resp: is_residential = True
                    else:
                        clean_resp = api_resp.replace(" ", "").replace("\\n", "").replace("\\r", "")
                        if "hosting" in api_resp or "datacenter" in api_resp or "机房" in api_resp or "data center" in api_resp:
                            if '"hosting":false' not in clean_resp and '"datacenter":false' not in clean_resp: is_residential = False
            except: pass
            
            if not is_residential:
                is_history_golden = False
                with golden_lock:
                    if node["ip"] in golden_nodes: is_history_golden = True
                
                if is_history_golden:
                    print(f"[*] 单端口 ({node['country']}) 虽为机房IP，但具备【历史黄金池】免死特权，强制放行: {node['ip']}", flush=True)
                else:
                    print(f"[-] 单端口 ({node['country']}) 检测为机房IP，暂时隔离冷却(2小时): {node['ip']}", flush=True)
                    try: process.terminate(); process.wait(timeout=2)
                    except: process.kill()
                    add_to_blacklist(node["ip"], node["country"], reason="datacenter", duration=7200) 
                    with pool_lock: pool[slot]["connecting"] = False
                    return

            setup_routing(slot)
            
            services_passed = True
            if youtube_check_enabled:
                print(f"[*] 单端口 ({node['country']}) 核验通过，执行 YouTube 业务连通性测试...", flush=True)
                test_urls = ["https://www.youtube.com"]
                for test_url in test_urls:
                    res = subprocess.run(["curl", "-s", "-I", "-m", "15", "-H", "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "--interface", f"tun{slot}", test_url], capture_output=True)
                    if res.returncode != 0:
                        print(f"[-] 单端口 ({node['country']}) 访问 {test_url} 阻断/超时，临时冷却: {node['ip']}", flush=True)
                        services_passed = False
                        break
            
            if not services_passed:
                try: process.terminate(); process.wait(timeout=2)
                except: process.kill()
                add_to_blacklist(node["ip"], node["country"], reason="fault", duration=60)
                with pool_lock: pool[slot]["connecting"] = False
                return

            add_golden_node(node)
            with pool_lock:
                pool[slot]["process"] = process
                pool[slot]["ip"] = node["ip"]
                pool[slot]["country"] = node["country"]
                pool[slot]["connected_at"] = time.time()
            print(f"[+] 单端口 ({node['country']}) 优质IP完全就绪入池: {node['ip']}", flush=True)
        else:
            try: process.terminate(); process.wait(timeout=2)
            except: process.kill()
            add_to_blacklist(node["ip"], node["country"], reason="fault", duration=60)
    finally:
        with pool_lock: pool[slot]["connecting"] = False

def health_check_loop():
    test_targets = [
        "http://www.gstatic.com/generate_204",
        "http://captive.apple.com/hotspot-detect.html",
        "https://www.cloudflare.com/cdn-cgi/trace",
        "http://www.msftconnecttest.com/connecttest.txt"
    ]

    while True:
        time.sleep(60) 
        slots_to_check = []
        with pool_lock:
            for slot, info in pool.items():
                if info["process"] and info["process"].poll() is None and (time.time() - info["connected_at"] > 60):
                    slots_to_check.append((slot, info["process"], info["ip"], dynamic_slot_map.get(slot, "UN")))
        
        for slot, process, ip, country in slots_to_check:
            failed = True
            
            for attempt in range(2):
                alive = False
                for target in test_targets:
                    res = subprocess.run(["curl", "-s", "-I", "-m", "10", "--interface", f"tun{slot}", target], capture_output=True)
                    if res.returncode == 0:
                        alive = True
                        break 
                
                if alive:
                    failed = False
                    break 
                    
                time.sleep(3)

            if failed:
                print(f"[!] 单端口网络 连续多次【多渠道联合盲探】均失败！判定掉线重拨: {ip}", flush=True)
                add_to_blacklist(ip, country, reason="fault", duration=60)
                try: process.terminate(); process.wait(timeout=2)
                except: process.kill()

def maintain_pool():
    global dead_ips, global_node_reservoir, golden_nodes
    while True:
        snapshot = harvest_snapshot_nodes()
        with reservoir_lock:
            for n in snapshot:
                global_node_reservoir[n["ip"]] = n
                
            now = time.time()
            stale_ips = [ip for ip, node in global_node_reservoir.items() if now - node["harvested_at"] > 10800]
            for ip in stale_ips: global_node_reservoir.pop(ip, None)
            print(f"[*] ⚡ 蓄水池循环，当前大池常驻: {len(global_node_reservoir)} 个 (极品保留库: {len(golden_nodes)} 个)", flush=True)

        empty_slots = []
        with pool_lock:
            for slot, info in pool.items():
                if not info["connecting"] and (info["process"] is None or info["process"].poll() is not None):
                    empty_slots.append(slot)
                    info["process"] = None; info["ip"] = ""; info["country"] = ""
        
        if empty_slots:
            with reservoir_lock:
                all_pool_nodes = sorted(list(global_node_reservoir.values()), key=lambda x: x.get("ping", 9999))
            with golden_lock:
                all_golden_nodes = sorted(list(golden_nodes.values()), key=lambda x: x.get("ping", 9999))

            used_ips = [info["ip"] for info in pool.values() if info["ip"]]
            
            for slot in empty_slots:
                if control_mode == "manual":
                    node = next((n for n in all_pool_nodes if n["ip"] == manual_node_ip), None)
                    if not node:
                        node = next((n for n in all_golden_nodes if n["ip"] == manual_node_ip), None)
                    if node and node["ip"] not in used_ips and not is_ip_blacklisted(node["ip"]):
                        used_ips.append(node["ip"])
                        with pool_lock: pool[slot]["connecting"] = True
                        threading.Thread(target=connect_slot, args=(slot, node), daemon=True).start()
                    else:
                        print(f"[-] 手动模式: 等待所选节点 {manual_node_ip or '(未选择)'} 可用...", flush=True)
                    continue

                target_country = dynamic_slot_map.get(slot, "JP")
                
                candidates = [n for n in all_pool_nodes if n["country"] == target_country and n["ip"] not in used_ips and not is_ip_blacklisted(n["ip"])]
                
                if not candidates:
                    golden_candidates = [n for n in all_golden_nodes if n["country"] == target_country and n["ip"] not in used_ips and not is_ip_blacklisted(n["ip"])]
                    if golden_candidates:
                        print(f"[*] 🏆 主池枯竭，触发【黄金备用池】！正在提取历史高质 [{target_country}] 节点...", flush=True)
                        candidates = golden_candidates

                if not candidates:
                    now_ts = time.time()
                    country_blacklisted = [ip for ip, meta in list(dead_ips.items()) if meta["country"] == target_country and now_ts < meta["expire_at"] and meta["reason"] != "datacenter"]
                    
                    if country_blacklisted:
                        for bip in country_blacklisted:
                            dead_ips.pop(bip, None)
                        print(f"[!] ⚡ 区域紧急熔断：[{target_country}] 储备资源彻底归零！已精准释放该区域共 {len(country_blacklisted)} 个冷却中节点提前救场！", flush=True)
                        candidates = [n for n in (all_pool_nodes + all_golden_nodes) if n["country"] == target_country and n["ip"] not in used_ips and not is_ip_blacklisted(n["ip"])]

                if candidates:
                    node = candidates.pop(0)
                    used_ips.append(node["ip"])
                    with pool_lock: pool[slot]["connecting"] = True
                    threading.Thread(target=connect_slot, args=(slot, node), daemon=True).start()
                    time.sleep(0.5)
                else:
                    print(f"[-] 单端口: 本地【大池+黄金储备】中该国家可用配额彻底打空，挂起抓取...", flush=True)
        time.sleep(5)

def main():
    if os.geteuid() != 0: return
    get_public_ip()
    setup_env()
    subprocess.run(["pkill", "-f", "openvpn.*tun[0-9]"], capture_output=True)
    
    print("========================================", flush=True)
    print("  免费住宅IP智能调度系统 [防误杀极品节点单端口版] 启动！", flush=True)
    print("========================================", flush=True)

    threading.Thread(target=update_config_loop, daemon=True).start()

    try:
        apply_config(fetch_config())
    except: pass

    import proxy_server
    for i in range(MAX_CONCURRENT_NODES):
        threading.Thread(target=proxy_server.start_proxy_server, args=("0.0.0.0", BASE_PROXY_PORT, f"tun{i}"), daemon=True).start()
    
    threading.Thread(target=health_check_loop, daemon=True).start()
    threading.Thread(target=c2_heartbeat_loop, daemon=True).start()
    maintain_pool()

if __name__ == "__main__":
    main()
`;
      return new Response(MANAGER_CODE, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    // ====================================================
    // [4] 动态分发：VPS 一键安装脚本
    // ====================================================
    if (url.pathname === "/agent") {
      const agentScript = `#!/usr/bin/env bash
echo "=========================================================="
echo "    免费住宅IP智能调度系统 直连部署 (智能防枯竭单端口版)"
echo "=========================================================="

crontab -l 2>/dev/null | grep -v "/opt/proxy_lite/heartbeat.sh" | crontab -
rm -f /opt/proxy_lite/heartbeat.sh

apt-get update -q
apt-get install -y openvpn python3 curl iproute2 iptables cron

mkdir -p /opt/proxy_lite/configs
cd /opt/proxy_lite

echo "[1/3] 从调度中心拉取智能隔离引擎..."
curl -fsSL -H 'Authorization: ${request.headers.get("Authorization")}' -o lite_manager.py ${domain}/scripts/lite_manager.py || exit 1
curl -fsSL -H 'Authorization: ${request.headers.get("Authorization")}' -o proxy_server.py ${domain}/scripts/proxy_server.py || exit 1

echo "[2/3] 配置系统群组守护..."
cat > /lib/systemd/system/proxy-lite.service << 'EOF'
[Unit]
Description=Residential Proxy Core Engine
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/proxy_lite
ExecStart=/usr/bin/python3 -u lite_manager.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable proxy-lite.service
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/proxy-lite.conf << 'EOF'
[Journal]
SystemMaxUse=50M
SystemMaxFileSize=10M
RuntimeMaxUse=20M
MaxRetentionSec=7day
EOF
systemctl restart systemd-journald
journalctl --vacuum-size=50M --vacuum-time=7d >/dev/null 2>&1 || true
systemctl restart proxy-lite.service

echo "[+] 智能时效隔离版本部署成功！稳定机房节点免死金牌机制已生效。"
`;
      return new Response(agentScript, { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    // ====================================================
    // [5] 开放API接口
    // ====================================================
    if (url.pathname === "/api/countries") {
        try {
            const requestedCountries = [
                "AE","AR","AT","AU","BE","BD","BG","BH","BR","CA","CH","CL","CN","CO",
                "CR","CY","CZ","DE","DK","EE","EG","ES","FI","FR","GB","GR","HK","HR",
                "HU","ID","IE","IL","IN","IQ","IR","IS","IT","JM","JO","JP","KE","KH",
                "KR","KW","KZ","LA","LB","LK","LT","LU","LV","MA","MD","MM","MN","MO",
                "MX","MY","NG","NL","NO","NP","NZ","OM","PA","PE","PH","PK","PL","PT",
                "QA","RO","RS","RU","SA","SE","SG","SI","SK","TH","TR","TW","UA","US",
                "UY","UZ","VE","VN","ZA"
            ];
            const response = await fetch("https://www.vpngate.net/api/iphone/");
            const text = await response.text();
            const lines = text.split('\n');
            const countries = new Set(requestedCountries);
            for (let i = 2; i < lines.length; i++) {
                const parts = lines[i].split(',');
                if (parts.length > 6) {
                    const country = parts[6];
                    if (country && country.length === 2 && country !== "xx" && country !== "--") countries.add(country);
                }
            }
            return new Response(JSON.stringify(Array.from(countries)), { headers: { "Content-Type": "application/json", "Access-Control-Allow-Origin": "*" } });
        } catch(err) {
            return new Response(JSON.stringify(["JP", "KR", "US", "GB", "TW"]), { headers: { "Content-Type": "application/json" } }); 
        }
    }

    // ====================================================
    // [6] 安全敏感接口拦截区
    // ====================================================
    if (url.pathname === "/" || url.pathname === "/api/config" || url.pathname === "/api/nodes" || url.pathname === "/api/proxies" || url.pathname === "/api/report" || url.pathname === "/api/switch") {
      if (!authenticate(request)) return unauthorizedResponse();
    }

    if (url.pathname === "/api/config" && request.method === "GET") {
        const { results } = await env.DB.prepare(`SELECT key, value FROM global_config WHERE key IN ('slot_map', 'force_switch', 'proxy_port', 'mode', 'manual_node_ip', 'youtube_check', 'config_fetch_interval', 'heartbeat_interval', 'frontend_poll_interval')`).all();
        let slot_map = {0: "JP"};
        let force_switch = {};
        let proxy_port = PROXY_PORT;
        let mode = 'auto';
        let manual_node_ip = '';
        let youtube_check = false;
        let config_fetch_interval = 15;
        let heartbeat_interval = 30;
        let frontend_poll_interval = 5;
        if (results) {
            for (let row of results) {
                if (row.key === 'slot_map') slot_map = JSON.parse(row.value);
                if (row.key === 'force_switch') force_switch = JSON.parse(row.value);
                if (row.key === 'proxy_port') proxy_port = parseInt(row.value, 10);
                if (row.key === 'mode') mode = row.value === 'manual' ? 'manual' : 'auto';
                if (row.key === 'manual_node_ip') manual_node_ip = row.value;
                if (row.key === 'youtube_check') youtube_check = row.value === 'true';
                if (row.key === 'config_fetch_interval') config_fetch_interval = Math.max(5, Math.min(3600, parseInt(row.value, 10) || 15));
                if (row.key === 'heartbeat_interval') heartbeat_interval = Math.max(10, Math.min(3600, parseInt(row.value, 10) || 30));
                if (row.key === 'frontend_poll_interval') frontend_poll_interval = Math.max(5, Math.min(300, parseInt(row.value, 10) || 5));
            }
        }
        return new Response(JSON.stringify({slot_map, force_switch, proxy_port, mode, manual_node_ip, youtube_check, config_fetch_interval, heartbeat_interval, frontend_poll_interval}), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/api/config" && request.method === "POST") {
        const data = await request.json();
        const proxyPort = Number.parseInt(data.proxy_port, 10);
        if (!Number.isInteger(proxyPort) || proxyPort < 1 || proxyPort > 65535) {
          return new Response("Invalid proxy port. Use a number from 1 to 65535.", { status: 400 });
        }
        const slotMap = data.slot_map || data;
        const mode = data.mode === 'manual' ? 'manual' : 'auto';
        const manualNodeIp = typeof data.manual_node_ip === 'string' ? data.manual_node_ip.trim() : '';
        const youtubeCheck = data.youtube_check === true;
        const configFetchInterval = Math.max(5, Math.min(3600, Number.parseInt(data.config_fetch_interval, 10) || 15));
        const heartbeatInterval = Math.max(10, Math.min(3600, Number.parseInt(data.heartbeat_interval, 10) || 30));
        const frontendPollInterval = Math.max(5, Math.min(300, Number.parseInt(data.frontend_poll_interval, 10) || 5));
        await env.DB.prepare(`
            INSERT INTO global_config (key, value) VALUES ('slot_map', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `).bind(JSON.stringify(slotMap)).run();
        await env.DB.prepare(`
            INSERT INTO global_config (key, value) VALUES ('proxy_port', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `).bind(String(proxyPort)).run();
        await env.DB.prepare(`
            INSERT INTO global_config (key, value) VALUES ('mode', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `).bind(mode).run();
        await env.DB.prepare(`
            INSERT INTO global_config (key, value) VALUES ('manual_node_ip', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `).bind(manualNodeIp).run();
        await env.DB.prepare(`
            INSERT INTO global_config (key, value) VALUES ('youtube_check', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `).bind(String(youtubeCheck)).run();
        for (const [key, value] of [['config_fetch_interval', configFetchInterval], ['heartbeat_interval', heartbeatInterval], ['frontend_poll_interval', frontendPollInterval]]) {
          await env.DB.prepare(`
              INSERT INTO global_config (key, value) VALUES (?1, ?2)
              ON CONFLICT(key) DO UPDATE SET value = excluded.value
          `).bind(key, String(value)).run();
        }
        return new Response("OK");
    }

    if (url.pathname === "/api/switch" && request.method === "POST") {
        const data = await request.json();
        const targetSlot = data.slot;
        let force_switch = {};
        const res = await env.DB.prepare(`SELECT value FROM global_config WHERE key = 'force_switch'`).first();
        if (res) force_switch = JSON.parse(res.value);
        force_switch[targetSlot] = Date.now();
        await env.DB.prepare(`
            INSERT INTO global_config (key, value) VALUES ('force_switch', ?1)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value
        `).bind(JSON.stringify(force_switch)).run();
        return new Response("OK");
    }

    if (url.pathname === "/api/report" && request.method === "POST") {
      try {
        const data = await request.json();
        await env.DB.prepare(`
          INSERT INTO servers (ip, details, log, candidates, last_seen) VALUES (?1, ?2, ?3, ?4, ?5)
          ON CONFLICT(ip) DO UPDATE SET details = excluded.details, log = excluded.log, candidates = excluded.candidates, last_seen = excluded.last_seen
        `).bind(data.ip, JSON.stringify(data.details || []), String(data.log || '').slice(-12000), JSON.stringify(data.candidates || []).slice(0, 100000), Date.now()).run();
        return new Response("OK", { status: 200 });
      } catch (err) { return new Response("Error", { status: 500 }); }
    }

    if (url.pathname === "/api/proxies") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`SELECT ip, details FROM servers`).all();
      let proxyList = [];
      if (results) {
        for (let server of results) {
          for (let node of JSON.parse(server.details)) {
            proxyList.push(`socks5://${PROXY_USER}:${PROXY_PASS}@${server.ip}:${node.port}#${node.country}_Port${node.port}_${node.node_ip || 'IP'}`);
          }
        }
      }
      return new Response(proxyList.join('\n'), { headers: { "Content-Type": "text/plain;charset=UTF-8" } });
    }

    if (url.pathname === "/api/nodes") {
      const cutoff = Date.now() - 120000;
      await env.DB.prepare(`DELETE FROM servers WHERE last_seen < ?1`).bind(cutoff).run();
      const { results } = await env.DB.prepare(`SELECT * FROM servers ORDER BY last_seen DESC`).all();
       return new Response(JSON.stringify((results || []).map(server => {
         let candidates = [];
         try { candidates = JSON.parse(server.candidates || '[]'); } catch (e) {}
         return {...server, candidates};
       })), { headers: { "Content-Type": "application/json" } });
    }

    if (url.pathname === "/") {
      return new Response(DASHBOARD_HTML(domain, WEB_USER, WEB_PASS, PROXY_USER, PROXY_PASS, PROXY_PORT), { headers: { "Content-Type": "text/html;charset=UTF-8" } });
    }

    return new Response("Not Found", { status: 404 });
  }
};

const DASHBOARD_HTML = (domain, webUser, webPass, proxyUser, proxyPass, proxyPort) => `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>免费住宅IP智能调度系统 (单端口防误杀版)</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-slate-950 text-slate-100 font-sans p-4 md:p-6 min-h-screen flex flex-col">
    <div class="max-w-[1440px] mx-auto w-full flex-grow relative">
        <div class="absolute -top-24 -left-24 w-72 h-72 bg-cyan-500/10 rounded-full blur-3xl pointer-events-none"></div>
        <div class="absolute top-20 right-0 w-80 h-80 bg-blue-600/10 rounded-full blur-3xl pointer-events-none"></div>
        <div class="relative flex flex-col lg:flex-row lg:justify-between lg:items-end gap-5 mb-7">
            <div>
                <div class="flex items-center gap-3 mb-3">
                    <div class="w-3 h-3 rounded-full bg-emerald-400 shadow-[0_0_18px_rgba(52,211,153,.8)]"></div>
                    <span class="text-xs tracking-[0.28em] uppercase text-cyan-300/80 font-semibold">Residential Edge Control</span>
                </div>
                <h1 class="text-3xl md:text-4xl font-black tracking-tight bg-gradient-to-r from-cyan-300 via-blue-400 to-violet-400 bg-clip-text text-transparent">住宅代理调度中心</h1>
                <p class="text-slate-400 mt-2 text-sm md:text-base">单端口智能网络编排 · 节点健康监控 · 实时遥测同步</p>
                <a href="/api/proxies" target="_blank" class="inline-flex items-center gap-2 mt-4 text-xs text-cyan-300 hover:text-cyan-200 transition">提取代理列表 <span class="font-mono bg-slate-900/80 border border-cyan-400/20 rounded px-2 py-1">${domain}/api/proxies</span></a>
            </div>
            
            <div class="flex flex-col items-end gap-2">
                <div class="glass-card p-4 rounded-2xl border border-white/10">
                    <p class="text-[11px] tracking-widest uppercase text-slate-500 mb-2">Provision New VPS</p>
                    <code class="text-emerald-300 text-xs md:text-sm select-all break-all">read -r -p 'Panel username: ' PANEL_USER; bash &lt;(curl -fsSL -u "$PANEL_USER" ${domain}/agent)</code>
                </div>
                <div class="glass-card p-3 px-4 rounded-2xl border border-white/10 w-full text-right text-xs text-slate-400">
                    <div>面板凭证 <span class="text-cyan-300 font-bold font-mono">${webUser}</span> <span class="text-slate-600">/</span> <span class="text-cyan-300 font-bold font-mono">${webPass}</span></div>
                    <div class="mt-1">代理凭证 <span class="text-amber-300 font-bold font-mono">${proxyUser}</span> <span class="text-slate-600">/</span> <span class="text-amber-300 font-bold font-mono">${proxyPass}</span></div>
                </div>
            </div>
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-4 gap-5 mb-5 relative">
            <div class="lg:col-span-1 glass-card p-5 rounded-2xl border border-white/10 flex flex-col min-h-[280px] max-h-[360px]">
                <div class="flex items-start justify-between mb-1">
                    <div><p class="text-[11px] tracking-widest uppercase text-slate-500">Global Pool</p><h2 class="text-xl font-bold text-slate-100 mt-1">可用国家</h2></div>
                    <span class="px-2 py-1 rounded-full text-[10px] bg-cyan-400/10 text-cyan-300 border border-cyan-400/20">LIVE</span>
                </div>
                <p class="text-xs text-slate-500 mb-4">节点池持续刷新，优质线路会优先进入调度队列。</p>
                <div id="countries-list" class="flex flex-wrap gap-2 overflow-y-auto custom-scrollbar flex-grow content-start">
                    <span class="text-slate-500 text-sm">正在拉取节点数据库...</span>
                </div>
            </div>
            <div class="lg:col-span-3 glass-card p-5 rounded-2xl border border-white/10">
                <div class="flex flex-col md:flex-row md:justify-between md:items-center gap-4 mb-5">
                    <div>
                        <p class="text-[11px] tracking-widest uppercase text-slate-500">Policy Console</p>
                        <h2 class="text-xl font-bold text-slate-100 mt-1">连接策略控制</h2>
                        <p class="text-xs text-slate-500 mt-1">端口、模式和节点策略保存后将同步到所有已纳管 VPS。</p>
                    </div>
                    <button onclick="saveConfig()" class="bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white px-6 py-3 rounded-xl text-sm font-bold shadow-lg shadow-cyan-900/30 transition transform hover:-translate-y-0.5">保存并全局下发</button>
                </div>
                <div class="flex flex-wrap gap-3" id="config-form">
                    <span class="text-gray-500 text-sm">加载中...</span>
                </div>
            </div>
        </div>
        
        <div class="glass-card rounded-2xl shadow-2xl shadow-black/20 overflow-hidden border border-white/10 mb-5">
            <table class="w-full text-left border-collapse">
                <thead>
                    <tr class="bg-white/[0.04] text-slate-400 border-b border-white/10">
                        <th class="py-3 px-4 font-semibold text-sm w-1/6">VPS 母机 IP</th>
                        <th class="py-3 px-4 font-semibold text-sm">已就绪的特优代理 (国家 | 节点IP:端口)</th>
                        <th class="py-3 px-4 font-semibold text-sm w-1/12">心跳状态</th>
                        <th class="py-3 px-4 font-semibold text-sm text-right w-1/12">在线率</th>
                    </tr>
                </thead>
                <tbody id="nodes-table" class="divide-y divide-gray-700">
                    <tr><td colspan="4" class="py-8 text-center text-gray-500">正在与调度中心数据库通信...</td></tr>
                </tbody>
            </table>
        </div>

        <div class="bg-[#050a12] border border-white/10 rounded-2xl shadow-2xl flex flex-col h-64 relative overflow-hidden">
            <div class="bg-white/[0.04] border-b border-white/10 px-4 py-3 flex items-center justify-between">
                <div class="flex items-center gap-2">
                    <div class="w-3 h-3 rounded-full bg-red-500"></div>
                    <div class="w-3 h-3 rounded-full bg-yellow-500"></div>
                    <div class="w-3 h-3 rounded-full bg-green-500"></div>
                    <span class="text-xs text-slate-400 ml-2 font-mono">journalctl -u proxy-lite.service</span>
                </div>
                <div class="text-[10px] text-green-400 font-mono animate-pulse">● 实时直播</div>
            </div>
             <div id="mock-terminal" class="hidden"></div>
             <pre id="remote-log" class="hidden p-4 overflow-y-auto flex-grow bg-black/40 text-xs text-green-300 whitespace-pre-wrap custom-scrollbar"></pre>
        </div>
    </div>

    <style>
        body { background-image: radial-gradient(circle at 20% 0%, rgba(14, 165, 233, .08), transparent 32rem), linear-gradient(135deg, #020617 0%, #0b1120 55%, #111827 100%); }
        .glass-card { background: linear-gradient(145deg, rgba(15, 23, 42, .88), rgba(15, 23, 42, .62)); box-shadow: 0 18px 60px rgba(0, 0, 0, .22), inset 0 1px rgba(255,255,255,.04); backdrop-filter: blur(16px); }
        th { letter-spacing: .08em; text-transform: uppercase; font-size: 10px !important; }
        td { border-color: rgba(255,255,255,.06) !important; }
        .custom-scrollbar::-webkit-scrollbar { width: 6px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: rgba(15,23,42,.6); border-radius: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #155e75; border-radius: 4px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #22d3ee; }
        @media (max-width: 640px) { body { padding: 12px; } table { min-width: 680px; } .glass-card { border-radius: 16px; } }
    </style>

    <script>
        // === 伪同步日志系统 ===
        const terminalLogs = [];
        function pushLog(msg, type="INFO") {
            const term = document.getElementById('mock-terminal');
            if (!term) return;
            const now = new Date();
            const timeStr = now.getHours().toString().padStart(2, '0') + ':' + 
                            now.getMinutes().toString().padStart(2, '0') + ':' + 
                            now.getSeconds().toString().padStart(2, '0');
            
            let color = 'text-gray-300';
            if(type === 'WARN') color = 'text-yellow-400';
            if(type === 'ERR') color = 'text-red-400';
            if(type === 'SUCCESS') color = 'text-green-400';
            if(type === 'SYS') color = 'text-blue-300';

            terminalLogs.push(\`<span class="text-gray-500">[\${timeStr}]</span> <span class="\${color}">[\${type}] \${msg}</span>\`);
            if(terminalLogs.length > 50) terminalLogs.shift();
            
            term.innerHTML = terminalLogs.join('<br>');
            term.scrollTop = term.scrollHeight;
        }

        function renderRemoteLogs(servers) {
            const log = servers.map(server => {
                const text = String(server.log || '').trim();
                return text ? \`===== \${server.ip} =====\\n\${text}\` : '';
            }).filter(Boolean).join('\\n');
            const remoteLog = document.getElementById('remote-log');
            if (log) {
                remoteLog.textContent = log.slice(-24000);
                remoteLog.classList.remove('hidden');
            } else {
                remoteLog.classList.add('hidden');
            }
        }

        async function fetchCountries() {
            try {
                const res = await fetch('/api/countries');
                const list = await res.json();
                const container = document.getElementById('countries-list');
                list.sort();
                container.innerHTML = list.map(c => \`<span class="bg-gray-700 px-2 py-1 rounded text-xs font-bold text-gray-300 border border-gray-600 cursor-pointer hover:bg-gray-600 transition" onclick="document.getElementById('slot-cfg-0').value='\${c}'">\${c}</span>\`).join('');
            } catch(e) {}
        }

        async function loadConfig() {
            try {
                const res = await fetch('/api/config');
                const map_data = await res.json();
                const map = map_data.slot_map || map_data; 
                const container = document.getElementById('config-form');
                
                const port = Number(map_data.proxy_port) || ${proxyPort};
                const val = map[0] || 'JP';
                let html = \`
                    <div class="flex flex-wrap items-end gap-4 bg-gray-900 border border-gray-700 rounded p-4 relative group">
                        <div class="flex flex-col gap-2 w-48">
                            <label for="control-mode" class="text-[12px] text-gray-400 text-left">连接模式</label>
                            <select id="control-mode" onchange="toggleManualMode()" class="bg-gray-800 border border-gray-600 rounded p-2 text-white font-bold focus:outline-none focus:border-blue-400 transition w-full">
                                <option value="auto" \${map_data.mode === 'manual' ? '' : 'selected'}>自动连接</option>
                                <option value="manual" \${map_data.mode === 'manual' ? 'selected' : ''}>手动选择</option>
                            </select>
                        </div>
                        <div class="flex flex-col gap-2 min-w-56 flex-1">
                            <label for="manual-node" class="text-[12px] text-gray-400 text-left">手动节点</label>
                            <select id="manual-node" class="bg-gray-800 border border-gray-600 rounded p-2 text-white font-mono focus:outline-none focus:border-blue-400 transition w-full">
                                <option value="\${map_data.manual_node_ip || ''}">等待节点列表...</option>
                            </select>
                        </div>
                        <div class="flex flex-col gap-2 w-48">
                            <label for="proxy-port" class="text-[12px] text-gray-400 text-left">代理监听端口</label>
                            <input type="number" id="proxy-port" value="\${port}" min="1" max="65535" step="1" required class="bg-gray-800 border border-gray-600 rounded p-2 text-white text-center font-bold text-xl focus:outline-none focus:border-blue-400 transition w-full" />
                        </div>
                        <label class="flex items-center gap-3 px-3 py-2 rounded-xl bg-slate-800/70 border border-white/10 cursor-pointer select-none">
                            <input type="checkbox" id="youtube-check" \${map_data.youtube_check ? 'checked' : ''} class="w-4 h-4 accent-cyan-400" />
                            <span><strong class="block text-sm text-slate-200">YouTube 可用检测</strong><small class="text-[11px] text-slate-500">默认关闭，减少连接耗时</small></span>
                        </label>
                        <div class="flex flex-col gap-2 w-40">
                            <label for="config-fetch-interval" class="text-[12px] text-gray-400 text-left">Agent 拉配置间隔（秒）</label>
                            <input type="number" id="config-fetch-interval" value="\${map_data.config_fetch_interval || 15}" min="5" max="3600" step="1" class="bg-gray-800 border border-gray-600 rounded p-2 text-white text-center font-bold focus:outline-none focus:border-blue-400 transition w-full" />
                        </div>
                        <div class="flex flex-col gap-2 w-40">
                            <label for="heartbeat-interval" class="text-[12px] text-gray-400 text-left">Agent 心跳间隔（秒）</label>
                            <input type="number" id="heartbeat-interval" value="\${map_data.heartbeat_interval || 30}" min="10" max="3600" step="1" class="bg-gray-800 border border-gray-600 rounded p-2 text-white text-center font-bold focus:outline-none focus:border-blue-400 transition w-full" />
                        </div>
                        <div class="flex flex-col gap-2 w-40">
                            <label for="frontend-poll-interval" class="text-[12px] text-gray-400 text-left">面板轮询间隔（秒）</label>
                            <input type="number" id="frontend-poll-interval" value="\${map_data.frontend_poll_interval || 5}" min="5" max="300" step="1" class="bg-gray-800 border border-gray-600 rounded p-2 text-white text-center font-bold focus:outline-none focus:border-blue-400 transition w-full" />
                        </div>
                        <div class="flex flex-col bg-gray-900 border-l border-gray-700 pl-4 text-center relative group w-48">
                            <div class="flex justify-between items-center px-1 mb-2">
                                <label class="text-[12px] text-gray-400">当前区域策略</label>
                            <button onclick="forceSwitchIP(0, \${port})" title="嫌弃该IP？一键强制拉黑换新" class="text-gray-500 hover:text-red-400 transition">
                                <svg class="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
                                    <path fill-rule="evenodd" d="M4 2a1 1 0 011 1v2.101a7.002 7.002 0 0111.601 2.566 1 1 0 11-1.885.666A5.002 5.002 0 005.999 7H9a1 1 0 010 2H4a1 1 0 01-1-1V3a1 1 0 011-1zm.008 9.057a1 1 0 011.214-.722 5.002 5.002 0 009.777 1.665H11a1 1 0 110-2h5a1 1 0 011 1v5a1 1 0 11-2 0v-2.101a7.002 7.002 0 01-11.601-2.566 1 1 0 01.61-1.277z" clip-rule="evenodd"></path>
                                </svg>
                            </button>
                            </div>
                            <input type="text" id="slot-cfg-0" value="\${val}" class="bg-gray-800 border border-gray-600 rounded p-2 text-white text-center font-bold text-xl uppercase focus:outline-none focus:border-blue-400 transition w-full" />
                        </div>
                    </div>
                \`;
                
                container.innerHTML = html;
                toggleManualMode();
            } catch(e) {}
        }

        function toggleManualMode() {
            const mode = document.getElementById('control-mode');
            const node = document.getElementById('manual-node');
            if (!mode || !node) return;
            node.disabled = mode.value !== 'manual';
            node.classList.toggle('opacity-50', node.disabled);
        }

        function updateManualNodeOptions(servers) {
            const select = document.getElementById('manual-node');
            if (!select) return;
            const selected = select.value;
            const candidates = [];
            (servers || []).forEach(server => {
                (server.candidates || []).forEach(node => {
                    if (!candidates.some(item => item.ip === node.ip)) candidates.push(node);
                });
            });
            candidates.sort((a, b) => (a.ping || 9999) - (b.ping || 9999) || String(a.country || '').localeCompare(String(b.country || '')) || String(a.ip).localeCompare(String(b.ip)));
            select.innerHTML = '<option value="">请选择可用节点</option>' + candidates.map(node =>
                \`<option value="\${node.ip}">\${node.country || '--'} | \${node.ip} | \${node.ping || '?'} ms</option>\`
            ).join('');
            if (candidates.some(node => node.ip === selected)) select.value = selected;
            toggleManualMode();
        }

        async function forceSwitchIP(slot, port) {
            if(!confirm(\`确认要强行断开并刷新【端口 \${port}】当前的节点 IP 吗？\\n(该IP仅会进入 1 分钟临时冷却，不会被从池中删除。)\`)) return;
            try {
                const res = await fetch('/api/switch', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({slot: slot})
                });
                if(res.ok) {
                    pushLog(\`[指令下达] 已向代理层发送端口 \${port} 的手动熔断强杀指令\`, 'WARN');
                    alert(\`⚡ 指令下达成功！\\nVPS 监控引擎已收到杀机指令。\`);
                } else {
                    alert('网络指令下发失败，请重试');
                }
            } catch(e) {
                alert('网络指令下发异常');
            }
        }

        async function saveConfig() {
            const port = Number.parseInt(document.getElementById('proxy-port').value, 10);
            if (!Number.isInteger(port) || port < 1 || port > 65535) {
                alert('代理端口必须是 1 到 65535 之间的整数');
                return;
            }
            const map = {
                0: document.getElementById(\`slot-cfg-0\`).value.toUpperCase().trim() || 'JP'
            };
            const mode = document.getElementById('control-mode').value;
            const manualNodeIp = document.getElementById('manual-node').value;
            const youtubeCheck = document.getElementById('youtube-check').checked;
            const configFetchInterval = Number.parseInt(document.getElementById('config-fetch-interval').value, 10);
            const heartbeatInterval = Number.parseInt(document.getElementById('heartbeat-interval').value, 10);
            const frontendPollInterval = Number.parseInt(document.getElementById('frontend-poll-interval').value, 10);
            if (!Number.isInteger(configFetchInterval) || configFetchInterval < 5 || configFetchInterval > 3600 || !Number.isInteger(heartbeatInterval) || heartbeatInterval < 10 || heartbeatInterval > 3600 || !Number.isInteger(frontendPollInterval) || frontendPollInterval < 5 || frontendPollInterval > 300) {
                alert('间隔设置不合法：配置拉取 5-3600 秒，心跳 10-3600 秒，面板轮询 5-300 秒');
                return;
            }
            if (mode === 'manual' && !manualNodeIp) {
                alert('手动模式必须先选择一个可用节点');
                return;
            }
            const res = await fetch('/api/config', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({slot_map: map, proxy_port: port, mode, manual_node_ip: manualNodeIp, youtube_check: youtubeCheck, config_fetch_interval: configFetchInterval, heartbeat_interval: heartbeatInterval, frontend_poll_interval: frontendPollInterval})
            });
            if (!res.ok) {
                alert('配置保存失败，请检查端口范围后重试');
                return;
            }
            pushLog('[控制中心广播] 国家路由策略已更新至节点。', 'SYS');
            alert(\`配置已下发，代理端口将切换为 \${port}。\`);
            loadConfig();
            restartNodePolling(frontendPollInterval);
        }

        let nodePollingTimer;
        function restartNodePolling(seconds) {
            if (nodePollingTimer) clearInterval(nodePollingTimer);
            nodePollingTimer = setInterval(fetchNodes, seconds * 1000);
        }

        async function fetchNodes() {
            try {
                const res = await fetch('/api/nodes');
                const servers = await res.json();
                const tbody = document.getElementById('nodes-table');
                renderRemoteLogs(servers || []);
                updateManualNodeOptions(servers || []);
                
                if (!servers || servers.length === 0) {
                    tbody.innerHTML = '<tr><td colspan="4" class="py-8 text-center text-gray-500">当前没有被纳管的机器，请在 VPS 运行右上角命令接入</td></tr>';
                    return;
                }

                servers.forEach(s => {
                    if (Math.random() > 0.6) {
                        const dList = JSON.parse(s.details || '[]');
                        const evtRand = Math.random();
                        if (evtRand > 0.8) {
                            pushLog(\`节点 [\${s.ip}] 心跳数据已同步，当前健康存活链路: \${dList.length}/1\`, 'SUCCESS');
                        } else if (evtRand > 0.5 && dList.length < 1) {
                            pushLog(\`节点 [\${s.ip}] 正在从黄金储备池中提取“免死金牌”极品节点...\`, 'INFO');
                        } else if (evtRand > 0.3) {
                            pushLog(\`节点 [\${s.ip}] 路由表重组完成，黄金历史节点已豁免下发。\`, 'SYS');
                        }
                    }
                });

                tbody.innerHTML = servers.map(server => {
                    const details = JSON.parse(server.details || '[]');
                    const timeAgo = Math.floor((Date.now() - server.last_seen) / 1000);
                    
                    details.sort((a,b) => a.port - b.port);

                    let proxyBadges = details.map(d => 
                        \`<div class="inline-flex items-center bg-gray-700 border border-gray-600 rounded px-2 py-1 mr-2 mb-2 text-xs">
                            <span class="text-blue-400 font-bold mr-2">\${d.country}</span>
                            <span class="font-mono text-blue-200 mr-2" title="节点物理IP">\${d.node_ip || '分配中...'}:\${d.port}</span>
                        </div>\`
                    ).join('');

                    if (details.length === 0) proxyBadges = '<span class="text-yellow-500 text-xs">高容错极速调度中... 正在建立单端口稳定网络...</span>';

                    return \`
                        <tr class="hover:bg-gray-750 transition-colors">
                            <td class="py-4 px-4 font-mono text-lg text-blue-300 align-top">\${server.ip}</td>
                            <td class="py-4 px-4 align-top">\${proxyBadges}</td>
                            <td class="py-4 px-4 text-gray-400 align-top">\${timeAgo}s 前</td>
                            <td class="py-4 px-4 align-top text-right">
                                <span class="\${details.length === 1 ? 'bg-green-900 text-green-300' : 'bg-yellow-900 text-yellow-300'} py-1 px-3 rounded-full text-xs font-bold">\${details.length} / 1</span>
                            </td>
                        </tr>
                    \`;
                }).join('');
            } catch (err) {}
        }
        
        fetchCountries();
        loadConfig();
        fetchNodes();
        fetch('/api/config').then(res => res.json()).then(config => restartNodePolling(config.frontend_poll_interval || 5)).catch(() => restartNodePolling(5));
    </script>
</body>
</html>
`;
