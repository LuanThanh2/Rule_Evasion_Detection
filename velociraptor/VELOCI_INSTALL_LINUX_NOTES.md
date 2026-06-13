# Velociraptor Linux Client install notes (WebServer DMZ)

Ngay cai: 2026-06-12
Server: SERVER-ELK, Ubuntu 22.04.5, amd64
Client: WebServer, Ubuntu 22.04.5, amd64
Velociraptor: 0.76.1

Tham khao file goc: `VELOCI_INSTALL_NOTES.md` (cach cai server tu dau, giai thich tung file/port).
File nay ghi lai qua trinh cai **client Linux tren WebServer** ket noi ve **server tren SERVER-ELK**,
bao gom cac loi gap phai va cach xu ly firewall 2 lop (ufw + pfSense).

## Topology lab

```
[May Ubuntu ca nhan] --wt0 overlay--> SERVER-ELK (100.75.12.114)
                                          |
                              LAN 192.168.10.0/24 (pfSense LAN, gw .1)
                                          |
SERVER-ELK = 192.168.10.10  <---pfSense--->  DMZ 192.168.50.0/24 (opt1, gw .1)
                                          |
                                    WebServer = 192.168.50.100
```

- SSH vao SERVER-ELK: `sshpass -p '123' ssh -o StrictHostKeyChecking=no ubuntu@100.75.12.114`
- SSH vao WebServer: **phai jump qua SERVER-ELK** (may ngoai khong vao truc tiep duoc):
  `sshpass -p '123' ssh -o StrictHostKeyChecking=no ubuntu@192.168.50.100` (chay tu SERVER-ELK; sshpass da duoc cai tren SERVER-ELK)
- pfSense: console qua Proxmox; GUI `https://192.168.10.1` (LAN) / `https://192.168.50.1` (DMZ)
- pfSense mac dinh **block DMZ -> LAN**, chi pass san 9200 (Elasticsearch) va 8220 (Fleet)

## Thong tin da cau hinh

- Velociraptor server: da chay san tren SERVER-ELK (khong cai lai)
  - Frontend/client URL: `https://192.168.10.10:8000/`
  - GUI: `https://192.168.10.10:8889/app/index.html`
  - API: `127.0.0.1:8001` (local only)
  - Service: `velociraptor_server.service`, config `/etc/velociraptor/server.config.yaml`
  - Luu y: password GUI may nay KHONG phai `tzxr` (do la lab cu 10.10.20.20). Quen thi reset:
    `sudo -u velociraptor /usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml user add --role administrator admin`
- Client WebServer:
  - **client_id: `C.348bd65bf6fd3224`** (luu trong `/etc/velociraptor.writeback.yaml` tren WebServer)
  - Service: `velociraptor_client.service`, config `/etc/velociraptor/client.config.yaml`
- Goi client dung (da copy vao project, dat ten theo quy uoc windows_client):
  `~/rule_evasion_detection/Rule_Evasion_Detection/velociraptor/linux_client/Velociraptor-Linux-Client-192.168.10.10.deb`
  (ban goc build tai `~/velociraptor_deploy/` tren SERVER-ELK; huong dan cai nhanh: `linux_client/README_LINUX_CLIENT_INSTALL.md`)
- Goi client CU `velociraptor_client_0.76.1_amd64.deb` o folder goc va trong
  `~/rule_evasion_detection/velociraptor/` **KHONG dung duoc** — nhung IP cu 10.10.20.20 (xem Loi #1)

## Vi tri file config tren tung may (QUAN TRONG — hay nham)

`client.config.yaml` xuat hien tren CA 2 may nhung VAI TRO khac nhau:

### Tren SERVER-ELK (192.168.10.10) — server KHONG chay client.config.yaml

| Duong dan | Vai tro |
|---|---|
| `/etc/velociraptor/server.config.yaml` | **Server service that su chay file NAY** (owner `velociraptor`, perm 600). ExecStart: `velociraptor --config /etc/velociraptor/server.config.yaml frontend` |
| `~/rule_evasion_detection/Rule_Evasion_Detection/velociraptor/server.config.yaml` | Ban server config trong project (de build goi `.deb`, sinh client config) |
| `~/rule_evasion_detection/Rule_Evasion_Detection/velociraptor/linux_client/client.config.yaml` | Ban client config MOI (IP 192.168.10.10) — chi de tham khao / cai thu cong, KHONG phai server chay |
| `~/rule_evasion_detection/Rule_Evasion_Detection/velociraptor/client.config.yaml` | Ban client config CU (IP 10.10.20.20) — bo, dung dung |
| `~/velociraptor_deploy/client.config.yaml` | Ban goc sinh ra luc build goi deb moi |

=> Tren server, `client.config.yaml` chi la "khuon" de build goi `.deb`. Sinh xong la het nhiem vu.
Server KHONG bao gio doc file client de chay.

### Tren WebServer (192.168.50.100) — client chay file that

| Duong dan | Vai tro |
|---|---|
| `/etc/velociraptor/client.config.yaml` | **Client service that su chay file NAY** (owner root, perm 600). ExecStart: `velociraptor_client --config /etc/velociraptor/client.config.yaml client --quiet` |
| `/etc/velociraptor.writeback.yaml` | Luu `client_id: C.348bd65bf6fd3224` (sinh ra luc enroll lan dau) |
| `/tmp/velociraptor_client_0.76.1_amd64.deb` | Goi deb da copy sang de cai (o /tmp, reboot co the mat — khong sao vi da cai) |

=> Khi `dpkg -i` goi `.deb`, no TU copy config nhung san vao `/etc/velociraptor/client.config.yaml`.
**Khong can copy tay** `client.config.yaml` sang client — goi deb da chua san ben trong.
File `client.config.yaml` roi trong `linux_client/` chi can khi cai thu cong (chay binary truc tiep, khong qua deb).

## Cac loi gap phai va cach xu ly

### Loi #1 — Goi client deb cu nhung sai IP server

Goi `velociraptor_client_0.76.1_amd64.deb` co san trong `~/rule_evasion_detection/velociraptor/`
duoc build tu lab cu, nhung `server_urls = https://10.10.20.20:8000/` va CA cert cu
=> client se khong bao gio ket noi duoc ve server moi.

Cach kiem tra goi deb nhung IP nao truoc khi cai:

```bash
dpkg-deb -x velociraptor_client_0.76.1_amd64.deb /tmp/vrcli_check
grep -A3 "server_urls" /tmp/vrcli_check/etc/velociraptor/client.config.yaml
rm -rf /tmp/vrcli_check
```

Cach fix: **build lai goi client tu config server DANG CHAY** (de CA cert + server_urls khop 100%):

```bash
# Tren SERVER-ELK
mkdir -p ~/velociraptor_deploy && cd ~/velociraptor_deploy

# Sinh client config tu server config dang chay (can sudo vi file 600)
sudo /usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml \
  config client > client.config.yaml

# Build goi deb, nhung binary he thong vao
/usr/local/bin/velociraptor --config client.config.yaml \
  debian client --output . --binary /usr/local/bin/velociraptor
```

Giai thich:

- `config client`: trich phan client (server_urls, CA cert, nonce) tu server config day du.
- `debian client --binary /usr/local/bin/velociraptor`: tao goi `.deb` client, dung luon binary da cai tren server (cung version 0.76.1, cung arch amd64).
- Quy tac: **moi khi server doi IP/cert, phai build lai goi client**. Khong tai dung goi cu.

### Loi #2 — ufw tren SERVER-ELK chi mo port 8000 cho subnet LAN

ufw co rule `8000/tcp ALLOW IN 192.168.10.0/24`, WebServer nam o `192.168.50.0/24` nen bi chan.

Fix:

```bash
sudo ufw allow from 192.168.50.0/24 to any port 8000 proto tcp \
  comment "Velociraptor frontend - WebServer subnet"
```

### Loi #3 — pfSense block DMZ -> LAN (loi chinh, kho thay nhat)

Sau khi mo ufw van bi chan. Chan doan bang tcpdump tren SERVER-ELK:

```bash
# Terminal 1 (SERVER-ELK): nghe goi tin tu WebServer toi port 8000
sudo tcpdump -ni ens18 'tcp port 8000 and src host 192.168.50.100'

# Terminal 2 (WebServer): thu ket noi
timeout 3 bash -c '</dev/tcp/192.168.10.10/8000' && echo "KET NOI OK" || echo "BI CHAN"
```

Ket qua: tcpdump **im lang** => goi SYN chet o pfSense, chua bao gio den SERVER-ELK.
(Neu tcpdump thay SYN ma van khong connect duoc thi van de moi nam o ufw/service.)

Do them: pfSense chi cho DMZ -> LAN qua port 9200 va 8220; moi port khac (22, 8000, 8889,
5601, ICMP...) deu bi block boi rule "Block DMZ to LAN".

Fix tren pfSense GUI: **Firewall -> Rules -> tab DMZ** -> Add (mui ten len, rule nam TREN rule block):

- Action: Pass, Protocol: TCP
- Source: Single host -> `192.168.50.100`
- Destination: Single host -> `192.168.10.10`, port `8000`
- Description: `Velociraptor client to server`
- Save -> **APPLY CHANGES** (nut xanh dau trang — quen buoc nay rule KHONG co hieu luc, day chinh la loi da gap; cot States cua rule se la `0/0 B`)

Fix nhanh hon bang console pfSense (menu -> `8` Shell), khoi can GUI:

```bash
easyrule pass opt1 tcp 192.168.50.100 192.168.10.10 8000
pfctl -sr | grep 8000   # kiem tra rule da nap vao ruleset dang chay chua
```

Giai thich:

- `opt1` = interface DMZ (WebServer). pfSense loc tren interface ma goi tin DI VAO.
- `easyrule` tu them rule + apply ngay, khong can Apply Changes thu cong.
- `pfctl -sr` in ruleset dang chay that su — khac voi config da save nhung chua apply.
- Xem goi bi block real-time: `tcpdump -nei pflog0 port 8000`

## Cai client tren WebServer

```bash
# Tu SERVER-ELK copy goi deb sang WebServer
sshpass -p '123' scp -o StrictHostKeyChecking=no \
  ~/velociraptor_deploy/velociraptor_client_0.76.1_amd64.deb ubuntu@192.168.50.100:/tmp/

# Tren WebServer
sudo dpkg -i /tmp/velociraptor_client_0.76.1_amd64.deb
sudo systemctl restart velociraptor_client
systemctl is-active velociraptor_client
```

Goi deb tu tao service `velociraptor_client.service` va enable san (symlink multi-user.target).

## Verify client da enroll

```bash
# 1. Tren WebServer — port 8000 phai thong truoc da:
timeout 3 bash -c '</dev/tcp/192.168.10.10/8000' && echo OK || echo BLOCKED

# 2. Tren WebServer — lay client_id:
sudo grep client_id /etc/velociraptor.writeback.yaml
# -> client_id: C.348bd65bf6fd3224

# 3. Tren SERVER-ELK — client_id phai xuat hien trong datastore:
sudo ls /var/lib/velociraptor/clients/
# -> C.348bd65bf6fd3224 (WebServer), C.cd6bfbb23aee7979 (Windows IQAM883)

# 4. Tren SERVER-ELK — heartbeat dang cap nhat (timestamp moi, ~10s/lan):
sudo tail -2 /var/lib/velociraptor/clients/C.348bd65bf6fd3224/monitoring/Generic.Client.Stats/$(date +%Y-%m-%d).json
```

Khi enroll thanh cong, server tu chay flow Interrogation dau tien (thu muc `collections/F.*`).

## Checklist khi them 1 client Linux moi vao lab nay

1. Build goi client tu `/etc/velociraptor/server.config.yaml` dang chay (Loi #1) — hoac tai dung
   `~/velociraptor_deploy/velociraptor_client_0.76.1_amd64.deb` neu server chua doi IP/cert.
2. Neu client nam subnet moi: mo ufw port 8000 tren SERVER-ELK cho subnet do (Loi #2).
3. Neu client nam sau pfSense (DMZ/subnet khac LAN): them rule pass tcp -> `192.168.10.10:8000`
   tren tab interface tuong ung, nho **Apply Changes** (Loi #3).
4. scp goi deb sang client, `dpkg -i`, restart service.
5. Verify theo 4 buoc o tren.
6. Neu dung AI Agent: them client_id moi vao `agent/vr_client_map.yaml`.

## Lenh van hanh nhanh

```bash
# Tren SERVER-ELK
systemctl status velociraptor_server --no-pager
ss -ltnp | grep -E ':(8000|8001|8003|8889)\b'
sudo ufw status | grep 8000

# Tren WebServer
systemctl status velociraptor_client --no-pager
sudo journalctl -u velociraptor_client -n 50 --no-pager
sudo grep client_id /etc/velociraptor.writeback.yaml
```
