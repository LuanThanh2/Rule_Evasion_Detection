# Velociraptor Server install notes

Ngay cai: 2026-05-17
May: Ubuntu 24.04, amd64
Velociraptor: 0.76.1

## Thong tin da cau hinh

- Server IP chinh cho lab: `10.10.20.20`
- IP phu/NAT VMware: `192.168.254.145`
- Frontend/client URL: `https://10.10.20.20:8000/`
- GUI URL: `https://10.10.20.20:8889/app/index.html`
- GUI allowed CIDR: `127.0.0.1/32`, `10.10.20.0/24`, `192.168.254.0/24`
- GUI user da tao: `admin`
- GUI password lab: `tzxr`

Luu y: GUI dung HTTPS self-signed, trinh duyet se bao certificate warning.
Voi moi truong that, doi password va dung TLS/certificate chuan.

## File quan trong

- Binary goc: `/home/luanthanh/velociraptor/velociraptor`
- Merge config: `/home/luanthanh/velociraptor/server.config.merge.json`
- Server config sinh ra: `/home/luanthanh/velociraptor/server.config.yaml`
- Server config dang chay: `/etc/velociraptor/server.config.yaml`
- Client config: `/home/luanthanh/velociraptor/client.config.yaml`
- Server package: `/home/luanthanh/velociraptor/velociraptor-server-0.76.1.amd64.deb`
- Client package: `/home/luanthanh/velociraptor/velociraptor_client_0.76.1_amd64.deb`
- Datastore: `/var/lib/velociraptor`
- Log: `/var/log/velociraptor`
- Systemd service: `velociraptor_server.service`

## Chuc nang tung file

- `/home/luanthanh/velociraptor/velociraptor`
  - Day la binary Velociraptor chay truc tiep.
  - Neu tai file ten `velociraptor-v0.76.1-linux-amd64`, chi can doi ten thanh `velociraptor` cho ngan.
  - Dung de tao config, tao goi `.deb`, test version, chay query/API command.

- `/home/luanthanh/velociraptor/server.config.merge.json`
  - Day la file nen sua khi muon doi IP server, subnet duoc phep vao GUI, duong dan datastore/log.
  - File nay khong phai config day du; no la file override de sinh ra `server.config.yaml`.
  - Neu cai tren may server khac, sua cac truong quan trong:
    - `Client.server_urls`: URL client se ket noi ve server, vi du `https://10.10.20.20:8000/`.
    - `Frontend.hostname`: IP/hostname server Velociraptor.
    - `GUI.public_url`: URL mo giao dien web.
    - `GUI.allowed_cidr`: subnet/IP duoc phep truy cap GUI.

- `/home/luanthanh/velociraptor/server.config.yaml`
  - Day la server config day du duoc sinh ra tu `server.config.merge.json`.
  - File nay co certificate/private key cua server nen can giu quyen `600`.
  - Dung de tao package server `.deb` va tao config/package client.
  - Sau khi cai `.deb`, ban dang chay config tai `/etc/velociraptor/server.config.yaml`, khong phai file local nay.

- `/etc/velociraptor/server.config.yaml`
  - Day la server config that dang duoc systemd service su dung.
  - Service hien chay lenh:
    `/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml frontend`
  - Neu sua config local trong thu muc project, can tao lai package/copy lai config vao `/etc/velociraptor/` roi restart service.

- `/home/luanthanh/velociraptor/client.config.yaml`
  - Day la config cho may client/endpoint.
  - Client can file nay de biet server nam o dau va tin CA nao.
  - Truong quan trong nhat la `Client.server_urls`.
  - File nay khong phai config de chay server.

- `/home/luanthanh/velociraptor/api.config.yaml`
  - Day la config de tool/API client ket noi vao Velociraptor API.
  - Dung cho AI Agent hoac script tu dong hoa khi can query, tao hunt, lay ket qua.
  - Hien tai dang tro ve API local: `127.0.0.1:8001`.
  - File nay co API client private key, nen can bao ve nhu secret.
  - Neu AI Agent chay tren may khac, phai mo API bind tren server va doi `api_connection_string`, nhung chi nen lam trong mang tin cay.

- `/home/luanthanh/velociraptor/velociraptor-server-0.76.1.amd64.deb`
  - Goi cai dat server cho Ubuntu/Debian.
  - Khi cai, no dat binary vao `/usr/local/bin/velociraptor`, config vao `/etc/velociraptor/server.config.yaml`, va tao systemd service.

- `/home/luanthanh/velociraptor/velociraptor_client_0.76.1_amd64.deb`
  - Goi cai dat client Linux.
  - Copy file nay sang may client roi cai bang `dpkg -i`.
  - Goi client da nhung san config de tu ket noi ve server.

- `/home/luanthanh/velociraptor/windows_client`
  - Thu muc chua goi cai client cho Windows va script cai dat.
  - Copy ca thu muc sang Windows endpoint va chay PowerShell bang quyen Administrator.

- `/var/lib/velociraptor`
  - Datastore cua Velociraptor server.
  - Noi luu metadata, flow, hunt, ket qua thu thap.

- `/var/log/velociraptor`
  - Thu muc log cua Velociraptor server.

## Y nghia cac port

- `8000`: Frontend cho client ket noi ve server.
- `8889`: GUI web de quan tri Velociraptor.
- `8001`: API server, dung cho CLI/API/AI Agent. Hien tai chi bind local `127.0.0.1`.
- `8003`: Monitoring/debug metrics local.

## Khi tach 2 may server/client

- Tren may server:
  - Sua IP/subnet trong `server.config.merge.json`.
  - Sinh lai `server.config.yaml`.
  - Tao lai `velociraptor-server-*.deb`.
  - Cai package server bang `dpkg -i`.

- Tren may client:
  - Khong can sua IP client vao config.
  - Client chi can ket noi duoc toi `https://<IP_SERVER>:8000/`.
  - Tao lai/copy dung `velociraptor_client_*.deb` tu server sang client roi cai.

- Neu AI Agent chay cung may server:
  - Giu `api.config.yaml` voi `api_connection_string: 127.0.0.1:8001`.

- Neu AI Agent chay may khac:
  - Can sua API bind trong server config, mo firewall port `8001`, va doi `api.config.yaml`.
  - Chi nen mo API trong lab/subnet tin cay vi API co quyen manh.

## Cach cai server tu dau

```bash
mkdir -p ~/velociraptor
cd ~/velociraptor

# Neu vua tai binary ten velociraptor-v0.76.1-linux-amd64:
mv velociraptor-v0.76.1-linux-amd64 velociraptor
chmod +x velociraptor
./velociraptor version
```

Giai thich:

- `mkdir -p ~/velociraptor`: tao thu muc lam viec cho Velociraptor.
- `cd ~/velociraptor`: chuyen vao thu muc do.
- `mv velociraptor-v0.76.1-linux-amd64 velociraptor`: doi ten binary tai ve thanh `velociraptor`.
- `chmod +x velociraptor`: cap quyen executable de Linux cho phep chay file.
- `./velociraptor version`: kiem tra binary co chay duoc va dung version khong.

Tao file `server.config.merge.json`:

```json
{
  "Client": {
    "server_urls": [
      "https://10.10.20.20:8000/"
    ],
    "pinned_server_name": "VelociraptorServer"
  },
  "GUI": {
    "bind_address": "0.0.0.0",
    "allowed_cidr": [
      "127.0.0.1/32",
      "10.10.20.0/24",
      "192.168.254.0/24"
    ],
    "public_url": "https://10.10.20.20:8889/app/index.html"
  },
  "Frontend": {
    "hostname": "10.10.20.20",
    "bind_address": "0.0.0.0",
    "bind_port": 8000
  },
  "Datastore": {
    "implementation": "FileBaseDataStore",
    "location": "/var/lib/velociraptor",
    "filestore_directory": "/var/lib/velociraptor",
    "compression": "zlib"
  },
  "Logging": {
    "output_directory": "/var/log/velociraptor",
    "separate_logs_per_component": true
  },
  "Monitoring": {
    "bind_address": "127.0.0.1",
    "bind_port": 8003
  }
}
```

Giai thich cac block trong `server.config.merge.json`:

- `Client.server_urls`: dia chi ma cac client/endpoint se goi ve server.
- `Client.pinned_server_name`: ten server duoc pin trong cert de client xac thuc dung server.
- `GUI.bind_address`: dia chi GUI lang nghe. `0.0.0.0` nghia la lang nghe tren moi card mang.
- `GUI.allowed_cidr`: danh sach IP/subnet duoc phep vao GUI.
- `GUI.public_url`: URL dung de mo giao dien web tren trinh duyet.
- `Frontend.hostname`: IP/hostname server ma client se thay.
- `Frontend.bind_address`: dia chi frontend lang nghe. `0.0.0.0` cho phep client tu may khac ket noi.
- `Frontend.bind_port`: port frontend cho client, hien la `8000`.
- `Datastore.location`: noi luu du lieu server.
- `Logging.output_directory`: noi luu log.
- `Monitoring.bind_address`: monitoring chi mo local de an toan.

Sinh config va package server:

```bash
./velociraptor config generate --merge_file server.config.merge.json > server.config.yaml
chmod 600 server.config.yaml
./velociraptor --config server.config.yaml debian server --output . --binary ./velociraptor
```

Giai thich:

- `./velociraptor config generate --merge_file server.config.merge.json > server.config.yaml`
  - Sinh config server day du tu merge file.
  - Dau `>` ghi output vao file `server.config.yaml`.
- `chmod 600 server.config.yaml`
  - Chi user owner duoc doc/ghi file.
  - Can thiet vi file nay co private key/certificate.
- `./velociraptor --config server.config.yaml debian server --output . --binary ./velociraptor`
  - Dung config vua sinh de tao goi cai server `.deb`.
  - `--output .` ghi package ra thu muc hien tai.
  - `--binary ./velociraptor` chi ro binary nao se duoc nhung vao package.

Cai package:

```bash
sudo dpkg -i velociraptor-server-0.76.1.amd64.deb
sudo install -d -o velociraptor -g velociraptor -m 0750 /var/log/velociraptor
sudo systemctl restart velociraptor_server
sudo systemctl enable velociraptor_server
```

Giai thich:

- `sudo dpkg -i velociraptor-server-0.76.1.amd64.deb`
  - Cai Velociraptor server vao he thong.
  - Tao `/usr/local/bin/velociraptor`, `/etc/velociraptor/server.config.yaml`, va service systemd.
- `sudo install -d -o velociraptor -g velociraptor -m 0750 /var/log/velociraptor`
  - Tao thu muc log va gan owner/group cho user `velociraptor`.
  - `0750` nghia la owner toan quyen, group co quyen doc/chay, user khac khong co quyen.
- `sudo systemctl restart velociraptor_server`
  - Khoi dong lai service de nap config moi.
- `sudo systemctl enable velociraptor_server`
  - Cho service tu dong chay khi may boot.

Tao user GUI:

```bash
sudo -u velociraptor /usr/local/bin/velociraptor \
  --config /etc/velociraptor/server.config.yaml \
  user add --role administrator admin

sudo systemctl restart velociraptor_server
```

Giai thich:

- `sudo -u velociraptor`
  - Chay command bang user service `velociraptor`, dung quyen voi datastore/config.
- `/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml`
  - Goi binary da cai trong he thong va dung config server dang chay.
- `user add --role administrator admin`
  - Tao/cap nhat user GUI ten `admin` voi role administrator.
- `sudo systemctl restart velociraptor_server`
  - Restart server sau khi tao/cap nhat user.

## Lenh van hanh nhanh

```bash
systemctl status velociraptor_server --no-pager
journalctl -u velociraptor_server -n 100 --no-pager
ss -ltnp | grep -E ':(8000|8001|8003|8889)\b'
curl -k -I https://127.0.0.1:8889/app/index.html
```

Giai thich:

- `systemctl status velociraptor_server --no-pager`
  - Xem service server dang `active/running` hay bi loi.
- `journalctl -u velociraptor_server -n 100 --no-pager`
  - Xem 100 dong log gan nhat cua service.
- `ss -ltnp | grep -E ':(8000|8001|8003|8889)\b'`
  - Kiem tra cac port Velociraptor co dang listen khong.
- `curl -k -I https://127.0.0.1:8889/app/index.html`
  - Test GUI HTTPS co tra response khong.
  - `-k` bo qua canh bao self-signed certificate.
  - `-I` chi lay header, khong tai toan bo trang.

## Cai client Ubuntu trong lab

Copy file client package sang may client roi chay:

```bash
sudo dpkg -i velociraptor_client_0.76.1_amd64.deb
sudo systemctl status velociraptor_client --no-pager
```

Giai thich:

- `sudo dpkg -i velociraptor_client_0.76.1_amd64.deb`
  - Cai Velociraptor client tren may endpoint Ubuntu/Debian.
  - Goi nay da co config de client ket noi ve server.
- `sudo systemctl status velociraptor_client --no-pager`
  - Kiem tra client service co dang chay khong.

Neu chi can client config:

```bash
cat client.config.yaml
```

Giai thich:

- `cat client.config.yaml`
  - In noi dung client config ra terminal.
  - Dung khi can kiem tra `server_urls`, certificate, hoac tao package thu cong.

## Cai client Windows trong lab

Bo cai Windows da nam trong:

```bash
/home/luanthanh/velociraptor/windows_client
```

File nen dung tren Windows endpoint:

```text
Velociraptor-Windows-Client-10.10.20.20.msi
```

Copy ca thu muc `windows_client` sang may Windows bi giam sat, mo PowerShell bang quyen Administrator roi chay:

```powershell
cd C:\Path\To\windows_client
Set-ExecutionPolicy -Scope Process Bypass -Force
.\install_velociraptor_client_windows.ps1
```

Giai thich:

- `cd C:\Path\To\windows_client`
  - Chuyen vao thu muc chua file cai Windows client.
- `Set-ExecutionPolicy -Scope Process Bypass -Force`
  - Tam thoi cho phep chay script PowerShell trong phien hien tai.
  - Khong doi policy vinh vien cua may.
- `.\install_velociraptor_client_windows.ps1`
  - Chay script cai dat Velociraptor Windows client.

Huong dan chi tiet nam trong:

```text
windows_client\README_WINDOWS_CLIENT_INSTALL.md
```

## Doi password GUI

```bash
sudo -u velociraptor /usr/local/bin/velociraptor \
  --config /etc/velociraptor/server.config.yaml \
  user add --role administrator admin

sudo systemctl restart velociraptor_server
```

Giai thich:

- Lenh `user add --role administrator admin` co the dung de tao user moi hoac cap nhat password user `admin`.
- Khi command hoi password, nhap password moi.
- Restart service de dam bao thay doi duoc nap sach se.

Nhap password moi khi command hoi.
