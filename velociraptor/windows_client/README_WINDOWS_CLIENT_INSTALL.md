# Cai Velociraptor Client tren may Windows bi giam sat

Bo cai nay danh cho Windows endpoint trong lab hien tai.

## Thong tin ket noi

- Velociraptor Server: `10.10.20.20`
- Client ket noi ve: `https://10.10.20.20:8000/`
- GUI de xem client: `https://10.10.20.20:8889/app/index.html`
- Service tren Windows: `Velociraptor`
- Thu muc cai mac dinh: `C:\Program Files\Velociraptor\`

## File trong bo cai

- `Velociraptor-Windows-Client-10.10.20.20.msi`: MSI da nhung client config, nen dung file nay.
- `Velociraptor-Windows-Client-10.10.20.20.exe`: EXE da nhung client config, dung khi khong cai MSI.
- `client.config.yaml`: client config du phong.
- `install_velociraptor_client_windows.ps1`: script cai dat tren Windows.
- `install_velociraptor_client_windows.cmd`: wrapper de chay script PowerShell nhanh hon.
- `checksums.sha256`: hash de kiem tra file sau khi copy.

## Cach cai nhanh tren Windows endpoint

Copy ca thu muc `windows_client` sang may Windows can giam sat.

Mo PowerShell bang quyen Administrator, cd vao thu muc vua copy:

```powershell
cd C:\Path\To\windows_client
Set-ExecutionPolicy -Scope Process Bypass -Force
.\install_velociraptor_client_windows.ps1
```

Hoac right-click `install_velociraptor_client_windows.cmd` va chon `Run as administrator`.

Script se:

- Kiem tra co dang chay bang Administrator khong.
- Thu ket noi TCP toi `10.10.20.20:8000`.
- Uu tien cai bang MSI da nhung config.
- Kiem tra service `Velociraptor` sau khi cai.

Neu muon bat buoc endpoint phai ket noi duoc server truoc khi cai:

```powershell
.\install_velociraptor_client_windows.ps1 -RequireNetwork
```

Neu muon cai bang EXE thay vi MSI:

```powershell
.\install_velociraptor_client_windows.ps1 -UseExeInstaller
```

Neu may da co service cu va muon cai lai:

```powershell
.\install_velociraptor_client_windows.ps1 -ForceReinstall
```

## Cai thu cong bang MSI

PowerShell Administrator:

```powershell
msiexec.exe /i .\Velociraptor-Windows-Client-10.10.20.20.msi /qn /norestart
sc.exe query Velociraptor
```

## Cai thu cong bang EXE va config

PowerShell Administrator:

```powershell
.\Velociraptor-Windows-Client-10.10.20.20.exe service install --config .\client.config.yaml -v
sc.exe query Velociraptor
```

## Kiem tra sau khi cai

Tren Windows endpoint:

```powershell
Get-Service Velociraptor
sc.exe query Velociraptor
Test-NetConnection 10.10.20.20 -Port 8000
Get-ChildItem 'C:\Program Files\Velociraptor'
```

Tren Velociraptor GUI:

1. Mo `https://10.10.20.20:8889/app/index.html`.
2. Dang nhap bang user admin cua server.
3. Vao thanh Search clients va tim hostname Windows vua cai.

## Go cai dat trong lab

Neu cai bang MSI, co the go bang Apps & Features hoac:

```powershell
msiexec.exe /x .\Velociraptor-Windows-Client-10.10.20.20.msi /qn /norestart
```

Neu cai bang EXE service installer:

```powershell
.\Velociraptor-Windows-Client-10.10.20.20.exe service stop
.\Velociraptor-Windows-Client-10.10.20.20.exe service remove
```

## Troubleshooting nhanh

Neu service chay nhung client khong hien online:

- Kiem tra Windows co route toi `10.10.20.20` khong.
- Kiem tra firewall giua Windows endpoint va server co cho TCP `8000` khong.
- Kiem tra gio he thong Windows va Ubuntu khong lech qua xa.
- Kiem tra config co server URL dung:

```powershell
Get-Content 'C:\Program Files\Velociraptor\client.config.yaml' | Select-String 'server_urls|pinned_server_name'
```

## Nguon tham khao

- Velociraptor Deploying Clients: https://docs.velociraptor.app/docs/deployment/clients/
- Velociraptor service command: https://docs.velociraptor.app/docs/cli/service/
- Velociraptor Downloads: https://docs.velociraptor.app/downloads/
