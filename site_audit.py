import html.parser
import ipaddress
import os
import queue
import socket
import ssl
import threading
import urllib.error
import urllib.parse
import urllib.request
import tkinter as tk
from tkinter import messagebox, filedialog
from datetime import datetime, timezone
from zipfile import ZipFile, ZIP_DEFLATED
from xml.sax.saxutils import escape

BG = "#f4f6f8"
CARD = "#ffffff"
INK = "#17212b"
MUTED = "#718096"
ACCENT = "#2563eb"
GREEN = "#16835d"
AMBER = "#a56808"
RED = "#bb3d42"
USER_AGENT = "SiteScope/1.1 (authorized passive security review)"


class PageInspector(html.parser.HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms, self.links, self.http_resources = [], 0, []
        self.title, self.description = "", ""
        self._in_title, self._title_parts = False, []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "title":
            self._in_title = True
        if tag == "meta" and attrs.get("name", "").lower() == "description":
            self.description = attrs.get("content", "").strip()
        if tag == "form":
            self.forms.append({"action": attrs.get("action", ""), "method": attrs.get("method", "get").lower(), "inputs": []})
        if tag == "input" and self.forms:
            self.forms[-1]["inputs"].append({"type": attrs.get("type", "text").lower(), "name": attrs.get("name", "")})
        if tag == "a" and attrs.get("href"):
            self.links += 1
        resource = attrs.get("src") or (attrs.get("href") if tag in ("link", "script", "img", "iframe") else None)
        if resource and resource.lower().startswith("http://"):
            self.http_resources.append(resource)

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self._title_parts.append(data.strip())

    def finish(self):
        self.title = " ".join(x for x in self._title_parts if x)


class AuditApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SiteScope — анализ сайта")
        self.root.geometry("1000x790")
        self.root.minsize(760, 600)
        self.root.configure(bg=BG)
        self.events = queue.Queue()
        self.last_result = None
        self._build()
        self.root.after(100, self._poll)

    def _build(self):
        outer = tk.Frame(self.root, bg=BG)
        outer.pack(fill="both", expand=True, padx=34, pady=26)
        top = tk.Frame(outer, bg=BG); top.pack(fill="x")
        tk.Label(top, text="◉", font=("Segoe UI", 23), fg=ACCENT, bg=BG).pack(side="left", padx=(0, 10))
        title_box = tk.Frame(top, bg=BG); title_box.pack(side="left")
        tk.Label(title_box, text="SiteScope", font=("Segoe UI", 21, "bold"), fg=INK, bg=BG).pack(anchor="w")
        tk.Label(title_box, text="Локальный анализ безопасности сайта", font=("Segoe UI", 10), fg=MUTED, bg=BG).pack(anchor="w")
        tk.Label(top, text="ТОЛЬКО С РАЗРЕШЕНИЯ", font=("Segoe UI", 8, "bold"), fg=GREEN, bg="#e6f4ee", padx=10, pady=7).pack(side="right", pady=5)
        intro = tk.Frame(outer, bg=BG); intro.pack(fill="x", pady=(27, 12))
        tk.Label(intro, text="Проверьте конфигурацию сайта", font=("Segoe UI", 18, "bold"), fg=INK, bg=BG).pack(anchor="w")
        tk.Label(intro, text="TLS, заголовки, cookies, формы, DNS и известные публичные файлы — без эксплуатации уязвимостей.", font=("Segoe UI", 10), fg=MUTED, bg=BG).pack(anchor="w", pady=(4, 0))
        row = tk.Frame(outer, bg=BG); row.pack(fill="x", pady=(8, 14))
        self.url_entry = tk.Entry(row, font=("Segoe UI", 12), relief="flat", bd=0, bg=CARD, fg=INK, insertbackground=INK)
        self.url_entry.pack(side="left", fill="x", expand=True, ipady=13, padx=(0, 10)); self.url_entry.insert(0, "https://example.com")
        self.root.bind_all("<Control-KeyPress-v>", self._paste_url, add="+")
        self.root.bind_all("<Control-KeyPress-V>", self._paste_url, add="+")
        self.root.bind_all("<Shift-KeyPress-Insert>", self._paste_url, add="+")
        self.url_entry.bind("<<Paste>>", self._paste_url)
        self.url_entry.bind("<Button-3>", self._show_paste_menu)
        self.paste_menu = tk.Menu(self.root, tearoff=0)
        self.paste_menu.add_command(label="Вставить", command=lambda: self._paste_url())
        self.paste_menu.add_command(label="Копировать", command=lambda: self.url_entry.event_generate("<<Copy>>"))
        self.paste_menu.add_command(label="Вырезать", command=lambda: self.url_entry.event_generate("<<Cut>>"))
        self.paste_menu.add_command(label="Выделить всё", command=lambda: self.url_entry.select_range(0, "end"))
        self.scan_button = tk.Button(row, text="  Анализировать  →  ", command=self.start_scan, font=("Segoe UI", 10, "bold"), bg=ACCENT, fg="white", activebackground="#1d4ed8", activeforeground="white", relief="flat", bd=0, cursor="hand2", padx=9, pady=12)
        self.scan_button.pack(side="left", padx=(0, 8))
        self.doc_button = tk.Button(row, text="  Создать отчёт  ↓  ", command=self.create_report, font=("Segoe UI", 10, "bold"), bg=INK, fg="white", activebackground="#293845", activeforeground="white", relief="flat", bd=0, cursor="hand2", padx=9, pady=12, state="disabled")
        self.doc_button.pack(side="right")
        tk.Label(outer, text="Запускайте проверку только для сайтов, которыми владеете или на анализ которых у вас есть разрешение. Сканирование файлов ограничено безопасными GET-запросами; инъекции и эксплойты не выполняются.", font=("Segoe UI", 9), fg=MUTED, bg=BG, wraplength=920, justify="left").pack(anchor="w", pady=(0, 14))
        self.status = tk.Label(outer, text="Готов к проверке", font=("Segoe UI", 9), fg=MUTED, bg=BG, anchor="w"); self.status.pack(fill="x", pady=(0, 8))
        self.report = tk.Text(outer, font=("Consolas", 10), bg=CARD, fg=INK, relief="flat", bd=0, padx=20, pady=18, wrap="word", state="disabled", spacing1=2, spacing3=4)
        self.report.pack(fill="both", expand=True)
        for name, color in (("heading", INK), ("good", GREEN), ("warn", AMBER), ("bad", RED), ("muted", MUTED)):
            self.report.tag_configure(name, foreground=color, font=("Segoe UI", 13, "bold") if name == "heading" else ("Consolas", 10), spacing1=9 if name == "heading" else 2, spacing3=5 if name == "heading" else 4)
        self._set_report("Введите адрес сайта и нажмите «Анализировать».\n\nВ дополнение к базовым настройкам проверяются robots.txt, sitemap.xml, security.txt и ограниченный список известных конфигурационных путей. Чувствительное содержимое не сохраняется и не включается в отчёт.")

    def _paste_url(self, _event=None):
        focused = self.root.focus_get()
        if focused is not self.url_entry:
            return None
        try:
            clipboard = self.root.clipboard_get()
        except tk.TclError:
            return "break"
        try:
            self.url_entry.delete("sel.first", "sel.last")
        except tk.TclError:
            pass
        self.url_entry.insert("insert", clipboard)
        return "break"

    def _show_paste_menu(self, event):
        self.url_entry.focus_set()
        self.paste_menu.tk_popup(event.x_root, event.y_root)
        return "break"

    def _set_report(self, text, tag=None):
        self.report.configure(state="normal"); self.report.delete("1.0", "end"); self.report.insert("end", text, tag or ()); self.report.configure(state="disabled")

    def start_scan(self):
        raw = self.url_entry.get().strip()
        if not raw:
            messagebox.showinfo("Нужен адрес", "Введите адрес сайта, например https://example.com"); return
        if "://" not in raw: raw = "https://" + raw
        parsed = urllib.parse.urlparse(raw)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            messagebox.showerror("Некорректный адрес", "Укажите корректный адрес сайта с http:// или https://"); return
        try:
            ip = ipaddress.ip_address(parsed.hostname.strip("[]"))
            if not ip.is_global:
                messagebox.showerror("Адрес недоступен", "Проверка локальных и частных IP-адресов отключена."); return
        except ValueError:
            pass
        self.url_entry.delete(0, "end"); self.url_entry.insert(0, raw)
        self.scan_button.configure(state="disabled", text="  Проверяю…  "); self.doc_button.configure(state="disabled")
        self.status.configure(text="Получаю публичные данные сайта…", fg=ACCENT); self._set_report("Выполняется безопасная проверка…")
        threading.Thread(target=self._audit, args=(raw,), daemon=True).start()

    @staticmethod
    def _request(url, timeout=10, limit=65536):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml,*/*;q=0.5"})
        try:
            response = urllib.request.urlopen(req, timeout=timeout)
        except urllib.error.HTTPError as response:
            pass
        with response:
            data = response.read(limit)
            return {"status": response.status, "headers": response.headers, "url": response.geturl(), "body": data}

    def _audit(self, url):
        try:
            result = {"url": url, "findings": [], "info": [], "files": [], "started": datetime.now().astimezone().strftime("%d.%m.%Y %H:%M:%S")}
            parsed = urllib.parse.urlparse(url); host = parsed.hostname
            try: result["ip"] = ", ".join(sorted({x[4][0] for x in socket.getaddrinfo(host, None)}))
            except OSError as exc: result["findings"].append(("bad", f"DNS: не удалось определить адрес ({exc})"))
            try:
                page = self._request(url, limit=1_000_000)
            except Exception as exc:
                self.events.put(("error", str(exc))); return
            result["final_url"], result["status"], result["headers"] = page["url"], page["status"], page["headers"]
            headers = result["headers"]
            content_type = headers.get("Content-Type", "")
            body = page["body"].decode("utf-8", errors="replace") if "html" in content_type.lower() or not content_type else ""
            final = urllib.parse.urlparse(result["final_url"]); is_https = final.scheme == "https"
            result["info"].append(f"HTTP: {result['status']} · Итоговый адрес: {result['final_url']}")
            if "ip" in result: result["info"].append(f"DNS: {result['ip']}")
            parser = PageInspector()
            if body:
                parser.feed(body); parser.close(); parser.finish()
                result["info"] += [f"Название сайта: {parser.title or 'не определено'}", f"Описание: {parser.description or 'не указано в meta description'}", f"HTML: {len(parser.forms)} форм · {parser.links} ссылок · {len(parser.http_resources)} внешних HTTP-ресурсов"]
                if parser.http_resources: result["findings"].append(("warn", f"В HTML найдены ресурсы без HTTPS: {len(parser.http_resources)} (возможное mixed content)."))
                for form in parser.forms:
                    action = urllib.parse.urlparse(urllib.parse.urljoin(result["final_url"], form["action"] or result["final_url"]))
                    if action.scheme == "http" and is_https: result["findings"].append(("warn", "Форма отправляет данные на адрес без HTTPS."))
                    if any(i["type"] == "password" for i in form["inputs"]) and form["method"] != "post": result["findings"].append(("warn", "Форма с полем пароля использует GET: проверьте, что секреты не попадают в URL."))
                    if form["method"] == "get" and any(i["type"] == "password" for i in form["inputs"]): result["findings"].append(("bad", "Возможная утечка пароля: GET-форма содержит поле password."))
            else: result["info"] += ["Название сайта: не удалось прочитать HTML", "Описание: недоступно"]

            for header, label, severity in (("Strict-Transport-Security", "HSTS", "warn"), ("Content-Security-Policy", "Content Security Policy", "warn"), ("X-Content-Type-Options", "X-Content-Type-Options", "warn"), ("X-Frame-Options", "X-Frame-Options / CSP frame-ancestors", "warn"), ("Referrer-Policy", "Referrer-Policy", "muted"), ("Permissions-Policy", "Permissions-Policy", "muted")):
                present = headers.get(header)
                if header == "X-Frame-Options" and not present and "frame-ancestors" in headers.get("Content-Security-Policy", "").lower(): present = True
                result["findings"].append(("good", f"{label}: настроен") if present else (severity, f"{label}: отсутствует"))
            if not is_https: result["findings"].append(("bad", "Главная страница не использует HTTPS."))
            if headers.get("Server"): result["info"].append(f"Server: {headers['Server']}")
            if headers.get("X-Powered-By"): result["findings"].append(("muted", f"X-Powered-By раскрывает технологию: {headers['X-Powered-By']}"))
            cookies = headers.get_all("Set-Cookie") or []
            for cookie in cookies[:10]:
                name = cookie.split("=", 1)[0].strip() or "cookie"; flags = cookie.lower()
                missing = [label for flag, label in (("; secure", "Secure"), ("; httponly", "HttpOnly"), ("; samesite", "SameSite")) if flag not in flags]
                result["findings"].append(("warn", f"Cookie «{name}»: без флагов {', '.join(missing)}") if missing else ("good", f"Cookie «{name}»: защитные флаги установлены"))
            if not cookies: result["findings"].append(("good", "Set-Cookie: в ответе главной страницы не обнаружен"))

            if is_https:
                try:
                    context = ssl.create_default_context()
                    with socket.create_connection((host, final.port or 443), timeout=7) as sock:
                        with context.wrap_socket(sock, server_hostname=host) as secure: cert = secure.getpeercert()
                    expires = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    days = (expires - datetime.now(timezone.utc)).days
                    result["findings"].append(("good" if days > 30 else "warn", f"TLS-сертификат: истекает через {days} дн." if days >= 0 else f"TLS-сертификат истёк {-days} дн. назад"))
                except Exception as exc: result["findings"].append(("warn", f"TLS: сведения о сертификате недоступны ({exc})"))

            # Small, fixed list of public metadata and common accidental-exposure paths; bodies are never retained.
            paths = ["/robots.txt", "/sitemap.xml", "/.well-known/security.txt", "/.env", "/.git/HEAD", "/.DS_Store", "/config.php.bak", "/backup.zip"]
            for path in paths:
                target = urllib.parse.urljoin(result["final_url"], path)
                try:
                    item = self._request(target, timeout=5, limit=2048)
                    code, ctype, sample = item["status"], item["headers"].get("Content-Type", ""), item["body"]
                except urllib.error.URLError as exc:
                    code = getattr(getattr(exc, "reason", None), "code", None)
                    if code is None and isinstance(exc, urllib.error.HTTPError): code = exc.code
                    ctype, sample = code or "недоступен", b""
                except Exception:
                    code, ctype, sample = "ошибка/таймаут", "", b""
                if code == 200:
                    result["files"].append((path, code, ctype))
                    if path in ("/.env", "/.git/HEAD", "/.DS_Store", "/config.php.bak", "/backup.zip"):
                        # Never put response content into results; only report the HTTP exposure signal.
                        result["findings"].append(("bad", f"Путь {path} отвечает HTTP 200 — проверьте, не опубликован ли конфиденциальный файл."))
                    else: result["info"].append(f"Публичный файл {path}: доступен (HTTP 200).")
                elif code == 403:
                    result["files"].append((path, code, ctype))
                    if path in ("/.env", "/.git/HEAD", "/.DS_Store", "/config.php.bak", "/backup.zip"): result["findings"].append(("good", f"Путь {path}: доступ запрещён (403)."))
                elif path in ("/.env", "/.git/HEAD", "/.DS_Store", "/config.php.bak", "/backup.zip") and code == 404:
                    result["files"].append((path, code, ctype))
            result["info"].append(f"Проверка публичных путей: {len(result['files'])} отвечающих (200/403/404) из {len(paths)}.")
            query_names = sorted({k for k, _ in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)})
            result["info"].append("Параметры URL: " + (", ".join(query_names) if query_names else "не обнаружены"))
            result["findings"].append(("muted", "Инъекции (SQLi/XSS/command injection) не тестировались: активные payload-запросы намеренно отключены. Поля и параметры перечислены для ручной авторизованной проверки."))
            result["info"].append("Ограничения: это пассивный внешний обзор; он не проверяет исходный код, авторизацию, скрытые маршруты, бизнес-логику или все варианты уязвимостей.")
            self.events.put(("result", result))
        except Exception as exc:
            self.events.put(("error", str(exc)))

    def _render_result(self, data):
        lines = [("ОБЗОР САЙТА", "heading"), (data["url"], "muted"), ("\nСВЕДЕНИЯ О САЙТЕ", "heading")]
        lines += [(x, "") for x in data["info"]]
        lines += [("\nРЕЗУЛЬТАТЫ ПРОВЕРКИ", "heading")]
        lines += [(f"{'✓' if tag == 'good' else '!' if tag in ('warn','bad') else '·'}  {text}", tag) for tag, text in data["findings"]]
        self.report.configure(state="normal"); self.report.delete("1.0", "end")
        for text, tag in lines: self.report.insert("end", text + "\n", tag)
        self.report.configure(state="disabled")

    def _poll(self):
        try:
            while True:
                kind, payload = self.events.get_nowait()
                self.scan_button.configure(state="normal", text="  Анализировать  →  ")
                if kind == "error":
                    self.status.configure(text="Не удалось завершить проверку", fg=RED); self._set_report("Не удалось получить данные сайта.\n\n" + payload + "\n\nПроверьте адрес и подключение к интернету.", "bad")
                else:
                    self.last_result = payload; self.doc_button.configure(state="normal")
                    self.status.configure(text="Проверка завершена · результаты носят ориентировочный характер", fg=GREEN); self._render_result(payload)
        except queue.Empty: pass
        self.root.after(100, self._poll)

    @staticmethod
    def _docx_paragraph(text, style="Normal"):
        return f'<w:p><w:pPr><w:pStyle w:val="{style}"/></w:pPr><w:r><w:t xml:space="preserve">{escape(str(text))}</w:t></w:r></w:p>'

    def create_report(self):
        data = self.last_result
        if not data: return
        host = urllib.parse.urlparse(data["final_url"]).hostname or "site"
        suggested = f"SiteScope_{host}_{datetime.now():%Y%m%d_%H%M}.docx"
        path = filedialog.asksaveasfilename(title="Сохранить отчёт аудита", initialfile=suggested, defaultextension=".docx", filetypes=[("Документ Word", "*.docx")])
        if not path: return
        title = next((x.partition(": ")[2] for x in data["info"] if x.startswith("Название сайта:")), host)
        desc = next((x.partition(": ")[2] for x in data["info"] if x.startswith("Описание:")), "")
        # Cover page: identity, site summary and scope, intentionally separated from detailed findings.
        parts = [self._docx_paragraph("SITESCOPE  |  ОТЧЁТ ПО БЕЗОПАСНОСТИ", "Subtitle"), self._docx_paragraph(title, "Title"), self._docx_paragraph(data["final_url"], "Subtitle"), self._docx_paragraph("ПАССИВНЫЙ ВНЕШНИЙ АУДИТ", "Heading1"), self._docx_paragraph(desc or "Описание сайта не указано в метаданных страницы."), self._docx_paragraph("Что проверено", "Heading2"), self._docx_paragraph("Доступность и TLS/HTTPS · защитные HTTP-заголовки · cookies · базовые сведения о формах и HTML · ограниченный набор публичных служебных и конфигурационных путей."), self._docx_paragraph("Что это за сайт", "Heading2"), self._docx_paragraph(f"Название: {title}. Адрес: {data['final_url']}. {desc}"), self._docx_paragraph(f"Дата проверки: {data['started']}"), self._docx_paragraph("Проверку выполнять только с разрешения владельца сайта. Результаты автоматизированного обзора не являются подтверждением отсутствия уязвимостей.")]
        parts.append('<w:p><w:r><w:br w:type="page"/></w:r></w:p>')
        parts += [self._docx_paragraph("Подробные результаты", "Title"), self._docx_paragraph("Сводка", "Heading1")]
        parts += [self._docx_paragraph(x) for x in data["info"]]
        parts.append(self._docx_paragraph("Находки", "Heading1"))
        if data["findings"]:
            parts += [self._docx_paragraph(f"[{tag.upper()}] {text}") for tag, text in data["findings"]]
        else: parts.append(self._docx_paragraph("Находок не зарегистрировано."))
        parts.append(self._docx_paragraph("Проверенные публичные пути", "Heading1"))
        parts += [self._docx_paragraph(f"{p} — HTTP {code}{(' · ' + ctype) if ctype else ''}") for p, code, ctype in data["files"]] or [self._docx_paragraph("Подтверждённых ответов 200/403/404 для выбранных путей не получено.")]
        parts += [self._docx_paragraph("Ограничения и рекомендации", "Heading1"), self._docx_paragraph("SQL-инъекции, XSS и другие инъекции не тестировались: активные payload-запросы не отправляются. Проверка не анализирует исходный код, авторизацию и бизнес-логику. Рекомендуется подтверждать находки вручную, устранять публикацию конфигураций и резервных копий, настраивать защитные заголовки и проводить отдельный авторизованный тест безопасности.")]
        document = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>{''.join(parts)}<w:sectPr><w:pgSz w:w="11906" w:h="16838"/><w:pgMar w:top="1200" w:right="1100" w:bottom="1200" w:left="1100"/></w:sectPr></w:body></w:document>'''
        styles = '''<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:docDefaults><w:rPrDefault><w:rPr><w:rFonts w:ascii="Aptos" w:hAnsi="Aptos"/><w:sz w:val="21"/><w:color w:val="263445"/></w:rPr></w:rPrDefault><w:pPrDefault><w:pPr><w:spacing w:after="140" w:line="300"/></w:pPr></w:pPrDefault></w:docDefaults><w:style w:type="paragraph" w:default="1" w:styleId="Normal"><w:name w:val="Normal"/></w:style><w:style w:type="paragraph" w:styleId="Title"><w:name w:val="Title"/><w:rPr><w:b/><w:sz w:val="38"/><w:color w:val="17212B"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Subtitle"><w:name w:val="Subtitle"/><w:rPr><w:sz w:val="20"/><w:color w:val="2563EB"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading1"><w:name w:val="heading 1"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="28"/><w:color w:val="2563EB"/></w:rPr></w:style><w:style w:type="paragraph" w:styleId="Heading2"><w:name w:val="heading 2"/><w:basedOn w:val="Normal"/><w:rPr><w:b/><w:sz w:val="24"/><w:color w:val="17212B"/></w:rPr></w:style></w:styles>'''
        try:
            with ZipFile(path, "w", ZIP_DEFLATED) as doc:
                doc.writestr("[Content_Types].xml", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/></Types>')
                doc.writestr("_rels/.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/></Relationships>')
                doc.writestr("word/document.xml", document)
                doc.writestr("word/styles.xml", styles)
                doc.writestr("word/_rels/document.xml.rels", '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rIdStyles" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/></Relationships>')
            self.status.configure(text=f"Отчёт сохранён: {path}", fg=GREEN)
            try: os.startfile(path)
            except OSError as exc: messagebox.showinfo("Отчёт создан", f"Файл сохранён, но не удалось открыть автоматически:\n{path}\n\n{exc}")
        except Exception as exc: messagebox.showerror("Ошибка создания отчёта", str(exc))


def main():
    root = tk.Tk()
    AuditApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
