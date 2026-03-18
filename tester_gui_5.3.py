#!/usr/bin/env python3
import concurrent.futures
import os
import queue
import socket
import ssl
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import dns.resolver
import requests
import tkinter as tk
from tkinter import messagebox, ttk

APP_TITLE = "DPI & Connectivity Tester"
APP_VERSION = "v5.3"
TIMEOUT = 10
MAX_WORKERS = 4
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36"
)
SITES_FILENAME = "user_sites.txt"

DEFAULT_CORE_SITES = [
    {"id": "YT-01", "provider": "YouTube", "country": "🌐", "host": "youtube.com", "url": "https://youtube.com/"},
    {"id": "GH-01", "provider": "GitHub", "country": "🌐", "host": "github.com", "url": "https://github.com/"},
    {"id": "MS-01", "provider": "Microsoft", "country": "🌐", "host": "microsoft.com", "url": "https://microsoft.com/"},
    {"id": "AKM-01", "provider": "Akamai", "country": "🇸🇪", "host": "cdn.apple-mapkit.com", "url": "https://cdn.apple-mapkit.com/"},
    {"id": "AWS-01", "provider": "AWS", "country": "🇺🇸", "host": "corp.kaltura.com", "url": "https://corp.kaltura.com/"},
    {"id": "CDN77-01", "provider": "CDN77", "country": "🇺🇸", "host": "cdn.eso.org", "url": "https://cdn.eso.org/"},
    {"id": "CF-01", "provider": "Cloudflare", "country": "🇺🇸", "host": "img.wzstats.gg", "url": "https://img.wzstats.gg/"},
    {"id": "CF-02", "provider": "Cloudflare", "country": "🇨🇦", "host": "justice.gov", "url": "https://justice.gov/"},
    {"id": "CNTB-01", "provider": "Contabo", "country": "🇫🇷", "host": "oddremedies.com", "url": "https://oddremedies.com/"},
    {"id": "DO-01", "provider": "DigitalOcean", "country": "🇩🇪", "host": "ui-arts.com", "url": "https://ui-arts.com/"},
    {"id": "DO-02", "provider": "DigitalOcean", "country": "🇬🇧", "host": "admin.survey54.com", "url": "https://admin.survey54.com/"},
    {"id": "FST-01", "provider": "Fastly", "country": "🇨🇦", "host": "ssl.p.jwpcdn.com", "url": "https://ssl.p.jwpcdn.com/"},
    {"id": "GCORE-01", "provider": "Gcore", "country": "🇱🇺", "host": "gcore.com", "url": "https://gcore.com/"},
    {"id": "GC-01", "provider": "Google Cloud", "country": "🇺🇸", "host": "api.usercentrics.eu", "url": "https://api.usercentrics.eu/"},
    {"id": "GC-02", "provider": "Google Cloud", "country": "🇺🇸", "host": "widgets.reputation.com", "url": "https://widgets.reputation.com/"},
    {"id": "HE-01", "provider": "Hetzner", "country": "🇩🇪", "host": "king.hr", "url": "https://king.hr/"},
    {"id": "HE-02", "provider": "Hetzner", "country": "🇫🇮", "host": "nioges.com", "url": "https://nioges.com/"},
    {"id": "MBCOM-01", "provider": "Melbicom", "country": "🇺🇸", "host": "elecane.com", "url": "https://elecane.com/"},
    {"id": "OR-01", "provider": "Oracle", "country": "🇸🇬", "host": "vps.inprodec.com", "url": "https://vps.inprodec.com/"},
    {"id": "OVH-01", "provider": "OVH", "country": "🇫🇷", "host": "www.adwin.fr", "url": "https://www.adwin.fr/"},
    {"id": "SW-01", "provider": "Scaleway", "country": "🇳🇱", "host": "www.velivole.fr", "url": "https://www.velivole.fr/"},
    {"id": "VLTR-01", "provider": "Vultr", "country": "🇩🇪", "host": "gertrud.tv", "url": "https://gertrud.tv/"},
    {"id": "VLTR-02", "provider": "Vultr", "country": "🇺🇸", "host": "us.rudder.qntmnet.com", "url": "https://us.rudder.qntmnet.com/"},
]


def build_default_test_suite() -> list[dict]:
    return [dict(item) for item in DEFAULT_CORE_SITES]


DEFAULT_TEST_SUITE = build_default_test_suite()

HELP_TEXT = """
Этот скрипт выполняет тесты с вашего компьютера для определения различных видов блокировок.

--- ОПИСАНИЕ ТЕСТОВ В ВЫВОДЕ ---

DNS:
  - Тест отправляет запросы к независимым публичным DNS-серверам (Cloudflare, Google).
  - "OK" означает, что IP-адрес успешно получен.
  - "Ошибка" говорит о невозможности получить IP. Это может быть как проблемой сети,
    так и признаком DNS-блокировки.

Локация:
  - Определяет страну и город, где предположительно находится сервер,
    на основе его IP-адреса через сервис ip-api.com.

TLS 1.3 / 1.2:
  - Проверяет возможность установить зашифрованное соединение с сервером, используя
    конкретную версию протокола TLS. Блокировка TLS 1.3 может указывать на то,
    что провайдер пытается понизить соединение до старой версии для анализа.

SSL:
  - Проверяет полное TLS-рукопожатие, включая проверку подлинности SSL-сертификата.
  - "OK" означает, что сертификат сайта подлинный и соединение установлено.
  - "Подмена сертификата" — явный признак атаки 'человек посередине' (MITM),
    часто используемой DPI для расшифровки и анализа HTTPS-трафика.
  - "Ошибка" (напр. ConnectionResetError) на этом этапе указывает на блокировку по IP
    или по имени сервера (SNI) на ранней стадии соединения.

HTTP:
  - После успешного TLS-соединения отправляется стандартный веб-запрос (HTTP GET).
  - "OK" c кодом 200-299 означает, что сервер успешно ответил.
  - "Ошибка" на этом этапе — классический признак DPI, который анализирует и
    блокирует трафик по его содержимому уже внутри "защищенного" канала.

DPI (16KB):
  - Специальный тест, который пытается скачать большой файл. Если загрузка обрывается
    на объеме около 16-24 КБ, это указывает на вид DPI-блокировки,
    разрывающей соединение после передачи небольшого объема данных.

--- ИНТЕРПРЕТАЦИЯ ИТОГОВЫХ ВЕРДИКТОВ ---

DNS-блокировка:
  - Не удалось получить IP-адрес домена. Возможно, домен не существует
    или его DNS-записи блокируются.

Блокировка по IP / SNI:
  - DNS-запрос успешен, но SSL-соединение было сброшено на самом раннем этапе.

Блокировка 'black-hole':
  - Запрос к серверу не завершился за отведенное время (таймаут). Трафик
    к заблокированному ресурсу просто отбрасывается без ответа.

Подмена SSL (DPI/MITM):
  - Соединение установлено, но SSL-сертификат не является доверенным.
    Явный признак атаки 'человек посередине' (MITM).

Блокировка по DPI (HTTP):
  - DNS и SSL-соединение прошли успешно, но последующий HTTP-запрос
    внутри защищенного канала был заблокирован.

DPI (разрыв при скачивании):
  - Выявлен специфический тип DPI, рвущий соединение при попытке скачать файл.

Доступен:
  - Все основные тесты (DNS, SSL, HTTP) прошли успешно.

--- ДОПОЛНЕНИЯ ДЛЯ ТЕКУЩЕЙ GUI-ВЕРСИИ ---

Мой список:
  - В пользовательский список можно добавлять не только домен, но и полный адрес.
  - Поддерживаются варианты:
      site.com
      site.com:771
      https://site.com
      http://site.com
      https://site.com/path/file.ext
  - Если протокол не указан, программа автоматически подставляет https://
  - Если указан путь до конкретного файла или страницы, проверка будет выполняться именно по этому адресу.

Что лучше добавлять в список:
  - Для обычной проверки доступности чаще всего лучше использовать сам домен или главную страницу сайта.
    Они обычно живут дольше и реже пропадают.
  - Адрес до конкретного файла тоже можно использовать, но такие ссылки со временем могут перестать работать,
    даже если сам сайт и домен остаются доступными.
  - Поэтому для стандартного списка в приложении в основном используются домены и страницы сайтов,
    а не ссылки на отдельные файлы.

Не проверено (HTTP ...):
  - Это не обязательно ошибка и не обязательно блокировка.
  - Такой статус означает, что HTTP-ответ получен, но код ответа оказался служебным
    или неподходящим для теста скачивания большого объема данных.
  - Например, сайт может вернуть редирект, страницу защиты, запрет доступа или другой нестандартный ответ.

Не проверено (<16 KB ...):
  - Сайт ответил успешно, но объем данных оказался слишком маленьким для теста DPI по разрыву скачивания.
  - Это нормальная ситуация для небольших страниц, коротких ответов, редиректов и легких сайтов.
  - Такой статус не означает, что сайт заблокирован.

Локация в текущей версии:
  - Приложение пытается определить страну и город сервера по IP-адресу.
  - В части случаев локация может не определиться, определиться не полностью
    или показываться приблизительно.
  - Это нормально для некоторых CDN, балансировщиков, Anycast-узлов и защитных сетей.

Стандартная проверка:
  - Встроенный список подобран так, чтобы проверять крупные площадки, CDN и инфраструктурные сервисы.
  - Список может обновляться между версиями приложения.
  - Если какой-то ресурс со временем меняет поведение, закрывает доступ или переезжает,
    это не всегда означает блокировку со стороны провайдера.

Подсказки в интерфейсе:
  - При наведении мыши на ячейки в таблице и на строки в подробностях приложение может показывать
    дополнительные пояснения по ошибкам, статусам и итоговому вердикту.
  - Если для какого-то текста нет отдельной расшифровки, может показываться сам текст результата
    или общий итог по строке.
""".strip()

TOOLTIP_HINTS = {
    "вердикт: доступен ✅": "Сайт открылся без явных признаков блокировки: DNS, SSL и HTTP прошли успешно.",
    "вердикт: доступен ✅ (dpi-тест ограничен)": "Базовая доступность подтверждена, но DPI-тест оказался неполным: сайт мог вернуть слишком маленький ответ, редирект или служебную страницу.",
    "вердикт: dns-блокировка": "Не удалось получить IP. Часто это проблема DNS или DNS-фильтрации.",
    "вердикт: подмена ssl": "Сертификат не доверенный. Возможен MITM или вмешательство DPI.",
    "вердикт: блокировка по ip/sni": "DNS ответил, но TLS/SSL не установился. Похоже на блокировку по IP или имени сервера.",
    "вердикт: блокировка по dpi (http)": "TLS-соединение поднялось, но сам HTTP-запрос не прошёл. Это похоже на DPI-фильтрацию содержимого.",
    "вердикт: dpi (разрыв при скачивании)": "Соединение рвётся во время передачи данных. Это похоже на DPI по объёму или содержимому.",
    "вердикт: блокировка 'black-hole'": "Пакеты, вероятно, молча отбрасываются. Типичный симптом black-hole блокировки.",
    "ошибка (nxdomain)": "Такой домен не найден через DNS.",
    "ошибка (lifetimeout)": "DNS-сервер не ответил вовремя. Возможна проблема сети или фильтрация запросов.",
    "ошибка (timeout": "Таймаут: сервер не ответил вовремя или трафик молча отбрасывается.",
    "timeout": "Таймаут: сервер не ответил вовремя или трафик молча отбрасывается.",
    "подмена сертификата": "Ошибка проверки сертификата. Возможна подмена сертификата или корпоративный MITM.",
    "sslcertverificationerror": "Ошибка проверки сертификата. Возможна подмена сертификата.",
    "ssl error": "Ошибка SSL/TLS. Соединение не удалось корректно защитить или согласовать параметры шифрования.",
    "sslerror": "Ошибка SSL/TLS. Соединение не удалось корректно защитить или согласовать параметры шифрования.",
    "tls": "Ошибка TLS/SSL. Возможна несовместимость настроек, фильтрация или сбой при рукопожатии.",
    "connectionreseterror": "Соединение было сброшено. Часто встречается при блокировке по IP/SNI или DPI.",
    "connectionabortederror": "Соединение было прервано. Это бывает при сетевых фильтрах и нестабильных прокси.",
    "connectionrefusederror": "Удалённый узел отверг подключение. Либо порт закрыт, либо фильтр режет соединение.",
    "gaierror": "Имя узла не удалось преобразовать в IP. Проверь домен и DNS.",
    "name or service not known": "Имя узла не удалось разрешить. Проверь домен и DNS.",
    "remote end closed connection": "Сервер или промежуточный фильтр закрыл соединение без полного ответа.",
    "remoteDisconnected".lower(): "Удалённая сторона закрыла соединение без ответа.",
    "blocked ❌": "Попытка установить соединение была заблокирована на одном из этапов.",
    "не проверено (http": "HTTP вернул служебный код ответа. Базовая доступность есть, но этот ответ не подходит для DPI-теста по скачиванию.",
    "не проверено (<16 kb": "Сайт ответил слишком маленьким объёмом данных. Для DPI-теста это недостаточно.",
    "detected❗️ (chunkedencodingerror)": "Поток ответа оборвался во время загрузки. Это может быть признаком DPI или нестабильного маршрута.",
    "detected❗️": "Во время загрузки большого ответа возник обрыв. Это похоже на DPI-разрыв соединения.",
    "ok (": "Проверка прошла успешно на этом этапе.",
    "ok ✅": "Проверка прошла успешно на этом этапе.",
}


@dataclass
class SiteResult:
    label: str
    site_id: str
    provider: str
    country: str
    url: str
    host: str
    dns_status: str
    dns_time: str
    ip: str
    location: str
    tls13_status: str
    tls12_status: str
    ssl_status: str
    ssl_time: str
    http_status: str
    http_time: str
    dpi_download_status: str
    verdict: str


class ToolTip:
    def __init__(self, widget):
        self.widget = widget
        self.tipwindow = None
        self.text = ""

    def show(self, text, x, y):
        if not text:
            self.hide()
            return
        if self.tipwindow and self.text == text:
            try:
                self.tipwindow.geometry(f"+{x}+{y}")
            except tk.TclError:
                pass
            return
        self.hide()
        self.text = text
        self.tipwindow = tw = tk.Toplevel(self.widget)
        tw.wm_overrideredirect(True)
        tw.wm_geometry(f"+{x}+{y}")
        label = ttk.Label(
            tw,
            text=text,
            justify="left",
            background="#fff8dc",
            relief="solid",
            borderwidth=1,
            padding=(8, 6),
            wraplength=420,
        )
        label.pack()

    def hide(self):
        if self.tipwindow is not None:
            self.tipwindow.destroy()
            self.tipwindow = None
        self.text = ""


def get_app_base_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def get_user_sites_path() -> Path:
    return get_app_base_dir() / SITES_FILENAME


def normalize_url(value: str) -> str:
    value = value.strip()
    if not value:
        return ""
    if not value.startswith(("http://", "https://")):
        value = f"https://{value}"
    parsed = urlparse(value)
    if not parsed.hostname:
        raise ValueError("Не удалось определить домен. Введите адрес в формате site.com или https://site.com")
    return value


def load_user_sites() -> list[str]:
    path = get_user_sites_path()
    try:
        if not path.exists():
            path.write_text("", encoding="utf-8")
        return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    except Exception:
        return []


def save_user_sites(sites: list[str]) -> None:
    path = get_user_sites_path()
    path.write_text("\n".join(sites) + ("\n" if sites else ""), encoding="utf-8")


def open_user_sites_file() -> None:
    path = get_user_sites_path()
    if not path.exists():
        path.write_text("", encoding="utf-8")
    if sys.platform.startswith("win"):
        os.startfile(str(path))
    elif sys.platform == "darwin":
        subprocess.Popen(["open", str(path)])
    else:
        subprocess.Popen(["xdg-open", str(path)])


def test_dns(hostname: str):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["1.1.1.1", "8.8.8.8"]
    start_time = time.monotonic()
    try:
        answers = resolver.resolve(hostname)
        ip_address = answers[0].to_text()
        duration = time.monotonic() - start_time
        return f"OK ({ip_address})", f"{duration:.3f} с", ip_address
    except Exception as exc:
        duration = time.monotonic() - start_time
        return f"Ошибка ({exc.__class__.__name__})", f"{duration:.3f} с", None


def get_ip_location(ip_address: str | None, country_hint: str = "") -> str:
    if not ip_address:
        return country_hint or "N/A"

    services = [
        (f"http://ip-api.com/json/{ip_address}?fields=status,country,city", ("country", "city"), "status", "success"),
        (f"https://ipwho.is/{ip_address}", ("country", "city"), "success", True),
    ]

    for url, fields, ok_key, ok_value in services:
        try:
            response = requests.get(url, timeout=5, headers={"User-Agent": USER_AGENT})
            response.raise_for_status()
            data = response.json()
            if data.get(ok_key) != ok_value:
                continue
            parts = [data.get(field, "") for field in fields]
            location = ", ".join(part for part in parts if part)
            if location:
                return location
        except Exception:
            continue

    return country_hint or "Не удалось определить"


def test_tls_version(host: str, ip: str | None, port: int, version_enum: ssl.TLSVersion, version_str: str) -> str:
    if not ip:
        return "Пропуск (нет IP)"
    context = ssl.create_default_context()
    context.minimum_version = version_enum
    if version_str == "TLSv1.2":
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                return "OK ✅"
    except Exception as exc:
        return f"Blocked ❌ ({exc.__class__.__name__})"


def test_ssl_handshake(host: str, ip: str | None, port: int):
    if not ip:
        return "Пропуск (нет IP)", "N/A"
    context = ssl.create_default_context()
    start_time = time.monotonic()
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=host):
                duration = time.monotonic() - start_time
                return "OK ✅", f"{duration:.3f} с"
    except ssl.SSLCertVerificationError:
        duration = time.monotonic() - start_time
        return "Подмена сертификата ❌", f"{duration:.3f} с"
    except Exception as exc:
        duration = time.monotonic() - start_time
        return f"Ошибка ({exc.__class__.__name__}) ❌", f"{duration:.3f} с"


def test_http_get(url: str):
    try:
        response = requests.get(url, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT})
        duration = response.elapsed.total_seconds()
        return f"OK ({response.status_code}) ✅", f"{duration:.3f} с"
    except requests.exceptions.RequestException as exc:
        return f"Ошибка ({exc.__class__.__name__}) ❌", "N/A"


def test_dpi_download(url: str):
    try:
        with requests.get(url, stream=True, timeout=TIMEOUT, headers={"User-Agent": USER_AGENT}) as response:
            status_code = response.status_code
            if status_code >= 400:
                return f"Не проверено (HTTP {status_code})"
            total = 0
            for chunk in response.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                total += len(chunk)
                if total > 2 * 1024 * 1024:
                    return "Not detected ✅"
            if total < 16 * 1024:
                return f"Не проверено (<16 KB, {total // 1024} KB)"
            if 16 * 1024 <= total <= 24 * 1024:
                return f"Detected❗️ ({total // 1024} KB)"
            return "Not detected ✅"
    except requests.exceptions.RequestException as exc:
        return f"Detected❗️ ({exc.__class__.__name__})"


def determine_verdict(results: dict[str, str]) -> str:
    if "Ошибка" in results["dns_status"]:
        return "DNS-блокировка ❗️"
    if "Подмена сертификата" in results["ssl_status"]:
        return "Подмена SSL (DPI/MITM) ❗️"
    if "Ошибка" in results["ssl_status"] and "Timeout" not in results["ssl_status"]:
        return "Блокировка по IP/SNI ❗️"
    if "Ошибка" in results["http_status"]:
        return "Блокировка по DPI (HTTP) ❗️"
    if results["dpi_download_status"].startswith("Detected"):
        return "DPI (разрыв при скачивании) ❗️"
    if "Timeout" in results["ssl_status"]:
        return "Блокировка 'black-hole' ❗️"
    if "Не проверено" in results["dpi_download_status"]:
        return "Доступен ✅ (DPI-тест ограничен)"
    return "Доступен ✅"


def build_label(item: dict, index: int, total: int) -> str:
    if isinstance(item, dict):
        country = f" {item.get('country', '')}" if item.get("country") else ""
        return f"[{item.get('id', f'SITE-{index+1}')}] {item.get('provider', 'Сайт')}{country}"
    return f"Сайт {index + 1}/{total}"


def run_full_test_on_url(item, index: int = 0, total: int = 1) -> SiteResult:
    if isinstance(item, dict):
        source_item = dict(item)
        url = source_item.get("url", "")
        site_id = source_item.get("id", "")
        provider = source_item.get("provider", "")
        country = source_item.get("country", "")
        host_override = source_item.get("host", "")
    else:
        source_item = {}
        url = str(item)
        site_id = f"USER-{index + 1:02d}"
        provider = "Пользовательский сайт"
        country = ""
        host_override = ""

    parsed_url = urlparse(url)
    hostname = host_override or parsed_url.hostname or ""
    if not url and hostname:
        url = f"https://{hostname}/"
        parsed_url = urlparse(url)

    port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)

    results: dict[str, str] = {}
    results["dns_status"], results["dns_time"], ip = test_dns(hostname)
    results["location"] = get_ip_location(ip, country_hint=country)
    results["tls13_status"] = test_tls_version(hostname, ip, port, ssl.TLSVersion.TLSv1_3, "TLSv1.3")
    results["tls12_status"] = test_tls_version(hostname, ip, port, ssl.TLSVersion.TLSv1_2, "TLSv1.2")
    results["ssl_status"], results["ssl_time"] = test_ssl_handshake(hostname, ip, port)
    results["http_status"], results["http_time"] = test_http_get(url)
    results["dpi_download_status"] = test_dpi_download(url)
    results["verdict"] = determine_verdict(results)

    return SiteResult(
        label=build_label(source_item if isinstance(item, dict) else {"id": site_id, "provider": provider, "country": country}, index, total),
        site_id=site_id,
        provider=provider,
        country=country,
        url=url,
        host=hostname,
        dns_status=results["dns_status"],
        dns_time=results["dns_time"],
        ip=ip or "N/A",
        location=results["location"],
        tls13_status=results["tls13_status"],
        tls12_status=results["tls12_status"],
        ssl_status=results["ssl_status"],
        ssl_time=results["ssl_time"],
        http_status=results["http_status"],
        http_time=results["http_time"],
        dpi_download_status=results["dpi_download_status"],
        verdict=results["verdict"],
    )



class DPIConnectivityApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_TITLE} ({APP_VERSION})")
        self.root.geometry("1120x720")
        self.root.minsize(900, 620)

        self.user_sites = load_user_sites()
        self.worker_thread = None
        self.stop_event = threading.Event()
        self.ui_queue: queue.Queue = queue.Queue()
        self.result_by_row: dict[str, SiteResult] = {}
        self.all_results: list[SiteResult] = []

        self.stats_var = tk.StringVar(value="Готово.")
        self.path_var = tk.StringVar(value=f"Файл списка: {get_user_sites_path()}")
        self.progress_var = tk.DoubleVar(value=0.0)
        self.show_only_issues = tk.BooleanVar(value=False)

        self.tree_tooltip = ToolTip(self.root)
        self.details_tooltip = ToolTip(self.root)

        self._build_ui()
        self._refresh_user_sites_box()
        self._poll_ui_queue()

    def _build_ui(self):
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        self.paned = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        self.paned.grid(row=0, column=0, sticky="nsew")

        self.left_frame = ttk.Frame(self.paned, padding=12)
        self.right_frame = ttk.Frame(self.paned, padding=12)

        self.paned.add(self.left_frame, weight=0)
        self.paned.add(self.right_frame, weight=1)

        self._build_left_panel()
        self._build_right_panel()

        self.root.after(120, self._fix_initial_pane_width)

    def _fix_initial_pane_width(self):
        try:
            self.root.update_idletasks()
            left_width = max(self.left_frame.winfo_reqwidth() + 20, 300)
            self.paned.sashpos(0, left_width)
        except Exception:
            pass

    def _build_left_panel(self):
        lf = self.left_frame
        lf.columnconfigure(0, weight=1)
        lf.rowconfigure(2, weight=1)

        header = ttk.Label(lf, text=f"{APP_TITLE} {APP_VERSION}", font=("Segoe UI", 14, "bold"))
        header.grid(row=0, column=0, sticky="w", pady=(0, 10))

        section_main = ttk.LabelFrame(lf, text="Основные действия", padding=10)
        section_main.grid(row=1, column=0, sticky="ew")
        section_main.columnconfigure(0, weight=1)

        self.btn_standard = ttk.Button(section_main, text="Стандартная проверка", command=self.run_standard_suite)
        self.btn_standard.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self.btn_my_list = ttk.Button(section_main, text="Мой список", command=self.run_user_suite)
        self.btn_my_list.grid(row=1, column=0, sticky="ew", pady=(0, 8))

        self.btn_stop = ttk.Button(section_main, text="Остановить тест", command=self.stop_tests)
        self.btn_stop.grid(row=2, column=0, sticky="ew")

        section_add = ttk.LabelFrame(lf, text="Работа с моим списком", padding=10)
        section_add.grid(row=2, column=0, sticky="nsew", pady=(12, 0))
        section_add.columnconfigure(0, weight=1)
        section_add.rowconfigure(7, weight=1)

        ttk.Label(section_add, text="Адрес сайта").grid(row=0, column=0, sticky="w")
        self.site_entry = ttk.Entry(section_add)
        self.site_entry.grid(row=1, column=0, sticky="ew", pady=(4, 6))
        self.site_entry.insert(0, "site.com")
        self.site_entry.bind("<FocusIn>", self._clear_placeholder)
        self.site_entry.bind("<FocusOut>", self._restore_placeholder)
        self.site_entry.bind("<Return>", lambda _event: self.add_and_check_site())

        ttk.Label(
            section_add,
            text="Можно вводить site.com, site.com:771, https://site.com или http://site.com",
            foreground="#666666",
            wraplength=280,
        ).grid(row=2, column=0, sticky="w", pady=(0, 8))

        self.btn_add_check = ttk.Button(section_add, text="Добавить и проверить", command=self.add_and_check_site)
        self.btn_add_check.grid(row=3, column=0, sticky="ew", pady=(0, 6))

        self.btn_open_file = ttk.Button(section_add, text="Открыть файл списка", command=self.open_sites_file)
        self.btn_open_file.grid(row=4, column=0, sticky="ew")

        ttk.Label(section_add, textvariable=self.path_var, wraplength=280, foreground="#666666").grid(
            row=5, column=0, sticky="w", pady=(8, 8)
        )

        ttk.Label(section_add, text="Сайты в списке:").grid(row=6, column=0, sticky="nw")
        list_frame = ttk.Frame(section_add)
        list_frame.grid(row=7, column=0, sticky="nsew", pady=(4, 8))
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)

        self.user_sites_box = tk.Listbox(list_frame, height=8)
        self.user_sites_box.grid(row=0, column=0, sticky="nsew")
        user_scroll = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.user_sites_box.yview)
        user_scroll.grid(row=0, column=1, sticky="ns")
        self.user_sites_box.configure(yscrollcommand=user_scroll.set)

        section_help = ttk.LabelFrame(lf, text="Справка", padding=10)
        section_help.grid(row=3, column=0, sticky="ew", pady=(12, 0))
        section_help.columnconfigure(0, weight=1)
        self.btn_help = ttk.Button(section_help, text="Открыть подробную справку", command=self.show_help_window)
        self.btn_help.grid(row=0, column=0, sticky="ew")

    def _build_right_panel(self):
        rf = self.right_frame
        rf.columnconfigure(0, weight=1)
        rf.rowconfigure(1, weight=1)
        rf.rowconfigure(2, weight=1)

        topbar = ttk.Frame(rf)
        topbar.grid(row=0, column=0, sticky="ew", pady=(0, 10))
        topbar.columnconfigure(0, weight=1)
        topbar.columnconfigure(1, weight=0)

        ttk.Label(topbar, textvariable=self.stats_var, font=("Segoe UI", 10, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(topbar, text="Показать только проблемы", variable=self.show_only_issues, command=self._on_filter_toggle).grid(
            row=0, column=1, sticky="e", padx=(12, 0)
        )
        ttk.Progressbar(topbar, variable=self.progress_var, maximum=100).grid(row=1, column=0, columnspan=2, sticky="ew", pady=(6, 0))

        result_frame = ttk.LabelFrame(rf, text="Результаты", padding=8)
        result_frame.grid(row=1, column=0, sticky="nsew")
        result_frame.columnconfigure(0, weight=1)
        result_frame.rowconfigure(0, weight=1)

        columns = ("label", "host", "ip", "dns", "ssl", "http", "dpi", "verdict")
        self.tree = ttk.Treeview(result_frame, columns=columns, show="headings", height=14)
        self.tree.grid(row=0, column=0, sticky="nsew")

        headings = {
            "label": "Сайт / провайдер",
            "host": "Хост",
            "ip": "IP",
            "dns": "DNS",
            "ssl": "SSL",
            "http": "HTTP",
            "dpi": "DPI (16KB)",
            "verdict": "Вердикт",
        }
        widths = {
            "label": 200,
            "host": 160,
            "ip": 105,
            "dns": 145,
            "ssl": 145,
            "http": 145,
            "dpi": 155,
            "verdict": 190,
        }

        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], minwidth=90, stretch=(col in {"label", "host", "verdict"}), anchor="w")

        yscroll = ttk.Scrollbar(result_frame, orient=tk.VERTICAL, command=self.tree.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        xscroll = ttk.Scrollbar(result_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        xscroll.grid(row=1, column=0, sticky="ew")
        self.tree.configure(yscrollcommand=yscroll.set, xscrollcommand=xscroll.set)

        self.tree.tag_configure("ok", foreground="#1f7a1f")
        self.tree.tag_configure("limited", foreground="#9a6b00")
        self.tree.tag_configure("issue", foreground="#b22222")

        self.tree.bind("<<TreeviewSelect>>", self._on_select_result)
        self.tree.bind("<Motion>", self._on_tree_motion)
        self.tree.bind("<Leave>", lambda _e: self.tree_tooltip.hide())

        details_frame = ttk.LabelFrame(rf, text="Подробности", padding=8)
        details_frame.grid(row=2, column=0, sticky="nsew", pady=(10, 0))
        details_frame.columnconfigure(0, weight=1)
        details_frame.rowconfigure(0, weight=1)

        self.details_text = tk.Text(details_frame, wrap="word", height=12)
        self.details_text.grid(row=0, column=0, sticky="nsew")
        self.details_text.configure(state="disabled")
        details_scroll = ttk.Scrollbar(details_frame, orient=tk.VERTICAL, command=self.details_text.yview)
        details_scroll.grid(row=0, column=1, sticky="ns")
        self.details_text.configure(yscrollcommand=details_scroll.set)
        self.details_text.bind("<Motion>", self._on_details_motion)
        self.details_text.bind("<Leave>", lambda _e: self.details_tooltip.hide())

        self._set_details_text("Выберите строку в таблице, чтобы увидеть подробности по сайту.")

    def _clear_placeholder(self, _event=None):
        if self.site_entry.get().strip() == "site.com":
            self.site_entry.delete(0, tk.END)

    def _restore_placeholder(self, _event=None):
        if not self.site_entry.get().strip():
            self.site_entry.insert(0, "site.com")

    def _refresh_user_sites_box(self):
        self.user_sites_box.delete(0, tk.END)
        for site in self.user_sites:
            self.user_sites_box.insert(tk.END, site)
        self.path_var.set(f"Файл списка: {get_user_sites_path()}")

    def _reset_results(self):
        self.all_results.clear()
        self.result_by_row.clear()
        for row_id in self.tree.get_children():
            self.tree.delete(row_id)
        self._set_details_text("Выберите строку в таблице, чтобы увидеть подробности по сайту.")
        self.progress_var.set(0)
        self.tree_tooltip.hide()
        self.details_tooltip.hide()

    def _set_details_text(self, text: str):
        self.details_text.configure(state="normal")
        self.details_text.delete("1.0", tk.END)
        self.details_text.insert("1.0", text)
        self.details_text.configure(state="disabled")

    def _row_tag_for_result(self, result: SiteResult) -> str:
        verdict = result.verdict.lower()
        if verdict.startswith("доступен ✅"):
            if "ограничен" in verdict:
                return "limited"
            return "ok"
        return "issue"

    def _matches_filter(self, result: SiteResult) -> bool:
        if not self.show_only_issues.get():
            return True
        return not result.verdict.lower().startswith("доступен ✅")

    def _render_result_row(self, result: SiteResult):
        values = (
            result.label,
            result.host,
            result.ip,
            f"{result.dns_status} | {result.dns_time}",
            f"{result.ssl_status} | {result.ssl_time}",
            f"{result.http_status} | {result.http_time}",
            result.dpi_download_status,
            result.verdict,
        )
        row_id = self.tree.insert("", tk.END, values=values, tags=(self._row_tag_for_result(result),))
        self.result_by_row[row_id] = result
        return row_id

    def _append_result(self, result: SiteResult):
        self.all_results.append(result)
        if self._matches_filter(result):
            self._render_result_row(result)

    def _refresh_tree_from_results(self):
        selected_result = None
        selected = self.tree.selection()
        if selected:
            selected_result = self.result_by_row.get(selected[0])

        for row_id in self.tree.get_children():
            self.tree.delete(row_id)
        self.result_by_row.clear()

        selected_row = None
        for result in self.all_results:
            if self._matches_filter(result):
                row_id = self._render_result_row(result)
                if selected_result is result:
                    selected_row = row_id

        if selected_row:
            self.tree.selection_set(selected_row)
            self.tree.see(selected_row)
        elif self.tree.get_children():
            first = self.tree.get_children()[0]
            self.tree.selection_set(first)
            self._on_select_result()
        else:
            self._set_details_text("Нет строк, подходящих под текущий фильтр.")

    def _format_result_details(self, result: SiteResult) -> str:
        return (
            f"Метка:      {result.label}\n"
            f"ID:         {result.site_id}\n"
            f"Провайдер:  {result.provider or '—'}\n"
            f"Страна:     {result.country or '—'}\n"
            f"URL:        {result.url}\n"
            f"Хост:       {result.host}\n"
            f"IP:         {result.ip}\n"
            f"Локация:    {result.location}\n\n"
            f"DNS:        {result.dns_status}, {result.dns_time}\n"
            f"TLS 1.3:    {result.tls13_status}\n"
            f"TLS 1.2:    {result.tls12_status}\n"
            f"SSL:        {result.ssl_status}, {result.ssl_time}\n"
            f"HTTP:       {result.http_status}, {result.http_time}\n"
            f"DPI (16KB): {result.dpi_download_status}\n\n"
            f"Вердикт:    {result.verdict}"
        )

    def _on_select_result(self, _event=None):
        selected = self.tree.selection()
        if not selected:
            return
        result = self.result_by_row.get(selected[0])
        if result:
            self._set_details_text(self._format_result_details(result))

    def _text_has_issue(self, text: str) -> bool:
        lowered = text.lower()
        success_markers = ["ok (", "ok ✅", "доступен ✅", "не проверено"]
        issue_markers = [
            "ошибка", "подмена", "blocked", "detected", "timeout", "nxdomain",
            "connection", "black-hole", "mitm", "refused", "aborted", "closed",
        ]
        if any(marker in lowered for marker in issue_markers):
            return True
        if any(marker in lowered for marker in success_markers):
            return False
        return False

    def _tooltip_verdict_text(self, result: SiteResult) -> str:
        return self._explain_text(f"Вердикт: {result.verdict}") or result.verdict


    def _tooltip_text_for_result_column(self, result: SiteResult, column_id: str) -> str:
        if column_id in {"#1", "#2", "#3", "#8"}:
            return self._tooltip_verdict_text(result)

        column_map = {
            "#4": result.dns_status,
            "#5": f"{result.tls13_status} {result.tls12_status} {result.ssl_status}",
            "#6": result.http_status,
            "#7": result.dpi_download_status,
        }
        text = column_map.get(column_id, "")
        if not text:
            return ""
        explanation = self._explain_text(text)
        if explanation:
            return explanation
        if self._text_has_issue(text):
            return text
        return self._tooltip_verdict_text(result)

    def _explain_text(self, text: str) -> str:
        lowered = text.lower()
        for key, explanation in TOOLTIP_HINTS.items():
            if key in lowered:
                return explanation
        return ""

    def _on_tree_motion(self, event):
        row_id = self.tree.identify_row(event.y)
        column_id = self.tree.identify_column(event.x)
        if not row_id or not column_id:
            self.tree_tooltip.hide()
            return

        result = self.result_by_row.get(row_id)
        if not result:
            self.tree_tooltip.hide()
            return

        explanation = self._tooltip_text_for_result_column(result, column_id)
        if explanation:
            self.tree_tooltip.show(explanation, event.x_root + 14, event.y_root + 12)
        else:
            self.tree_tooltip.hide()

    def _on_details_motion(self, event):
        try:
            index = self.details_text.index(f"@{event.x},{event.y}")
            line_start = f"{index} linestart"
            line_end = f"{index} lineend"
            line_text = self.details_text.get(line_start, line_end).strip()
        except tk.TclError:
            self.details_tooltip.hide()
            return

        explanation = self._explain_text(line_text)
        if not explanation and line_text.startswith(("Метка:", "ID:", "Провайдер:", "Страна:", "URL:", "Хост:", "IP:")):
            selected = self.tree.selection()
            if selected:
                result = self.result_by_row.get(selected[0])
                if result:
                    explanation = self._tooltip_verdict_text(result)
        if not explanation and self._text_has_issue(line_text):
            explanation = line_text
        if explanation:
            self.details_tooltip.show(explanation, event.x_root + 14, event.y_root + 12)
        else:
            self.details_tooltip.hide()

    def _on_filter_toggle(self):
        self._refresh_tree_from_results()

    def show_help_window(self):
        win = tk.Toplevel(self.root)
        win.title("Подробная справка")
        win.geometry("900x760")
        win.minsize(700, 520)
        win.columnconfigure(0, weight=1)
        win.rowconfigure(0, weight=1)

        text = tk.Text(win, wrap="word")
        text.grid(row=0, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(win, orient=tk.VERTICAL, command=text.yview)
        scroll.grid(row=0, column=1, sticky="ns")
        text.configure(yscrollcommand=scroll.set)
        text.insert("1.0", HELP_TEXT)
        text.configure(state="disabled")

    def open_sites_file(self):
        try:
            open_user_sites_file()
        except Exception as exc:
            messagebox.showerror("Ошибка", f"Не удалось открыть файл списка.\\n\\n{exc}")

    def add_and_check_site(self):
        raw = self.site_entry.get().strip()
        if not raw or raw == "site.com":
            messagebox.showinfo("Пустой ввод", "Введите адрес сайта, например: site.com")
            return
        try:
            url = normalize_url(raw)
        except ValueError as exc:
            messagebox.showerror("Некорректный адрес", str(exc))
            return

        if url not in self.user_sites:
            self.user_sites.append(url)
            save_user_sites(self.user_sites)
            self._refresh_user_sites_box()

        self.site_entry.delete(0, tk.END)
        self.site_entry.insert(0, "site.com")
        self._start_suite([url], "Проверка нового сайта")

    def run_standard_suite(self):
        self._start_suite(DEFAULT_TEST_SUITE, "Стандартная проверка")

    def run_user_suite(self):
        self.user_sites = load_user_sites()
        self._refresh_user_sites_box()
        if not self.user_sites:
            messagebox.showinfo("Мой список", "Список пуст. Добавьте хотя бы один сайт.")
            return
        self._start_suite(self.user_sites, "Проверка сайтов из моего списка")

    def stop_tests(self):
        if self.worker_thread and self.worker_thread.is_alive():
            self.stop_event.set()
            self.stats_var.set("Остановка теста... Завершаются уже начатые проверки.")
        else:
            self.stats_var.set("Нет активного теста.")

    def _set_running_state(self, is_running: bool):
        state_main = "disabled" if is_running else "normal"
        self.btn_standard.configure(state=state_main)
        self.btn_my_list.configure(state=state_main)
        self.btn_add_check.configure(state=state_main)
        self.site_entry.configure(state=state_main)
        self.btn_open_file.configure(state="normal")
        self.btn_help.configure(state="normal")
        self.btn_stop.configure(state="normal")

    def _start_suite(self, suite, title: str):
        if self.worker_thread and self.worker_thread.is_alive():
            messagebox.showwarning("Тест уже идет", "Сейчас уже выполняется тест. Сначала остановите его или дождитесь завершения.")
            return
        self._reset_results()
        self.stop_event.clear()
        self._set_running_state(True)
        self.stats_var.set(f"{title}: подготовка...")
        self.worker_thread = threading.Thread(target=self._worker_run_suite, args=(suite, title), daemon=True)
        self.worker_thread.start()

    def _worker_run_suite(self, suite, title: str):
        total = len(suite)
        self.ui_queue.put(("suite_started", {"title": title, "total": total}))
        completed = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(MAX_WORKERS, max(1, total))) as executor:
            future_map = {
                executor.submit(run_full_test_on_url, item, index, total): (index, item)
                for index, item in enumerate(suite)
            }
            try:
                for future in concurrent.futures.as_completed(future_map):
                    if self.stop_event.is_set():
                        for fut in future_map:
                            fut.cancel()
                        break
                    try:
                        result = future.result()
                        completed += 1
                        self.ui_queue.put(("result", {"result": result, "completed": completed, "total": total, "title": title}))
                    except Exception as exc:
                        completed += 1
                        index, item = future_map[future]
                        label = build_label(item if isinstance(item, dict) else {"id": f"USER-{index+1:02d}", "provider": "Пользовательский сайт"}, index, total)
                        fallback = SiteResult(
                            label=label,
                            site_id=f"ERR-{index+1:02d}",
                            provider=item.get("provider", "") if isinstance(item, dict) else "Пользовательский сайт",
                            country=item.get("country", "") if isinstance(item, dict) else "",
                            url=item["url"] if isinstance(item, dict) else str(item),
                            host=(item.get("host") if isinstance(item, dict) else None) or urlparse(item["url"] if isinstance(item, dict) else str(item)).hostname or "",
                            dns_status=f"Ошибка ({exc.__class__.__name__})",
                            dns_time="N/A",
                            ip="N/A",
                            location=item.get("country", "") if isinstance(item, dict) else "N/A",
                            tls13_status="N/A",
                            tls12_status="N/A",
                            ssl_status=f"Ошибка ({exc.__class__.__name__}) ❌",
                            ssl_time="N/A",
                            http_status=f"Ошибка ({exc.__class__.__name__}) ❌",
                            http_time="N/A",
                            dpi_download_status=f"Detected❗️ ({exc.__class__.__name__})",
                            verdict="Ошибка выполнения ❗️",
                        )
                        self.ui_queue.put(("result", {"result": fallback, "completed": completed, "total": total, "title": title}))
            finally:
                status = "stopped" if self.stop_event.is_set() else "done"
                self.ui_queue.put(("suite_finished", {"title": title, "completed": completed, "total": total, "status": status}))

    def _poll_ui_queue(self):
        try:
            while True:
                kind, payload = self.ui_queue.get_nowait()
                if kind == "suite_started":
                    total = payload["total"]
                    self.stats_var.set(f"{payload['title']}: 0 из {total}")
                    self.progress_var.set(0)
                elif kind == "result":
                    result = payload["result"]
                    self._append_result(result)
                    completed = payload["completed"]
                    total = payload["total"]
                    self.stats_var.set(f"{payload['title']}: {completed} из {total}")
                    self.progress_var.set((completed / total) * 100 if total else 0)
                elif kind == "suite_finished":
                    total = payload["total"]
                    completed = payload["completed"]
                    if payload["status"] == "stopped":
                        self.stats_var.set(f"{payload['title']}: остановлено ({completed} из {total})")
                    else:
                        self.stats_var.set(f"{payload['title']}: завершено ({completed} из {total})")
                    self.progress_var.set(100 if total and completed >= total else self.progress_var.get())
                    self._set_running_state(False)
                    if self.tree.get_children() and not self.tree.selection():
                        first = self.tree.get_children()[0]
                        self.tree.selection_set(first)
                        self.tree.see(first)
                        self._on_select_result()
        except queue.Empty:
            pass
        finally:
            self.root.after(120, self._poll_ui_queue)


def main():
    root = tk.Tk()
    try:
        root.iconname(APP_TITLE)
    except tk.TclError:
        pass
    app = DPIConnectivityApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
