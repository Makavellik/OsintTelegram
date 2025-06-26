from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
import requests
from bs4 import BeautifulSoup
import re
import hashlib
import socket
import time
import random
from urllib.parse import urlparse

from pathlib import Path
import webbrowser  # 👈 Añadido
import uuid
import html
import urllib
from fastapi.responses import HTMLResponse
import concurrent.futures
import asyncio
from playwright.async_api import async_playwright
import ssl
from ipaddress import ip_address, IPv4Address, IPv6Address

app = FastAPI(title="CIA OSINT Scraper Avanzado", version="v3.0")

# Lista de agentes actualizada y diversa
USER_AGENTS = [
    # Puedes ampliarla con más agentes modernos
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/116.0",
    "Mozilla/5.0 (Android 13; Mobile; rv:115.0) Gecko/115.0 Firefox/115.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.6 Mobile/15E148 Safari/604.1"
]

# Delay avanzado con variación más evasiva
def delay(min_delay=1.2, max_delay=4.2, jitter=0.15):
    base = random.uniform(min_delay, max_delay)
    final_delay = base + (random.uniform(-jitter, jitter))
    final_delay = max(0.5, final_delay)  # mínimo de seguridad
    print(f"[⏳ Delay simbiótico]: {final_delay:.2f} segundos")
    time.sleep(final_delay)

# Headers mejorados, únicos como asteroides con camuflaje
def get_random_headers():
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": random.choice([
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "application/json, text/javascript, */*; q=0.01"
        ]),
        "DNT": "1",
        "Connection": random.choice(["keep-alive", "close"]),
        "Referer": random.choice([
            "https://google.com",
            "https://duckduckgo.com",
            "https://bing.com",
            "https://search.brave.com"
        ]),
        "X-Request-ID": str(uuid.uuid4()),  # Encabezado evasivo único
        "Sec-Fetch-Site": random.choice(["cross-site", "same-origin", "none"]),
        "Accept-Language": random.choice([
            "es-ES,es;q=0.9,en;q=0.8",
            "en-US,en;q=0.9,es;q=0.8",
            "es-MX,es;q=0.9,en;q=0.6"
        ])
    }
    return headers

def get_ip_info(domain: str):
    """
    Obtiene información avanzada de IP y servidor a partir de un dominio.

    Retorna un diccionario con:
    - ip: dirección IP resuelta
    - pais: país asociado a la IP
    - servidor: info del servidor HTTP (header Server)
    - asn: número ASN (Autonomous System Number)
    - isp: proveedor de internet
    - tiempo_respuesta_dns: tiempo en segundos para resolver DNS
    - tiempo_respuesta_geo: tiempo en segundos para consulta geolocalización
    - error: mensaje de error, si ocurre alguno
    """
    resultado = {
        "ip": None,
        "pais": "Desconocido",
        "servidor": "Desconocido",
        "asn": "Desconocido",
        "isp": "Desconocido",
        "tiempo_respuesta_dns": None,
        "tiempo_respuesta_geo": None,
        "error": None
    }

    try:
        # Medir tiempo para resolución DNS
        t0 = time.perf_counter()
        ip = socket.gethostbyname(domain)
        t1 = time.perf_counter()
        resultado["ip"] = ip
        resultado["tiempo_respuesta_dns"] = round(t1 - t0, 4)

        # Consulta info geográfica y ASN vía ip-api.com con más campos
        t2 = time.perf_counter()
        response = requests.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "country,isp,as"},
            timeout=6
        )
        t3 = time.perf_counter()
        geo = response.json()

        if geo.get("country"):
            resultado["pais"] = geo["country"]
        if geo.get("isp"):
            resultado["isp"] = geo["isp"]
        if geo.get("as"):
            resultado["asn"] = geo["as"]

        resultado["tiempo_respuesta_geo"] = round(t3 - t2, 4)

        # Obtener headers HTTP para saber servidor
        # Usamos requests.head con timeout y seguimiento de redirección
        head_resp = requests.head(f"http://{domain}", timeout=6, allow_redirects=True)
        if 'Server' in head_resp.headers:
            resultado["servidor"] = head_resp.headers['Server']

    except Exception as e:
        resultado["error"] = f"{type(e).__name__}: {str(e)}"

    return resultado


def buscar_datos_ocultos(texto: str):
    """
    Escaneo simbiótico de texto para revelar información oculta, evasiva o sensible:
    - Emails, incluso disfrazados (at, dot).
    - Teléfonos internacionales en múltiples formatos.
    - Coordenadas en decimal y DMS (convierte DMS a decimal).
    - URLs clásicas y ofuscadas.
    - Perfiles sociales y huellas digitales extendidas.
    """

    def desofuscar(texto):
        # Limpieza básica simbiótica
        texto = html.unescape(texto)
        texto = urllib.parse.unquote_plus(texto)
        texto = texto.replace('[at]', '@').replace('(at)', '@').replace(' at ', '@')
        texto = texto.replace('[dot]', '.').replace('(dot)', '.').replace(' dot ', '.')
        return texto

    texto_limpio = desofuscar(texto.lower())

    resultado = {
        "emails": set(),
        "telefonos": set(),
        "coordenadas_posibles": set(),
        "urls": set(),
        "redes_sociales": set()
    }

    try:
        # --- Email detection ---
        email_regex = re.compile(r'\b[\w\.-]+@[\w\.-]+\.\w{2,6}\b')
        resultado["emails"].update(email_regex.findall(texto_limpio))

        # --- Teléfonos internacionales ---
        telefono_regex = re.compile(
            r'(\+?\d{1,3}[\s.-]?)?(\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{3,4}[\s.-]?\d{0,4}'
        )
        for match in telefono_regex.findall(texto_limpio):
            tel = ''.join(match)
            tel = re.sub(r'[^\d+]', '', tel)
            if 7 <= len(re.sub(r'\D', '', tel)) <= 15:
                resultado["telefonos"].add(tel)

        # --- Coordenadas GPS ---
        decimal_coord = re.compile(
            r'([-+]?\d{1,2}\.\d+)[,\s]+([-+]?\d{1,3}\.\d+)'  # lat, long
        )
        dms_coord = re.compile(
            r'(\d{1,3})[°\s]+(\d{1,2})[\'\s]+(\d{1,2}(?:\.\d+)?)[\"\s]*([NS])[,;\s]*'
            r'(\d{1,3})[°\s]+(\d{1,2})[\'\s]+(\d{1,2}(?:\.\d+)?)[\"\s]*([EW])',
            re.IGNORECASE
        )

        for lat, lon in decimal_coord.findall(texto_limpio):
            resultado["coordenadas_posibles"].add(f"{lat},{lon}")

        # Conversión de DMS a decimal
        def dms_to_decimal(d, m, s, direction):
            val = float(d) + float(m)/60 + float(s)/3600
            return -val if direction.upper() in ['S', 'W'] else val

        for match in dms_coord.findall(texto_limpio):
            lat_d, lat_m, lat_s, lat_dir, lon_d, lon_m, lon_s, lon_dir = match
            lat = dms_to_decimal(lat_d, lat_m, lat_s, lat_dir)
            lon = dms_to_decimal(lon_d, lon_m, lon_s, lon_dir)
            resultado["coordenadas_posibles"].add(f"{lat:.6f},{lon:.6f}")

        # --- URLs (normales y camufladas) ---
        url_regex = re.compile(
            r'((https?|ftp):\/\/[^\s/$.?#].[^\s]*)|(?:www\.[a-z0-9\-]+\.[a-z]{2,})',
            re.IGNORECASE
        )
        resultado["urls"].update(match[0] for match in url_regex.findall(texto_limpio) if match[0])

        # --- Redes sociales comunes ---
        redes_regex = re.compile(
            r'(?:https?://)?(?:www\.)?'
            r'(twitter|instagram|facebook|linkedin|tiktok|github|telegram)\.com/[A-Za-z0-9_\-\.]+',
            re.IGNORECASE
        )
        resultado["redes_sociales"].update(redes_regex.findall(texto_limpio))

    except Exception as e:
        print(f"[ERROR simbiótico]: {e}")

    # Convert sets to ordered lists
    return {k: sorted(list(v)) for k, v in resultado.items()}


_cache_geo = {}

def _get_geo_info(ip, max_retries=3, delay=1):
    if ip in _cache_geo:
        return _cache_geo[ip]
    for attempt in range(max_retries):
        try:
            url = f"http://ip-api.com/json/{ip}?fields=status,country,org,as,isp,query,message"
            r = requests.get(url, timeout=5)
            r.raise_for_status()
            data = r.json()
            if data.get("status") == "success":
                _cache_geo[ip] = data
                return data
            else:
                time.sleep(delay)
        except Exception:
            time.sleep(delay)
    return {"status": "fail", "message": "No se pudo obtener info geolocalización"}

def _get_ssl_info(domain, timeout=5):
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                fecha_exp = cert.get("notAfter")
                fecha_inicio = cert.get("notBefore")
                issuer = dict(x[0] for x in cert.get("issuer", ()))
                return {
                    "issuer": issuer.get("organizationName", "Desconocido"),
                    "fecha_inicio": fecha_inicio,
                    "fecha_expiracion": fecha_exp
                }
    except Exception:
        return {}

def analizar_enlaces(links: list):
    """
    Escanea y analiza lista de URLs enfocada en Telegram (t.me),
    resolviendo IP, DNS, SSL y geolocalización para enlaces externos.
    Retorna lista dict con info extendida para cada URL.
    """
    def analizar_link(link):
        resultado = {
            "url": link,
            "esquema": None,
            "dominio": None,
            "puerto": None,
            "subdominio": None,
            "tipo_telegram": None,  # canal, grupo, bot, usuario, desconocido
            "ips": [],
            "info_ip": {
                "pais": "Desconocido",
                "servidor": "Desconocido",
                "organizacion": "Desconocida",
                "asn": "Desconocido",
                "error": None
            },
            "info_ssl": {},
            "error": None
        }
        try:
            parsed = urlparse(link)
            domain = parsed.hostname
            resultado["esquema"] = parsed.scheme or "http"
            resultado["puerto"] = parsed.port
            if not domain:
                raise ValueError("Dominio vacío o inválido")

            domain = domain.lower().strip()
            resultado["dominio"] = domain

            # Detectar subdominio
            parts = domain.split('.')
            if len(parts) > 2:
                resultado["subdominio"] = ".".join(parts[:-2])

            # Detectar si es enlace Telegram y tipo
            if domain.endswith("t.me"):
                path = parsed.path.lower()
                if path.startswith("/joinchat") or "joinchat" in path:
                    resultado["tipo_telegram"] = "grupo/entrada"
                elif path.startswith("/bot") or "/bot" in path:
                    resultado["tipo_telegram"] = "bot"
                elif path.count('/') == 1 and len(path) > 1:
                    resultado["tipo_telegram"] = "usuario/canal"
                else:
                    resultado["tipo_telegram"] = "desconocido"
            else:
                resultado["tipo_telegram"] = "externo"

            # Para enlaces internos Telegram no se resuelven IPs, solo metadata básica
            if resultado["tipo_telegram"] == "externo":
                # Resolver IPs (IPv4 + IPv6)
                try:
                    info_dns = socket.getaddrinfo(domain, None)
                    ips = set()
                    for res in info_dns:
                        ip = res[4][0]
                        try:
                            ip_obj = ip_address(ip)
                            if isinstance(ip_obj, (IPv4Address, IPv6Address)):
                                ips.add(ip)
                        except ValueError:
                            pass
                    resultado["ips"] = sorted(list(ips))
                except Exception as dns_e:
                    resultado["info_ip"]["error"] = f"DNS Error: {dns_e}"

                # Info geolocalización y organización para primera IP válida
                if resultado["ips"]:
                    ip = resultado["ips"][0]
                    geo_resp = _get_geo_info(ip)
                    if geo_resp.get("status") == "success":
                        resultado["info_ip"]["pais"] = geo_resp.get("country", "Desconocido")
                        resultado["info_ip"]["organizacion"] = geo_resp.get("org", geo_resp.get("isp", "Desconocida"))
                        resultado["info_ip"]["asn"] = geo_resp.get("as", "Desconocido")
                        resultado["info_ip"]["servidor"] = geo_resp.get("isp", "Desconocido")
                    else:
                        resultado["info_ip"]["error"] = f"GeoError: {geo_resp.get('message', 'Unknown error')}"
                else:
                    resultado["info_ip"]["error"] = "No se encontraron IPs para el dominio"

                # Info SSL si esquema HTTPS
                if resultado["esquema"] == "https":
                    ssl_info = _get_ssl_info(domain)
                    resultado["info_ssl"] = ssl_info
            else:
                # Telegram interno, evitamos DNS y SSL para evitar errores y ahorrar tiempo
                resultado["info_ip"]["pais"] = "Interno Telegram"
                resultado["info_ip"]["organizacion"] = "Telegram Messenger"
                resultado["info_ip"]["asn"] = "AS7922"
                resultado["info_ip"]["servidor"] = "Telegram Server"
                resultado["ips"] = []

        except Exception as e:
            resultado["error"] = str(e)

        return resultado

    resultados = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(analizar_link, link) for link in links]
        for future in concurrent.futures.as_completed(futures):
            resultados.append(future.result())

    return resultados


def extraer_info_tecnica(soup):
    """
    Extrae info técnica ultra avanzada de un objeto BeautifulSoup:
    - Meta tags con todos sus atributos posibles (name, property, charset, http-equiv, etc)
    - Scripts inline cortos y largos, además de scripts externos (src)
    - JSON embebido en scripts (application/ld+json y otros)
    - Links técnicos: CSS, favicons, preloads, fuentes
    - Estilos CSS inline y <style> embebidos
    - Atributos ocultos (data-*, aria-*, hidden, estilos display:none, visibilidad oculta)
    - Iframes y su análisis (src, sandbox, título)
    - Estadísticas y registro de errores
    """

    meta = {}
    scripts_inline = []
    scripts_externos = []
    json_embebido = []
    links_tecnicos = []
    estilos_inline = []
    atributos_ocultos = []
    iframes_info = []
    errores_log = []

    try:
        # --- Meta tags extendidos ---
        for m in soup.find_all("meta"):
            try:
                attrs = {k: v for k, v in m.attrs.items()}
                key = None
                content = attrs.get("content", "")

                # Prioridad para key que identifique el meta tag
                if "name" in attrs:
                    key = f"name:{attrs['name'].strip()}"
                elif "property" in attrs:
                    key = f"property:{attrs['property'].strip()}"
                elif "charset" in attrs:
                    key = "charset"
                    content = attrs["charset"]
                elif "http-equiv" in attrs:
                    key = f"http-equiv:{attrs['http-equiv'].strip()}"
                else:
                    # Clave fallback: usar todos los atributos para identificar
                    key = "meta:" + ",".join(f"{k}={v}" for k, v in attrs.items())

                meta[key] = content.strip() if isinstance(content, str) else str(content)
            except Exception as e:
                errores_log.append(f"Meta tag error: {str(e)}")

        # --- Scripts ---
        for s in soup.find_all("script"):
            try:
                # Script externo con src
                if s.has_attr("src"):
                    src = s["src"]
                    if src and src.strip():
                        scripts_externos.append(src.strip())
                else:
                    # Script inline
                    if s.string:
                        txt = s.string.strip()
                        if txt:
                            scripts_inline.append(txt)
                    else:
                        # Script sin texto (posible script vacío o dinámico)
                        scripts_inline.append("[script sin texto o contenido dinámico]")
            except Exception as e:
                errores_log.append(f"Script parsing error: {str(e)}")

        # --- JSON embebido en scripts ---
        for s in soup.find_all("script", {"type": ["application/ld+json", "application/json"]}):
            try:
                if s.string:
                    json_embebido.append(s.string.strip())
            except Exception as e:
                errores_log.append(f"JSON embebido error: {str(e)}")

        # --- Links técnicos ---
        for link in soup.find_all("link", href=True):
            try:
                rel = link.get("rel")
                href = link.get("href")
                if rel:
                    rel_str = ','.join(rel).lower()
                    if any(x in rel_str for x in ["stylesheet", "icon", "shortcut icon", "preload", "dns-prefetch", "prefetch", "preconnect", "font"]):
                        links_tecnicos.append({"rel": rel_str, "href": href})
            except Exception as e:
                errores_log.append(f"Link técnico error: {str(e)}")

        # --- Estilos inline en etiquetas style ---
        for style_tag in soup.find_all("style"):
            try:
                if style_tag.string:
                    estilos_inline.append(style_tag.string.strip())
            except Exception as e:
                errores_log.append(f"Estilo inline error: {str(e)}")

        # --- Atributos ocultos y data-attributes ---
        for tag in soup.find_all(True):
            try:
                ocultos = {}
                # Buscar atributos data-* y aria-*
                for attr, val in tag.attrs.items():
                    if attr.startswith("data-") or attr.startswith("aria-"):
                        ocultos[attr] = val
                # Detectar ocultamiento por CSS inline o atributo hidden
                style = tag.get("style", "").lower()
                if "display:none" in style or "visibility:hidden" in style or tag.has_attr("hidden"):
                    ocultos["oculto_por_css_o_hidden"] = True
                if ocultos:
                    atributos_ocultos.append({
                        "tag": tag.name,
                        "attrs_ocultos": ocultos,
                        "texto": tag.text.strip()[:60]  # extracto para contexto
                    })
            except Exception as e:
                errores_log.append(f"Atributos ocultos error: {str(e)}")

        # --- Iframes ---
        for iframe in soup.find_all("iframe"):
            try:
                src = iframe.get("src", "")
                sandbox = iframe.get("sandbox", None)
                title = iframe.get("title", "")
                iframes_info.append({
                    "src": src,
                    "sandbox": sandbox,
                    "title": title
                })
            except Exception as e:
                errores_log.append(f"Iframe parsing error: {str(e)}")

    except Exception as e:
        errores_log.append(f"Error general en extraer_info_tecnica: {str(e)}")

    return {
        "meta_tags": meta,
        "scripts_inline": scripts_inline,
        "scripts_externos": scripts_externos,
        "json_embebido": json_embebido,
        "links_tecnicos": links_tecnicos,
        "estilos_inline": estilos_inline,
        "atributos_ocultos": atributos_ocultos,
        "iframes_info": iframes_info,
        "estadisticas": {
            "total_meta": len(meta),
            "total_scripts_inline": len(scripts_inline),
            "total_scripts_externos": len(scripts_externos),
            "total_json_embebido": len(json_embebido),
            "total_links_tecnicos": len(links_tecnicos),
            "total_estilos_inline": len(estilos_inline),
            "total_atributos_ocultos": len(atributos_ocultos),
            "total_iframes": len(iframes_info),
            "errores": errores_log
        }
    }


def crear_hash_perfil(data):
    base = ''.join([str(v) for v in data.values()])
    return hashlib.sha256(base.encode()).hexdigest()


async def extraer_dinamico_playwright(usuario: str):
    resultado = {
        "nombre_renderizado": None,
        "extra_info": None,
        "ultimos_mensajes": [],
        "foto_perfil_renderizada": None,
        "seguidores": None,
        "ultimo_post_tiempo": None,
        "enlaces_dinamicos": [],
        "imagenes": [],
        "videos": [],
        "scripts_embebidos": [],
        "json_embebido": [],
        "estilos_css": [],
        "atributos_ocultos": {},
        "xhr_fetch_requests": [],
        "shadow_dom_textos": [],
        "iframes_src": [],
        "error": None
    }

    for intento in range(1, 4):  # 3 intentos por si falla la carga
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                context = await browser.new_context()
                page = await context.new_page()

                # Capturar URLs de peticiones XHR/fetch (útiles para APIs ocultas)
                page.on("request", lambda request: 
                    resultado["xhr_fetch_requests"].append(request.url)
                    if request.resource_type in ["xhr", "fetch"] else None
                )

                await page.goto(f"https://t.me/{usuario}", timeout=20000)
                await page.wait_for_timeout(5000)  # Esperar carga dinámica

                # Extraer nombre renderizado
                try:
                    resultado["nombre_renderizado"] = await page.inner_text(".tgme_page_title")
                except: pass

                # Extra info (seguidores, estado, etc)
                try:
                    resultado["extra_info"] = await page.inner_text(".tgme_page_extra")
                except: pass

                # Extraer últimos mensajes (máximo 10)
                try:
                    mensajes = await page.query_selector_all(".tgme_widget_message_text")
                    for m in mensajes[:10]:
                        texto = await m.inner_text()
                        resultado["ultimos_mensajes"].append(texto)
                except: pass

                # Foto perfil (background-image o img)
                try:
                    foto_style = await page.get_attribute(".tgme_page_photo_image", "style")
                    match = re.search(r"url\(['\"]?(.*?)['\"]?\)", foto_style or "")
                    if match:
                        ruta = match.group(1)
                        resultado["foto_perfil_renderizada"] = (
                            "https:" + ruta if ruta.startswith("//") else ruta
                        )
                    else:
                        img_elem = await page.query_selector(".tgme_page_photo_image img")
                        if img_elem:
                            src = await img_elem.get_attribute("src")
                            resultado["foto_perfil_renderizada"] = src
                except: pass

                # Seguidores (cuando aparece en .tgme_page_extra o similar)
                try:
                    seguidores_text = await page.inner_text(".tgme_page_extra")
                    resultado["seguidores"] = seguidores_text
                except: pass

                # Último post - tiempo y fecha
                try:
                    ultimo_post = await page.query_selector(".tgme_widget_message_date time")
                    if ultimo_post:
                        resultado["ultimo_post_tiempo"] = await ultimo_post.get_attribute("datetime")
                except: pass

                # Enlaces detectados (solo http/https)
                try:
                    enlaces = await page.query_selector_all("a")
                    for enlace in enlaces:
                        href = await enlace.get_attribute("href")
                        if href and href.startswith("http") and href not in resultado["enlaces_dinamicos"]:
                            resultado["enlaces_dinamicos"].append(href)
                except: pass

                # Imágenes (src de todas las imágenes visibles)
                try:
                    imgs = await page.query_selector_all("img")
                    for img in imgs:
                        src = await img.get_attribute("src")
                        if src and src not in resultado["imagenes"]:
                            resultado["imagenes"].append(src)
                except: pass

                # Videos (src de videos visibles)
                try:
                    videos = await page.query_selector_all("video")
                    for video in videos:
                        src = await video.get_attribute("src")
                        if src and src not in resultado["videos"]:
                            resultado["videos"].append(src)
                except: pass

                # Scripts embebidos sin src (contenido JS inline)
                try:
                    scripts = await page.query_selector_all("script:not([src])")
                    for script in scripts:
                        contenido = await script.inner_text()
                        if contenido and contenido.strip() and contenido not in resultado["scripts_embebidos"]:
                            resultado["scripts_embebidos"].append(contenido.strip())
                except: pass

                # JSON embebido tipo application/ld+json (datos estructurados)
                try:
                    json_scripts = await page.query_selector_all('script[type="application/ld+json"]')
                    for js in json_scripts:
                        contenido = await js.inner_text()
                        if contenido and contenido.strip() and contenido not in resultado["json_embebido"]:
                            resultado["json_embebido"].append(contenido.strip())
                except: pass

                # Estilos CSS embebidos
                try:
                    styles = await page.query_selector_all("style")
                    for style in styles:
                        css_text = await style.inner_text()
                        if css_text and css_text.strip() and css_text not in resultado["estilos_css"]:
                            resultado["estilos_css"].append(css_text.strip())
                except: pass

                # Atributos ocultos (data-*, aria-*)
                try:
                    elementos = await page.query_selector_all("div, span, section, article")
                    for elem in elementos:
                        attrs = await elem.evaluate("(el) => { const result = {}; for(const attr of el.attributes) { if(attr.name.startsWith('data-') || attr.name.startsWith('aria-')) result[attr.name] = attr.value; } return result; }")
                        if attrs:
                            for k,v in attrs.items():
                                resultado["atributos_ocultos"][k] = v
                except: pass

                # Shadow DOM textos (info oculta en sombras del DOM)
                try:
                    shadow_texts = await page.evaluate("""() => {
                        const results = [];
                        function extractShadow(root) {
                            if(!root) return;
                            if(root.shadowRoot) {
                                const shadow = root.shadowRoot;
                                results.push(shadow.innerText || "");
                                shadow.querySelectorAll("*").forEach(extractShadow);
                            }
                        }
                        document.querySelectorAll("*").forEach(extractShadow);
                        return results.filter(r => r.length > 0);
                    }""")
                    if shadow_texts and isinstance(shadow_texts, list):
                        resultado["shadow_dom_textos"].extend(shadow_texts)
                except: pass

                # Iframes (src para posibles fuentes incrustadas)
                try:
                    iframes = await page.query_selector_all("iframe")
                    for iframe in iframes:
                        src = await iframe.get_attribute("src")
                        if src and src not in resultado["iframes_src"]:
                            resultado["iframes_src"].append(src)
                except: pass

                await browser.close()
                break  # éxito, salir del retry

        except Exception as e:
            resultado["error"] = f"Error general en intento {intento}: {str(e)}"
            await asyncio.sleep(2)

    return resultado


async def extraer_perfil_telegram(usuario: str):
    # --- Validación extendida y segura del alias ---
    if not re.match(r"^[a-zA-Z0-9_]{5,32}$", usuario):
        raise HTTPException(status_code=400, detail="❌ Username inválido. Solo letras, números y _ (5-32 caracteres)")

    url = f"https://t.me/{usuario}"
    delay()  # Simula comportamiento humano para evitar bloqueos

    # Intentos y manejo de errores robusto
    try:
        headers = get_random_headers()
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code != 200:
            raise HTTPException(status_code=404, detail=f"⚠️ Usuario no accesible ({response.status_code})")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"❌ Error al acceder a Telegram: {str(e)}")

    soup = BeautifulSoup(response.text, "html.parser")

    # --- Extracción base ---
    nombre_tag = soup.select_one(".tgme_page_title")
    bio_tag = soup.select_one(".tgme_page_description")
    nombre_texto = nombre_tag.text.strip() if nombre_tag else "Desconocido"
    bio_texto = bio_tag.text.strip() if bio_tag else "Sin biografía"

    # --- Foto perfil (con fallback) ---
    foto_url = "No disponible"
    try:
        style_attr = soup.select_one(".tgme_page_photo_image")["style"]
        match = re.search(r"url\(['\"]?(.*?)['\"]?\)", style_attr)
        if match:
            ruta = match.group(1)
            foto_url = "https:" + ruta if ruta.startswith("//") else ruta
    except Exception:
        pass

    # --- Multimedia detectada: imágenes, videos, iframes ---
    imagenes = [img['src'] for img in soup.find_all("img") if img.has_attr("src")]
    videos = [video['src'] for video in soup.find_all("video") if video.has_attr("src")]
    iframes_src = [iframe['src'] for iframe in soup.find_all("iframe") if iframe.has_attr("src")]

    # --- Enlaces visibles en texto y bio ---
    texto_crudo = soup.get_text(separator=" ")
    enlaces_visibles = set(re.findall(r'https?://[^\s\'"<>]+', texto_crudo))
    enlaces_bio = set(re.findall(r'https?://[^\s\'"<>]+', bio_texto)) if bio_texto else set()
    todos_los_enlaces = list(enlaces_visibles.union(enlaces_bio))

    # --- 🔍 Detección profunda con análisis avanzado ---
    datos_ocultos = buscar_datos_ocultos(texto_crudo + " " + bio_texto)

    # --- Información técnica, CSS, scripts, shadow DOM y atributos ocultos ---
    info_tecnica = extraer_info_tecnica(soup)

    # --- Análisis detallado de enlaces ---
    info_enlaces = analizar_enlaces(todos_los_enlaces)

    # --- Extracción dinámica usando Playwright (JS, carga dinámica, etc) ---
    info_dinamica = await extraer_dinamico_playwright(usuario)

    # --- Fingerprint ultra seguro con todos los datos relevantes ---
    datos_fingerprint = {
        "nombre": nombre_texto,
        "bio": bio_texto,
        "foto": foto_url,
        "emails": datos_ocultos.get("emails", []),
        "telefonos": datos_ocultos.get("telefonos", []),
        "enlaces": todos_los_enlaces,
        "extra_info_js": info_dinamica.get("extra_info"),
        "ultimos_mensajes": info_dinamica.get("ultimos_mensajes", []),
    }
    huella_sha256 = crear_hash_perfil(datos_fingerprint)

    # --- Reporte completo, incluye todo el universo ---
    perfil = {
        "usuario": usuario,
        "nombre": nombre_texto,
        "biografia": bio_texto,
        "foto_perfil": foto_url,
        "imagenes_detectadas": imagenes,
        "videos_detectados": videos,
        "iframes_src": iframes_src,
        "enlaces_detectados": todos_los_enlaces,
        "info_enlaces": info_enlaces,
        "datos_ocultos": datos_ocultos,
        "huella_sha256": huella_sha256,
        "info_tecnica_oculta": info_tecnica,
        "info_dinamica_js": info_dinamica,
        "timestamp": time.ctime(),
        "metodo": "Scraping híbrido ultra-avanzado (HTML + JS con Playwright + análisis profundo)",
    }

    # --- Genera reporte visual tipo hacker simbiotico ---
    generar_html_reporte(usuario, perfil)

    return perfil


def generar_html_reporte(usuario, perfil):
    import time, re, webbrowser
    from pathlib import Path

    info_enlaces = re.sub(r"[\\[\\]']", '', str(perfil['info_enlaces']))
    datos_ocultos = re.sub(r"[\\[\\]']", '', str(perfil['datos_ocultos']))
    info_tecnica = re.sub(r"[\\[\\]']", '', str(perfil['info_tecnica_oculta']))
    info_dinamica = re.sub(r"[\\[\\]']", '', str(perfil['info_dinamica_js']))

    html = f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8" />
<title>Reporte OSINT – {usuario}</title>

<style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&display=swap');

    /* Reset */
    * {{
        margin: 0;
        padding: 0;
        box-sizing: border-box;
    }}

    body {{
        font-family: 'Share Tech Mono', monospace;
        background: radial-gradient(circle at center, #000010, #000000);
        color: #00ffcc;
        overflow-x: hidden;
        position: relative;
        min-height: 100vh;
        padding: 2rem 1rem;
    }}

    /* Canvas para partículas */
    #canvas {{
        position: fixed;
        top: 0; left: 0;
        width: 100%;
        height: 100%;
        z-index: -1;
        pointer-events: none;
    }}

    /* Header */
    header {{
        text-align: center;
        margin-bottom: 2rem;
        animation: glowPulse 3s ease-in-out infinite alternate;
    }}

    @keyframes glowPulse {{
        0% {{ text-shadow: 0 0 8px #00ffcc, 0 0 20px #00ffcc; }}
        100% {{ text-shadow: 0 0 20px #00ffee, 0 0 40px #00ffee; }}
    }}

    header h1 {{
        font-size: 3rem;
        user-select: none;
    }}

    header p {{
        font-size: 1.1rem;
        color: #00ccaaaa;
        font-style: italic;
        margin-top: 0.5rem;
    }}

    /* Secciones */
    .seccion {{
        background: rgba(0, 255, 204, 0.1);
        border-left: 6px solid #00ffcc;
        border-radius: 15px;
        margin-bottom: 2.5rem;
        padding: 1.5rem 2rem;
        box-shadow:
            0 0 25px #00ffcc44,
            inset 0 0 15px #00ffaa88;
        transition: box-shadow 0.3s ease;
        backdrop-filter: saturate(180%) blur(8px);
        /* Removemos overflow para evitar scroll interno */
        /* overflow-x: auto; */
        word-wrap: break-word;
        white-space: normal;
    }}

    .seccion:hover {{
        box-shadow:
            0 0 50px #00ffeecc,
            inset 0 0 30px #00ffeecc;
    }}

    /* Títulos de sección */
    .seccion h2 {{
        color: #00ffee;
        border-bottom: 2px solid #00ffee;
        padding-bottom: 0.3rem;
        margin-bottom: 1rem;
        user-select: none;
        letter-spacing: 1.2px;
        font-size: 1.9rem;
    }}

    /* Texto clave y valor */
    .clave {{
        font-weight: 700;
        color: #a0ffd6;
        user-select: text;
    }}

    .valor {{
        color: #c8fff5;
        white-space: normal;
        word-break: break-word;
        user-select: text;
    }}

    /* Foto perfil con animación */
    img {{
        border-radius: 15px;
        max-width: 150px;
        margin-top: 12px;
        border: 2px solid #00ffcc;
        box-shadow:
            0 0 30px #00ffcc88;
        transition: transform 0.4s ease, box-shadow 0.4s ease;
        cursor: pointer;
        user-select: none;
    }}

    img:hover {{
        transform: scale(1.15) rotate(4deg);
        box-shadow:
            0 0 60px #00ffeecc;
    }}

    /* Preformat para info */
    pre {{
        background: rgba(0, 255, 204, 0.15);
        border-radius: 12px;
        padding: 1rem;
        color: #00ffcc;
        font-size: 1rem;
        /* Eliminamos scroll horizontal */
        overflow-x: visible;
        white-space: normal;
        word-break: break-word;
        box-shadow: inset 0 0 15px #00ffaaaa;
        user-select: text;
    }}

    /* Footer */
    footer {{
        text-align: center;
        font-size: 0.9rem;
        color: #007766aa;
        margin-top: 3rem;
        user-select: none;
    }}

    /* Scrollbar personalizado */
    ::-webkit-scrollbar {{
        height: 10px;
        background: #001111;
    }}
    ::-webkit-scrollbar-thumb {{
        background: #00ffccaa;
        border-radius: 10px;
    }}

</style>
</head>
<body>

<canvas id="canvas"></canvas>

<header>
    <h1>🌐 CIA OSINT ByMakaveli – {usuario}</h1>
    <p>Reporte generado el {perfil['timestamp']}</p>
</header>

<div class="seccion">
    <p><span class="clave">👤 Nombre:</span> <span class="valor">{perfil['nombre']}</span></p>
    <p><span class="clave">📄 Bio:</span> <span class="valor">{perfil['biografia']}</span></p>
    <p><span class="clave">🔐 Huella SHA256:</span> <span class="valor">{perfil['huella_sha256']}</span></p>
    <p><span class="clave">🖼️ Foto:</span><br><img src="{perfil['foto_perfil']}" alt="Foto de perfil" /></p>
    <p><span class="clave">🧪 Método:</span> <span class="valor">{perfil['metodo']}</span></p>
</div>

<div class="seccion">
    <h2>🔗 Enlaces Detectados</h2>
    <pre>{info_enlaces}</pre>
</div>

<div class="seccion">
    <h2>📬 Datos Ocultos</h2>
    <pre>{datos_ocultos}</pre>
</div>

<div class="seccion">
    <h2>🧬 Info Técnica</h2>
    <pre>{info_tecnica}</pre>
</div>

<div class="seccion">
    <h2>🧠 Info Dinámica (JS)</h2>
    <pre>{info_dinamica}</pre>
</div>

<footer>
    CIA OSINT © {time.strftime("%Y")} | Unidos en código y energía ByMakaveli
</footer>

<script>
    // Configuración de partículas con efectos únicos y reacción al mouse
    const canvas = document.getElementById('canvas');
    const ctx = canvas.getContext('2d');

    let width, height;
    function resize() {{
        width = window.innerWidth;
        height = window.innerHeight;
        canvas.width = width * devicePixelRatio;
        canvas.height = height * devicePixelRatio;
        canvas.style.width = width + 'px';
        canvas.style.height = height + 'px';
        ctx.scale(devicePixelRatio, devicePixelRatio);
    }}
    resize();
    window.addEventListener('resize', resize);

    class Particle {{
        constructor() {{
            this.reset();
        }}
        reset() {{
            this.x = Math.random() * width;
            this.y = Math.random() * height;
            this.size = Math.random() * 2 + 1;
            this.speedX = (Math.random() - 0.5) * 0.6;
            this.speedY = (Math.random() - 0.5) * 0.6;
            this.opacity = Math.random() * 0.7 + 0.3;
            this.color = `hsl(180, 100%, ${{Math.floor(Math.random() * 40) + 60}}%)`;
        }}
        update(mouse) {{
            this.x += this.speedX;
            this.y += this.speedY;

            // Reacción al mouse cercano
            if (mouse.x !== null && mouse.y !== null) {{
                const dx = this.x - mouse.x;
                const dy = this.y - mouse.y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if (dist < 100) {{
                    this.x += dx / dist * 3;
                    this.y += dy / dist * 3;
                }}
            }}

            if (this.x > width) this.x = 0;
            else if (this.x < 0) this.x = width;
            if (this.y > height) this.y = 0;
            else if (this.y < 0) this.y = height;
        }}
        draw(ctx) {{
            ctx.beginPath();
            const gradient = ctx.createRadialGradient(this.x, this.y, 0, this.x, this.y, this.size*4);
            gradient.addColorStop(0, `rgba(0, 255, 204, ${{this.opacity}})`);
            gradient.addColorStop(1, 'rgba(0,255,204,0)');
            ctx.fillStyle = gradient;
            ctx.arc(this.x, this.y, this.size * 2, 0, Math.PI * 2);
            ctx.fill();
        }}
    }}

    const particles = [];
    const PARTICLE_COUNT = 130;
    for(let i = 0; i < PARTICLE_COUNT; i++) {{
        particles.push(new Particle());
    }}

    const mouse = {{ x: null, y: null }};
    window.addEventListener('mousemove', e => {{
        mouse.x = e.clientX;
        mouse.y = e.clientY;
    }});
    window.addEventListener('mouseout', e => {{
        mouse.x = null;
        mouse.y = null;
    }});

    function animate() {{
        ctx.clearRect(0, 0, width, height);

        // Dibuja líneas entre partículas cercanas
        for(let i = 0; i < PARTICLE_COUNT; i++) {{
            particles[i].update(mouse);
            particles[i].draw(ctx);

            for(let j = i + 1; j < PARTICLE_COUNT; j++) {{
                const dx = particles[i].x - particles[j].x;
                const dy = particles[i].y - particles[j].y;
                const dist = Math.sqrt(dx * dx + dy * dy);
                if(dist < 130) {{
                    ctx.beginPath();
                    ctx.strokeStyle = `rgba(0, 255, 204, ${{1 - dist/130}})`;
                    ctx.lineWidth = 1;
                    ctx.moveTo(particles[i].x, particles[i].y);
                    ctx.lineTo(particles[j].x, particles[j].y);
                    ctx.stroke();
                }}
            }}
        }}

        requestAnimationFrame(animate);
    }}
    animate();
</script>

</body>
</html>
"""

    ruta = Path(f"reporte_particulas_avanzado_{usuario}.html").resolve()
    ruta.write_text(html, encoding="utf-8")
    webbrowser.open(f"file://{ruta}")




@app.get("/", response_class=HTMLResponse)
async def index():
    html_conexion = """
    <!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <title>🜂 CIA OSINT Ultra 🜂</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@600&family=Share+Tech+Mono&display=swap');

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            background: black;
            overflow: hidden;
            color: #00ffe0;
            font-family: 'Share Tech Mono', monospace;
            display: flex;
            flex-direction: column;
            justify-content: center;
            align-items: center;
            height: 100vh;
            text-align: center;
            padding: 20px;
        }

        canvas {
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            z-index: 0;
        }

        h1 {
            font-family: 'Orbitron', sans-serif;
            font-size: 3rem;
            color: #00fff7;
            text-shadow: 0 0 10px #00ffff, 0 0 20px #00ffcc;
            margin-bottom: 20px;
            animation: pulse 3s infinite ease-in-out;
            z-index: 2;
        }

        p {
            max-width: 700px;
            margin-bottom: 1rem;
            line-height: 1.5;
            text-shadow: 0 0 5px #00ffcc;
            font-size: 1.1rem;
            z-index: 2;
        }

        code {
            background: rgba(0, 255, 200, 0.1);
            padding: 4px 8px;
            border-radius: 6px;
            color: #00ffee;
            font-family: monospace;
            z-index: 2;
        }

        footer {
            margin-top: 30px;
            font-size: 0.85rem;
            color: #55fff7;
            opacity: 0.6;
            z-index: 2;
        }

        @keyframes pulse {
            0%, 100% { transform: scale(1); }
            50% { transform: scale(1.03); }
        }
    </style>
</head>
<body>
    <canvas id="universe"></canvas>
    <h1>🜂 CIA OSINT Ultra ByMakveli 🜂</h1>
    <p>Bienvenido al núcleo simbiótico de inteligencia. Este sistema analiza usuarios, perfiles y patrones públicos.</p>
    <p>Para comenzar un escaneo, accede a: <br><code>/osint/&lt;usuario&gt;</code></p>
    <p>Ejemplo de uso: <code>/osint/johndoe</code></p>
    <footer>Versión 0.0 - ⚡</footer>

    <script>
        const canvas = document.getElementById('universe');
        const ctx = canvas.getContext('2d');
        canvas.width = window.innerWidth;
        canvas.height = window.innerHeight;

        class Star {
            constructor() {
                this.x = Math.random() * canvas.width;
                this.y = Math.random() * canvas.height;
                this.radius = Math.random() * 1.5;
                this.alpha = Math.random();
                this.speed = Math.random() * 0.3;
            }
            draw() {
                ctx.beginPath();
                ctx.fillStyle = `rgba(255, 255, 255, ${this.alpha})`;
                ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
                ctx.fill();
            }
            update() {
                this.y += this.speed;
                if (this.y > canvas.height) {
                    this.y = 0;
                    this.x = Math.random() * canvas.width;
                }
                this.draw();
            }
        }

        class Line {
            constructor(stars) {
                this.stars = stars;
            }
            draw() {
                for (let i = 0; i < this.stars.length - 1; i++) {
                    const a = this.stars[i];
                    const b = this.stars[i + 1];
                    const dx = a.x - b.x;
                    const dy = a.y - b.y;
                    const distance = Math.sqrt(dx * dx + dy * dy);
                    if (distance < 120) {
                        ctx.beginPath();
                        ctx.strokeStyle = 'rgba(0,255,255,0.1)';
                        ctx.moveTo(a.x, a.y);
                        ctx.lineTo(b.x, b.y);
                        ctx.stroke();
                    }
                }
            }
        }

        class DataGlyph {
            constructor() {
                this.reset();
            }
            reset() {
                this.x = Math.random() * canvas.width;
                this.y = Math.random() * canvas.height;
                this.char = String.fromCharCode(0x30A0 + Math.random() * 96);
                this.alpha = 0.3 + Math.random() * 0.7;
                this.size = 12 + Math.random() * 18;
                this.speed = 0.2 + Math.random() * 0.5;
            }
            draw() {
                ctx.font = `${this.size}px monospace`;
                ctx.fillStyle = `rgba(0,255,180,${this.alpha})`;
                ctx.fillText(this.char, this.x, this.y);
            }
            update() {
                this.y += this.speed;
                if (this.y > canvas.height) this.reset();
                this.draw();
            }
        }

        class Radar {
            constructor() {
                this.angle = 0;
                this.radius = 150;
            }
            draw() {
                ctx.save();
                ctx.translate(canvas.width - 200, 200);
                ctx.beginPath();
                ctx.arc(0, 0, this.radius, 0, Math.PI * 2);
                ctx.strokeStyle = 'rgba(0,255,0,0.3)';
                ctx.stroke();
                ctx.rotate(this.angle);
                ctx.beginPath();
                ctx.moveTo(0, 0);
                ctx.lineTo(this.radius, 0);
                ctx.strokeStyle = 'rgba(0,255,0,0.5)';
                ctx.stroke();
                ctx.restore();
                this.angle += 0.01;
            }
        }

        let stars = [];
        let glyphs = [];
        for (let i = 0; i < 300; i++) stars.push(new Star());
        for (let i = 0; i < 100; i++) glyphs.push(new DataGlyph());
        const lines = new Line(stars);
        const radar = new Radar();

        function animate() {
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            stars.forEach(s => s.update());
            lines.draw();
            glyphs.forEach(g => g.update());
            radar.draw();
            requestAnimationFrame(animate);
        }

        animate();
    </script>
</body>
</html>

    """
    return HTMLResponse(content=html_conexion)


@app.get("/osint/{usuario}")
async def analizar_usuario(usuario: str):
    resultado = await extraer_perfil_telegram(usuario)
    return JSONResponse(content=resultado)
