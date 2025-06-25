
# 🚀 CIA OSINT Scraper Avanzado - v3.0 🚀

![FastAPI](https://img.shields.io/badge/FastAPI-async%20API-green)
![Playwright](https://img.shields.io/badge/Playwright-enabled-blue)
![Python](https://img.shields.io/badge/Python-3.9+-yellow)
![License](https://img.shields.io/badge/License-MIT-purple)
![Status](https://img.shields.io/badge/Status-Active-brightgreen)

---

## ✨ ¡Bienvenido al **CIA OSINT Scraper Avanzado**! ✨

Tu compañero perfecto para **desentrañar perfiles públicos de Telegram** con el poder del scraping híbrido:  
🌌 Una mezcla celestial de **HTML estático + JavaScript dinámico** para que no se te escape ni un dato.

---

## 💎 Características Estelares

| 🚀 Funcionalidad                     | 💡 Descripción                                       |
|------------------------------------|-----------------------------------------------------|
| **Scraping Híbrido**                | Combina BeautifulSoup + Playwright para máxima info |
| **Análisis Profundo de Enlaces**   | Obtiene IP, país y servidor de cada enlace detectado |
| **Detección de Datos Ocultos**     | Emails, teléfonos y coordenadas con regex mágica    |
| **Huella Digital Única**            | Genera hash SHA256 para identificar perfiles        |
| **Reportes Visuales**               | HTML moderno con diseño oscuro y apertura automática |
| **Randomización de User Agents**   | Para evitar bloqueos y ser lo más sigiloso posible  |
| **API RESTful rápida y escalable** | Con FastAPI y respuestas JSON limpias y claras       |

---

## 🔧 Requisitos Cósmicos

- Python 3.9 o superior  
- Instala las dependencias con:

```bash
pip install fastapi requests beautifulsoup4 playwright pdfkit
```

- Instala navegadores para Playwright:

```bash
playwright install
```

- Para reportes en PDF, instala `wkhtmltopdf` en tu sistema operativo  
- Navegador web para visualizar reportes generados automáticamente

---

## ⚡ Cómo ponerlo en órbita

1. Clona este repo o descarga el script.  
2. Instala dependencias y navegadores.  
3. Arranca el servidor FastAPI:

```bash
uvicorn OsintTelegram:app --reload
```

4. Visita en tu navegador o Postman:

```
http://127.0.0.1:8000/osint/{usuario}
```

Reemplaza `{usuario}` con el nombre de usuario público de Telegram que quieres escudriñar.

5. ¡Listo! Se abrirá un reporte detallado y estilizado con toda la info encontrada. 🌟

---

## 🌐 Endpoints Galácticos

| Método | Ruta              | Descripción                                   |
|--------|-------------------|-----------------------------------------------|
| GET    | `/`               | Mensaje bienvenida al API                      |
| GET    | `/osint/{usuario}`| Extrae y devuelve toda la info OSINT del perfil|

---

