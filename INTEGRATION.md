# MediaWiki integration — Special:AuthorDB

This repo can run as a MediaWiki **Special Page** by embedding the FastAPI app in
an iframe behind a thin PHP extension, with single sign-on from MediaWiki accounts.

```
Browser ─ http://wiki.sst1m.science ──► MediaWiki ── Special:AuthorDB (PHP)
                                                       │  requireLogin + 'manage-authors' check
                                                       │  mints short-lived HMAC SSO token
                                                       ▼
   <iframe src="/authordb/sso?token=…"> ─reverse proxy (same origin)─► uvicorn (127.0.0.1:8489)
                                                       │  /sso validates token → admin session → / (Home)
                                                       ▼
                                        SQLite /var/lib/authordb/authorship.db
```

- A logged-in wiki user with the **`manage-authors`** right (by default the
  `sysop` group) lands on the read-only Home view with a blue **[Edit]**
  button leading to the editable admin view.
- Any other logged-in wiki user gets the read-only / export view.
- The app's own password login is disabled in embedded mode — the wiki SSO
  is the only path to admin.
- Any wiki page can embed the always-current author list with the
  **`<authordb-list/>`** parser tag — the wiki server fetches the app's
  `/export_authorlist.wiki` markup fragment and refreshes it automatically.

## What's in this repo for the integration

| Path | Purpose |
|---|---|
| [`app.py`](app.py) | App changes: `/sso` endpoint, embedded-mode lockdown, CSP, `root_path`-aware URLs, `/export_authorlist.wiki` fragment |
| [`AuthorDB/`](AuthorDB/) | The MediaWiki extension (copy into `extensions/`) |
| [`deploy/`](deploy/) | systemd unit + reverse-proxy (Nginx/Apache) samples, preset for our deployment |
| [`tools/sso_smoketest.py`](tools/sso_smoketest.py) | PHP↔Python SSO token contract test (no wiki needed) |
| this file | Overview + full step-by-step install checklist (in Czech, below) |

## App environment variables

| Variable | Example | Effect |
|---|---|---|
| `AUTHOR_DB_SECRET` | long random string | HMAC secret; **must equal** `$wgAuthorDBSecret` |
| `AUTHORDB_EMBEDDED` | `1` | Disables password `/login` + default-admin seeding |
| `ROOT_PATH` | `/authordb` | Mount prefix behind the proxy; used for redirects and all template URLs |
| `AUTHORDB_FRAME_ANCESTORS` | `http://wiki.sst1m.science` | `CSP: frame-ancestors` — only the wiki may iframe the app (origin only, no path) |
| `AUTHORDB_COOKIE_SECURE` | `0` | `1` marks the session cookie `Secure` — only once the wiki runs on HTTPS |
| `AUTHORDB_DB_URL` | `sqlite:////var/lib/authordb/authorship.db` | SQLite location; defaults to `./authorship.db`. Set it so the code dir can stay read-only |

## Security notes

- The app binds to `127.0.0.1` only and is reachable solely via the wiki
  proxy; password login is disabled in embedded mode — so the wiki SSO is
  the sole path to admin.
- SSO tokens are single-purpose (`typ:"sso"`) and short-lived
  (`$wgAuthorDBSsoTtl`, default 60 s).
- Use a strong, unique shared secret — never the `dev-secret-change-me`
  default.
- The systemd unit runs the app under a dedicated no-login user with
  sandboxing (`ProtectSystem=strict`); the only writable path is
  `/var/lib/authordb`.

The rest of this document is the full installation checklist (in Czech),
targeting the SST-1M wiki deployment.

---

# Instalace AuthorDB do MediaWiki — odškrtávací návod

Cíl: aplikace Authorship DB (FastAPI) běží na serveru wiki jako systemd služba
`authordb` dostupná **jen z localhostu (port 8489)**, webserver wiki ji
reverse-proxuje na vlastním originu pod cestou `/authordb` a stránka
**`Special:AuthorDB`** ji zobrazuje v iframe. Uživatelé wiki s právem
`manage-authors` dostanou přes SSO token editační (admin) přístup, ostatní
přihlášení jen read-only/export pohled.

## Jak s návodem pracovat

Každý krok má část **Akce** (co udělat) a **Kontrola** (jak si ověřit, že se
krok povedl). Políčko `[ ]` si odškrtni **až po úspěšné kontrole** a teprve
pak pokračuj dalším krokem. Pokud kontrola neprojde, nepokračuj — podívej se
do sekce [Řešení potíží](#řešení-potíží) na konci.

## Hodnoty použité v tomto návodu (skutečné pro naši instalaci)

| Co | Hodnota |
|---|---|
| Zdrojové repo | `https://github.com/vic0ward/sst1m-author-db.git` (pro nás jen ke čtení) |
| Origin wiki | `http://wiki.sst1m.science` (zatím bez HTTPS) |
| Instalace MediaWiki na serveru | `/var/www/sst1m_wiki/wiki` |
| Adresář aplikace na serveru | `/srv/sst1m-author-db` |
| Port aplikace (jen localhost) | `8489` |
| Veřejná cesta k aplikaci | `/authordb` |
| Sdílený HMAC secret | v `deploy/authordb.service` (řádek `AUTHOR_DB_SECRET`) |

## Mapa umístění — co odkud kam patří

| Zdroj (repo/aplikace) | Cíl na serveru | Kdo to tam dá |
|---|---|---|
| celé repo | `/srv/sst1m-author-db/` | krok 2 (`git clone`) |
| — | `/srv/sst1m-author-db/.venv/` | krok 3 (vytváří se, nekopíruje) |
| `deploy/authordb.service` | `/etc/systemd/system/authordb.service` | krok 5 (kopie) |
| `deploy/nginx-authordb.conf` **nebo** `deploy/apache-authordb.conf` | do konfigurace webu wiki: Nginx `/etc/nginx/sites-available/…`, Apache `/etc/apache2/sites-available/…` | krok 6 (vložení bloku) |
| `AuthorDB/` (MediaWiki extension) | `/var/www/sst1m_wiki/wiki/extensions/AuthorDB/` | krok 7 (kopie) |
| — | `/var/lib/authordb/authorship.db` (SQLite data) | vytvoří systemd při 1. startu |
| — (úprava existujícího) | `/var/www/sst1m_wiki/wiki/LocalSettings.php` | krok 7 (přidání bloku) |
| `deploy/wiki-author-list.wiki-md` | obsah wiki stránky „Author List" (vloží se přes editor wiki) | ručně, kdokoli s editací wiki |

Logy služby: `journalctl -u authordb`.

## Krok 1 — Příprava čistého serveru

**Akce:**

- [ ] Nainstaluj potřebné balíčky (Ubuntu):

```bash
sudo apt update && sudo apt install -y git python3-venv curl
```

**Kontrola:**

- [ ] `python3 --version` vypíše 3.10 nebo novější.
- [ ] `git --version` něco vypíše.

## Krok 2 — Stažení aplikace z repa

**Akce:**

- [ ] Naklonuj repo do `/srv`:

```bash
cd /srv
sudo git clone https://github.com/vic0ward/sst1m-author-db.git sst1m-author-db
```

**Kontrola — repo musí obsahovat integraci a opravy z 31. 7. 2026
(všechny čtyři kontroly musí projít!):**

- [ ] Adresáře a soubory integrace existují:

```bash
ls /srv/sst1m-author-db
# musí obsahovat: app.py  AuthorDB  deploy  templates  static  tools  requirements.txt
```

- [ ] `app.py` je opravená verze:

```bash
grep -c display_name /srv/sst1m-author-db/app.py     # očekáváno: 2 nebo víc
```

- [ ] Šablony jsou opravená verze:

```bash
grep -c root_path /srv/sst1m-author-db/templates/home.html    # očekáváno: 1 nebo víc
```

- [ ] `requirements.txt` je krátký seznam, ne výpis conda prostředí:

```bash
wc -l < /srv/sst1m-author-db/requirements.txt        # očekáváno: cca 10, ne stovky
```

> **STOP — pokud kterákoli kontrola selhala:** repo na GitHubu ještě
> neobsahuje aktuální stav (integrace vznikla mimo něj a my do repa psát
> nemůžeme). Neopravuj nic ručně; požádej správce repa (vic0ward)
> o aktualizaci, nebo si nech poslat aktuální projekt a nahraj ho do
> `/srv/sst1m-author-db` místo clonu (rsync/scp). Souhrn toho, co má repo
> obsahovat, je v sekci
> [Provedené úpravy oproti původní aplikaci](#provedené-úpravy-oproti-původní-aplikaci).

## Krok 3 — Virtuální prostředí a závislosti

**Akce:**

- [ ] Vytvoř venv a nainstaluj závislosti:

```bash
cd /srv/sst1m-author-db
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt
```

**Kontrola:**

- [ ] Instalace skončila bez `ERROR` (varování o verzi pip nevadí).
- [ ] Aplikace se dá naimportovat:

```bash
sudo AUTHORDB_DB_URL=sqlite:////tmp/authordb-test.db \
    /srv/sst1m-author-db/.venv/bin/python -c \
    "import sys; sys.path.insert(0,'/srv/sst1m-author-db'); import app; print('OK')"
sudo rm -f /tmp/authordb-test.db
# musí vypsat: OK
```

## Krok 4 — Systémový uživatel a práva

**Akce:**

- [ ] Založ systémový účet služby (nedá se jím přihlásit):

```bash
sudo useradd --system --user-group --no-create-home \
    --home-dir /nonexistent --shell /usr/sbin/nologin sst1m-author-db
```

- [ ] Zamkni práva: kód vlastní root, služba jen čte, ostatní nic:

```bash
sudo chown -R root:sst1m-author-db /srv/sst1m-author-db
sudo chmod -R u=rwX,g=rX,o= /srv/sst1m-author-db
```

Datový adresář `/var/lib/authordb` **nevytvářej** — udělá to systemd
v kroku 5 sám a se správným vlastníkem.

**Kontrola:**

- [ ] `id sst1m-author-db` vypíše účet se skupinou `sst1m-author-db`.
- [ ] Čtení kódu projde:

```bash
sudo -u sst1m-author-db head -1 /srv/sst1m-author-db/app.py    # vypíše první řádek
```

- [ ] Zápis do kódu NEprojde (to je správně):

```bash
sudo -u sst1m-author-db touch /srv/sst1m-author-db/x    # musí selhat: Permission denied
```

## Krok 5 — Systemd služba

**Akce:**

- [ ] Zkopíruj unit a ochraň ho (obsahuje secret):

```bash
sudo cp /srv/sst1m-author-db/deploy/authordb.service /etc/systemd/system/authordb.service
sudo chmod 600 /etc/systemd/system/authordb.service
```

- [ ] Otevři `sudoedit /etc/systemd/system/authordb.service` a zkontroluj
      hodnoty (pro naši instalaci už jsou přednastavené správně):

| Řádek | Očekávaná hodnota |
|---|---|
| `User=` / `Group=` | `sst1m-author-db` |
| `Environment=AUTHORDB_EMBEDDED=` | `1` |
| `Environment=ROOT_PATH=` | `/authordb` |
| `Environment=AUTHORDB_FRAME_ANCESTORS=` | `http://wiki.sst1m.science` (jen protokol+doména, bez cesty a lomítka) |
| `Environment=AUTHORDB_COOKIE_SECURE=` | `0` (wiki je na HTTP; `1` až s HTTPS) |
| `Environment=AUTHORDB_DB_URL=` | `sqlite:////var/lib/authordb/authorship.db` |
| `Environment=AUTHOR_DB_SECRET=` | dlouhý náhodný řetězec (použije se i v kroku 7) |
| `ExecStart=… --port` | `8489` |

- [ ] Spusť službu:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now authordb
```

> **Zapamatuj si:** po každé pozdější změně kódu nebo unitu je nutný
> `sudo systemctl restart authordb`. Samotný `daemon-reload` běžící proces
> NErestartuje a starý kód zůstává v paměti.

**Kontrola:**

- [ ] Služba běží a čas u „since" je čerstvý:

```bash
systemctl status authordb | head -3    # "active (running)"
```

- [ ] Poslouchá jen na localhostu:

```bash
ss -tlnp | grep 8489    # jediný řádek, adresa 127.0.0.1:8489
```

- [ ] Aplikace odpovídá:

```bash
curl -s http://127.0.0.1:8489/ | head -3                # vypíše HTML
curl -s -o /dev/null -w "%{http_code}\n" \
     http://127.0.0.1:8489/authordb/static/style.css    # 200
```

- [ ] Vznikla databáze se správným vlastníkem:

```bash
sudo ls -l /var/lib/authordb/    # authorship.db, vlastník sst1m-author-db
```

## Krok 6 — Reverse proxy na originu wiki

Aplikace musí být pro prohlížeč na **stejném originu jako wiki** pod
`/authordb`.

> **Důležité:** proxy musí na backend posílat **původní cestu včetně
> prefixu `/authordb`**. Když prefix odřeže, stránky fungují, ale statické
> soubory (logo, CSS) vrací 404.

**Akce (vyber variantu podle webserveru wiki; zjistíš příkazem
`systemctl is-active nginx apache2`):**

- [ ] **Nginx** — do bloku `server { }` webu wiki
      (`/etc/nginx/sites-available/…`) vlož obsah `deploy/nginx-authordb.conf`:

```nginx
location /authordb/ {
    proxy_pass         http://127.0.0.1:8489;   # BEZ koncového lomítka: prefix zůstává
    proxy_set_header   Host              $host;
    proxy_set_header   X-Real-IP         $remote_addr;
    proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header   X-Forwarded-Proto $scheme;
    proxy_http_version 1.1;
}
```

```bash
sudo nginx -t && sudo systemctl reload nginx
```

- [ ] **Apache** — do `<VirtualHost>` webu wiki
      (`/etc/apache2/sites-available/…`) vlož obsah
      `deploy/apache-authordb.conf`; nejdřív zapni moduly:

```bash
sudo a2enmod proxy proxy_http headers
```

```apache
<Location "/authordb">
    ProxyPass         "http://127.0.0.1:8489/authordb"
    ProxyPassReverse  "http://127.0.0.1:8489/authordb"
    RequestHeader set X-Forwarded-Proto "http"
</Location>
```

```bash
sudo apachectl configtest && sudo systemctl restart apache2
```

**Kontrola:**

- [ ] Úvodní stránka přes proxy:

```bash
curl -s -o /dev/null -w "%{http_code}\n" http://wiki.sst1m.science/authordb/    # 200
```

- [ ] Statické soubory přes proxy (ověří, že se prefix neodřezává):

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
     http://wiki.sst1m.science/authordb/static/style.css    # 200
```

- [ ] Odkazy v HTML nesou prefix:

```bash
curl -s http://wiki.sst1m.science/authordb/ | grep -o 'href="[^"]*"' | sort -u
# všechny musí začínat /authordb/
```

- [ ] Padělaný SSO token je odmítnut:

```bash
curl -s -o /dev/null -w "%{http_code}\n" \
     "http://wiki.sst1m.science/authordb/sso?token=garbage"    # 403
```

- [ ] Z jiného počítače: `curl -m 5 http://wiki.sst1m.science:8489/` selže
      (timeout/refused) — přímý port není zvenku dostupný.

## Krok 7 — MediaWiki extension

**Akce:**

- [ ] Zkopíruj extension do wiki:

```bash
sudo cp -r /srv/sst1m-author-db/AuthorDB /var/www/sst1m_wiki/wiki/extensions/AuthorDB
```

- [ ] Zjisti secret ze služby:

```bash
sudo grep AUTHOR_DB_SECRET= /etc/systemd/system/authordb.service
```

- [ ] Do `/var/www/sst1m_wiki/wiki/LocalSettings.php` přidej na konec
      (za `<secret>` dosaď hodnotu z předchozího bodu):

```php
wfLoadExtension( 'AuthorDB' );
$wgAuthorDBBaseUrl = '/authordb';
$wgAuthorDBSecret = '<secret>';
// Volitelné:
// $wgAuthorDBSsoTtl      = 60;     // životnost SSO tokenu (s)
// $wgAuthorDBFrameHeight = '1400'; // záložní výška iframe bez JS (px);
//                                  // s JS se výška dopočítává automaticky
// $wgAuthorDBInternalUrl = 'http://127.0.0.1:8489/authordb'; // odkud si wiki
//                                  // server stahuje fragment pro <authordb-list/>
// $wgAuthorDBListCacheTtl = 300;   // jak dlouho smí stránka s <authordb-list/>
//                                  // držet starší seznam (s)
```

**Kontrola:**

- [ ] Otevři `http://wiki.sst1m.science/wiki/index.php/Special:Version` —
      v seznamu Special pages je uvedena extension **AuthorDB**.
      (Wiki nemá short URLs, adresy proto obsahují `index.php`.)

## Krok 8 — Oprávnění ve wiki

Editační právo `manage-authors` má automaticky skupina **`sysop`**.

**Akce (jen pokud chceš vlastní skupinu editorů):**

- [ ] Do `LocalSettings.php` přidej:

```php
$wgGroupPermissions['authordb-editor']['manage-authors'] = true;
```

- [ ] Členy do skupiny přidej přes
      `…/wiki/index.php/Special:UserRights`.

**Kontrola:**

- [ ] Na `…/wiki/index.php/Special:ListGroupRights` je u skupiny sysop
      (příp. tvé skupiny) právo `manage-authors`.

## Krok 9 — Závěrečné funkční testy

**Akce + kontrola (každý bod je zároveň test):**

- [ ] Kontrakt SSO tokenů PHP ↔ Python (bez wiki):

```bash
cd /srv/sst1m-author-db
sudo AUTHOR_DB_SECRET=test-secret \
     AUTHORDB_DB_URL=sqlite:////tmp/authordb-test.db \
     .venv/bin/python tools/sso_smoketest.py
sudo rm -f /tmp/authordb-test.db
# očekáváno: ALL CHECKS PASSED (5× PASS)
```

- [ ] Heslové přihlášení je mrtvé:

```bash
curl -s -o /dev/null -w "%{http_code}\n" -X POST \
     -d "username=x&password=y" http://wiki.sst1m.science/authordb/login    # 404
```

- [ ] Prohlížeč, **nepřihlášený** →
      `http://wiki.sst1m.science/wiki/index.php/Special:AuthorDB` vyzve
      k přihlášení do wiki.
- [ ] Prohlížeč, **sysop** → tamtéž se zobrazí admin rozhraní; tlačítka
      (+ Add author, exporty, Logout) fungují a zůstávají pod `/authordb`.
- [ ] Prohlížeč, **běžný uživatel** → tamtéž jen read-only tabulka
      autorů + odkazy na exporty (bez editace, bez login boxu).
- [ ] Konzole prohlížeče (F12) je bez CSP/frame chyb.
- [ ] Výška vloženého obsahu se přizpůsobuje: pod tabulkou není velké
      prázdné místo a obsah nemá vlastní (vnitřní) scrollbar; po
      otevření delší stránky (např. seznam autorů) se rám plynule
      natáhne.
- [ ] Exporty `.txt`, `.tex`, `.xml` vrací data.
- [ ] Wiki fragment pro `<authordb-list/>`:

```bash
curl -s http://127.0.0.1:8489/authordb/export_authorlist.wiki | head -3
# očekáváno: řádek se jmény „X. Yyy<sup>1</sup>, …", prázdný řádek, <small>
```

- [ ] Na wiki stránku „Author List" vlož obsah
      `deploy/wiki-author-list.wiki-md` (přes editor wiki; jádro je tag
      `<authordb-list/>`) — po uložení se na stránce vyrenderuje aktuální
      seznam autorů s afiliacemi.

**Tímto je instalace hotová.**

---

## Provedené úpravy oproti původní aplikaci

Evidence změn proti původnímu stavu repa (commit `29d58da`, květen 2026).
Tohle všechno musí obsahovat verze, kterou nasazuješ (kontroluje krok 2).

### app.py — integrace s MediaWiki (červen 2026)

- endpoint `GET /sso` — výměna HMAC tokenu z wiki za admin session cookie
- embedded režim (`AUTHORDB_EMBEDDED=1`): vypnuté heslové přihlášení
  (`GET /login` přesměruje, `POST /login` → 404) a nezakládá se účet
  `admin/admin123`
- CSP middleware `frame-ancestors` (`AUTHORDB_FRAME_ANCESTORS`) — iframovat
  smí jen wiki
- `root_path` z env `ROOT_PATH`; `Secure` cookie přes `AUTHORDB_COOKIE_SECURE`

### app.py — opravy funkčnosti (31. 7. 2026)

- volání šablon převedena na nový styl `TemplateResponse(request, name, ctx)`
  (starý styl v aktuálním Starlette padá s `TypeError: unhashable type: 'dict'`
  → Internal Server Error na každé stránce)
- doplněna chybějící metoda `Author.display_name()` (bez ní padal
  `/export.txt`, jakmile byl v DB autor)
- všechna přesměrování (`RedirectResponse`) prefixují cesty přes `ROOT_PATH`
- šablonám se předává Jinja globál `root_path`
  (`templates.env.globals["root_path"]`)
- cesta k databázi konfigurovatelná přes `AUTHORDB_DB_URL` (kvůli read-only
  adresáři s kódem)

### app.py + templates/home.html — vstup na Home místo adminu (1. 8. 2026)

- `GET /sso` po ověření tokenu přesměrovává na `/` (Home) místo `/admin`;
  admin session cookie se nastavuje stejně jako dřív (původní redirect je
  v kódu zakomentovaný)
- route `home()` předává šabloně příznak `is_admin` (platná admin session
  cookie); `templates/home.html` pak nahoře ukazuje modré tlačítko
  **[Edit]** → `/admin` — jen adminům, read-only uživatelé wiki ho nevidí
- z adminu vede zpět stávající tlačítko [Home]

### templates/ — funkční úpravy (31. 7. 2026)

Ve **všech** šablonách (`home`, `login`, `admin_list`, `author_list`,
`author_edit`, `affiliation_list`, `affiliation_edit`) dostaly všechny
absolutní odkazy (`href=`, `action=`, `src=`) prefix `{{ root_path }}` —
jinak by za proxy ukazovaly mimo `/authordb`.

### Oprava formulářů Save u autora/afiliace (1. 8. 2026)

Dva `action=` atributy z předchozího bodu unikly (dynamicky skládané
z Jinja výrazu) a tlačítko **Save** tak za proxy POSTovalo mimo aplikaci
(na origin wiki → uživatel skončil na hlavní stránce webu):

- `templates/author_edit.html`: `action` doplněn prefix `{{ root_path }}`
- `templates/affiliation_edit.html`: `action` byl chybný dvojnásobně —
  chyběl prefix **a** mířil na autorské endpointy (`/admin/author/new`;
  proměnná `author` v této šabloně ani neexistuje) → opraveno na
  `/admin/affiliation/new|edit/<id>` s prefixem
- `app.py`: `postal_code: str = Form(None)` → `Form("")` u obou
  afiliačních handlerů — prázdné PSČ ve formuláři jinak padalo 500
  (`AttributeError: 'NoneType' object has no attribute 'strip'`);
  do té doby skryté, protože formulář afiliací kvůli chybě výše nikdy
  nedoPOSToval na správný endpoint

Ve standalone režimu (prázdný `ROOT_PATH`) se chybějící prefix neprojevil —
proto si toho původní aplikace nevšimla.

### templates/ + static/ — kosmetické úpravy pro embed do wiki (31. 7. 2026)

Nic není smazané — jen **zakomentované** (Jinja `{# … #}`, CSS `/* … */`);
návrat = smazat komentářové značky.

| Soubor | Co je zakomentované | Proč |
|---|---|---|
| `templates/admin_list.html` | blok `<header>` (logo + „Admin - Authorship DB") | duplikoval nadpis wiki stránky |
| `templates/home.html` | `<h1>{{ app_name }}</h1>` | duplikoval nadpis wiki stránky |
| `templates/home.html` | karta „Admin / Login (admins only)" | heslové přihlášení je v embedded režimu vypnuté |
| `templates/home.html` | druhý „Admin / Login" odkaz dole | totéž |
| `static/style.css` | `background: #f4f6f8;` u `body` | šedý rám v iframe; pozadí wiki teď prosvítá |
| `static/style.css` | `max-width`/`margin`/`padding` u `main` (1. 8. 2026) | centrovaný sloupec 1200 px tvořil v iframe „ostrov" nezarovnaný s wiki stránkou + 40px mezeru nahoře |
| `static/style.css` | `padding: 0 16px` u `body` (1. 8. 2026) | poslední odsazení zužující obsah oproti wiki stránce; embed teď lícuje s nadpisem wiki |

### requirements.txt (31. 7. 2026)

Původní soubor byl 356řádkový `pip freeze` z conda prostředí s nefunkčními
`file:///` odkazy. Nahrazen minimálním seznamem: fastapi, uvicorn, jinja2,
sqlalchemy, python-multipart, passlib, **bcrypt připnutý na 4.0.1**
(passlib 1.7.4 neumí číst verzi z bcrypt ≥ 4.1).

### deploy/ (31. 7. 2026)

- `authordb.service`: uživatel `sst1m-author-db`, port 8489, DB
  v `/var/lib/authordb` (`StateDirectory`), systemd sandboxing
  (`ProtectSystem=strict` aj.), `AUTHORDB_COOKIE_SECURE=0`,
  `AUTHORDB_FRAME_ANCESTORS=http://wiki.sst1m.science`
- `nginx-authordb.conf` / `apache-authordb.conf`: port 8489 a **proxy
  neodřezává prefix** `/authordb` (jinak 404 na statické soubory)

### AuthorDB/ (extension) — automatická výška iframe (1. 8. 2026)

- nový ResourceLoader modul `ext.authorDB.frame`
  (`resources/ext.authorDB.frame.js`): iframe je same-origin, skript proto
  čte výšku vloženého dokumentu a průběžně jí přizpůsobuje výšku rámu
  (`ResizeObserver` + `load` při každé navigaci uvnitř) — žádný vnitřní
  scrollbar ani prázdné místo pod obsahem
- `extension.json`: registrace modulu (`ResourceModules`,
  `ResourceFileModulePaths`)
- `SpecialAuthorDB.php`: iframe dostal `id="authordb-frame"` a stránka
  načítá modul; původní `renderIframe` ponechán zakomentovaný
- `$wgAuthorDBFrameHeight` nově slouží jen jako záložní `min-height` pro
  prohlížeče bez JS; se zapnutým JS ji skript ihned nahradí spočtenou výškou

### app.py + AuthorDB/ — automatický seznam autorů na wiki stránce (1. 8. 2026)

- `app.py`: nový veřejný endpoint `GET /export_authorlist.wiki` (od 27. 8. 2026
  přejmenováno z `/export.wiki` — sladěno s `/export_authorlist.txt|tex|xml`
  přenesenými z main) — seznam autorů jako fragment MediaWiki markupu (jména
  s `<sup>` indexy afiliací + `<small>` blok afiliací s adresami), stejné
  indexování jako `/export_authorlist.tex`
- extension: parser tag `<authordb-list/>` (nový `src/Hooks.php`, registrace
  v `extension.json`, verze 1.1.0) — při renderování wiki stránky si server
  stáhne `/export_authorlist.wiki` z `$wgAuthorDBInternalUrl` (default
  `http://127.0.0.1:8489/authordb`, tj. přímo uvicorn) a vloží ho do stránky;
  parser cache expiruje po `$wgAuthorDBListCacheTtl` s (default 300), při
  nedostupnosti aplikace se místo seznamu zobrazí chybové hlášení a nový
  pokus proběhne do minuty
- `deploy/wiki-author-list.wiki-md`: zdroj stránky „Author List" přepsán na
  `<authordb-list/>`; původní ruční seznam ponechán v `<!-- -->` komentáři

## Řešení potíží

| Příznak | Příčina a řešení |
|---|---|
| kontroly v kroku 2 selhávají | repo neobsahuje aktuální stav — viz STOP rámeček v kroku 2 |
| `pip` hlásí `No such file or directory: /home/conda/...` | starý `requirements.txt` — repo neobsahuje opravy (viz krok 2) |
| `Internal Server Error` na každé HTML stránce | stará verze `app.py`/`templates/` — viz krok 2; po výměně souborů `sudo systemctl restart authordb` |
| oprava nahraná, ale chyba trvá | služba nebyla restartována — `daemon-reload` nestačí; stáří chyby poznáš podle časů v `systemctl status` |
| `502 Bad Gateway` na `/authordb/` | služba neběží, nebo proxy míří na jiný port než 8489 — `systemctl status authordb`, `journalctl -u authordb -e` |
| `500` na `/authordb/`, ale `127.0.0.1:8489` dává 200 a v `journalctl` nic nepřibývá | chybu vrací webserver, ne aplikace; u Apache typicky chybí moduly — `sudo a2enmod proxy proxy_http headers && sudo systemctl restart apache2` |
| stránky fungují, ale logo a CSS (`…/static/…`) 404 | proxy odřezává prefix — Nginx: `proxy_pass` **bez** koncového lomítka; Apache: `ProxyPass "http://127.0.0.1:8489/authordb"` |
| po přihlášení skončíš mimo `/authordb` (404 wiki) | chybí `ROOT_PATH=/authordb` v unitu, nebo stará verze `templates/` |
| iframe prázdný, v konzoli CSP chyba `frame-ancestors` | `AUTHORDB_FRAME_ANCESTORS` musí být přesně `http://wiki.sst1m.science` (bez cesty a lomítka) |
| SSO projde (303), ale admin hlásí 401 / vrátí na úvod | `AUTHORDB_COOKIE_SECURE=1` na HTTP wiki — prohlížeč cookie zahodí; nastav `0` |
| `403 Invalid or expired SSO token` pro sysopa | `$wgAuthorDBSecret` ≠ `AUTHOR_DB_SECRET`, nebo rozjetý čas serverů (token platí 60 s) |
| `unable to open database file` v logu | `/var/lib/authordb` neexistuje/špatný vlastník — startuj přes systemd, ne ručně |
| změny v datech se neukládají | DB zůstala v `/srv/…` — `sudo mv /srv/sst1m-author-db/authorship.db /var/lib/authordb/ && sudo chown sst1m-author-db: /var/lib/authordb/authorship.db` a restart |
| změna CSS se neprojevila | cache prohlížeče — Ctrl+F5, případně otevřít `…/authordb/` přímo v tabu a tam Ctrl+F5 |
| iframe má pořád pevnou výšku (~1400 px prázdného místa pod obsahem) | na wiki je stará kopie extension bez modulu `ext.authorDB.frame` — znovu zkopíruj `AuthorDB/` do `extensions/` (krok 7) a dej Ctrl+F5; zkontroluj v konzoli (F12), že se nenačítá JS chyba |
| na stránce se zobrazuje doslovně text `<authordb-list/>` | wiki běží se starou extension bez registrace tagu — typicky past `cp -r` do existujícího cíle (vznikne vnořený `extensions/AuthorDB/AuthorDB/`); zkopíruj obsah přes `cp -r …/AuthorDB/. …/extensions/AuthorDB/`, ověř verzi 1.1.0 na Special:Version a stránku obnov přes `…&action=purge` |
| místo `<authordb-list/>` je „Could not load the author list…" | služba neběží, nebo `$wgAuthorDBInternalUrl` nemíří na uvicorn včetně prefixu — na serveru otestuj `curl http://127.0.0.1:8489/authordb/export_authorlist.wiki` |
| seznam z `<authordb-list/>` je zastaralý | parser cache — projeví se do `$wgAuthorDBListCacheTtl` s (default 5 min), nebo stránku obnov přes `…index.php?title=<stránka>&action=purge` |

## Aktualizace aplikace v budoucnu

- [ ] Stáhni novou verzi (repo je pro nás jen ke čtení — pouze `pull`,
      nikdy `push`):

```bash
sudo git -C /srv/sst1m-author-db pull
```

- [ ] Obnov práva a restartuj:

```bash
sudo chown -R root:sst1m-author-db /srv/sst1m-author-db
sudo chmod -R u=rwX,g=rX,o= /srv/sst1m-author-db
sudo systemctl restart authordb
```

- [ ] Kontrola: `curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8489/` → 200.
- [ ] Změnila-li se extension (`AuthorDB/`): znovu zkopíruj **obsah** do
      existujícího adresáře (pozor, `cp -r` bez `/.` by při existujícím
      cíli vytvořil vnořený `extensions/AuthorDB/AuthorDB/` a staré
      soubory by zůstaly v platnosti!):

```bash
sudo cp -r /srv/sst1m-author-db/AuthorDB/. /var/www/sst1m_wiki/wiki/extensions/AuthorDB/
```

      Kontrola: na `…/wiki/index.php/Special:Version` je u AuthorDB
      očekávaná verze.
- [ ] Změnil-li se `deploy/authordb.service`: zopakuj krok 5 včetně
      `daemon-reload` + `restart`.

Databáze v `/var/lib/authordb` zůstává při aktualizacích nedotčená.
