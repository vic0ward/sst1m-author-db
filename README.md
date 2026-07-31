# SST-1M Authorship Database

Simple web interface to manage authors and affiliations and export lists in:
- TXT
- LaTeX
- XML
- MediaWiki markup (`/export.wiki`, used by the wiki integration)

## Features
- Admin interface
- Author <-> affiliation many-to-many
- Export formats compatible with collaboration templates

## Run locally (standalone)

```bash
pip install -r requirements.txt
uvicorn app:app --port 8489
```

Then open http://127.0.0.1:8489

Notes for standalone use:
- With no environment variables set, the app runs fully standalone: the
  SQLite database is created as `./authorship.db` and password login is
  enabled.
- The admin login form is at http://127.0.0.1:8489/login — the link to it
  on the home page is commented out in the templates (hidden for the
  MediaWiki embed), so use the URL directly. Default account is
  `admin` / `admin123`; change it immediately.
- The layout is visually tuned for the MediaWiki embed: the page header,
  gray background, body padding and the centered fixed-width column are
  commented out in the templates/CSS, so standalone pages render edge-to-edge
  on a white background. Functionality is unaffected.

## MediaWiki integration

In production this app runs embedded in the SST-1M MediaWiki as the
**`Special:AuthorDB`** page (iframe behind a same-origin reverse proxy,
single sign-on from wiki accounts, password login disabled). The extension
also provides the `<authordb-list/>` parser tag, which renders the
always-current author list on any wiki page. Architecture overview,
configuration reference and the full step-by-step installation guide are
in [INTEGRATION.md](INTEGRATION.md).
