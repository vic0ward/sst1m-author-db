# AuthorDB — MediaWiki extension

Embeds the [SST-1M Authorship DB](../README.md) (a FastAPI app) inside MediaWiki
as **`Special:AuthorDB`**, with single sign-on driven by MediaWiki accounts.

## How it works

```
Special:AuthorDB (PHP)  ──mints signed SSO token──►  <iframe src="/authordb/sso?token=…">
   requireLogin()                                          │
   + 'manage-authors' right check                          ▼
                                          FastAPI app validates token (shared secret),
                                          sets its admin session, serves /admin
```

- A logged-in wiki user with the **`manage-authors`** right gets a short-lived,
  HMAC-signed token and lands in the editable admin view.
- Any other logged-in user gets the read-only / export view.
- The separate `admin/admin123` password login of the app is disabled in
  embedded mode (`AUTHORDB_EMBEDDED=1`), so the wiki is the only way in.
- The iframe auto-sizes to its content (ResourceLoader module
  `ext.authorDB.frame`; the app is same-origin behind the reverse proxy, so
  the script can read the embedded document's height) — no inner scrollbar.
- The extension also provides the **`<authordb-list/>`** parser tag: put it
  on any wiki page and it renders the current author list (names with
  affiliation indices + the affiliation block), fetched server-side from the
  app's `/export_authorlist.wiki` endpoint and refreshed automatically.

The token is signed with a secret shared between this extension
(`$wgAuthorDBSecret`) and the app (`AUTHOR_DB_SECRET`). **They must match.**

## Install

1. Copy this `AuthorDB/` directory into your wiki's `extensions/` folder.
2. Run the FastAPI app in embedded mode behind a same-origin reverse proxy
   (see [`deploy/`](../deploy/) for samples). Recommended path: `/authordb`.
3. Add to `LocalSettings.php`:

```php
wfLoadExtension( 'AuthorDB' );

// Browser-visible base URL of the embedded app (same-origin reverse proxy path).
$wgAuthorDBBaseUrl = '/authordb';

// MUST equal the app's AUTHOR_DB_SECRET environment variable. Use a long random value.
$wgAuthorDBSecret = 'CHANGE-ME-to-a-long-random-shared-secret';

// Optional tuning:
// $wgAuthorDBSsoTtl     = 60;     // token lifetime (seconds)
// $wgAuthorDBFrameHeight = '1400'; // no-JS fallback iframe height (px);
//                                  // with JS the frame auto-sizes to content
// $wgAuthorDBInternalUrl = 'http://127.0.0.1:8489/authordb'; // server-side URL
//                                  // for the <authordb-list/> tag fetches
// $wgAuthorDBListCacheTtl = 300;   // how long pages may cache <authordb-list/> (s)

// By default the 'manage-authors' right is granted to the 'sysop' group.
// To grant it to a custom group instead:
// $wgGroupPermissions['authordb-editor']['manage-authors'] = true;
```

4. Visit **Special:AuthorDB** while logged in.

## Configuration reference

| Setting | Default | Meaning |
|---|---|---|
| `$wgAuthorDBBaseUrl` | `/authordb` | Browser-facing base URL of the app |
| `$wgAuthorDBSecret` | `''` | Shared HMAC secret (= app `AUTHOR_DB_SECRET`); empty ⇒ read-only embed |
| `$wgAuthorDBSsoTtl` | `60` | SSO token lifetime, seconds |
| `$wgAuthorDBFrameHeight` | `1400` | fallback iframe min-height in px (no-JS only; with JS the frame auto-sizes) |
| `$wgAuthorDBInternalUrl` | `http://127.0.0.1:8489/authordb` | server-side base URL used by `<authordb-list/>` to fetch from the app (must include the app's ROOT_PATH prefix) |
| `$wgAuthorDBListCacheTtl` | `300` | parser cache TTL (s) for pages with `<authordb-list/>` — max staleness of the embedded list |

## Embedding the author list on wiki pages

Put the self-closing tag anywhere in a wiki page:

```text
<authordb-list/>
```

It expands to the current author list in the collaboration format
(`C. Alispach<sup>1</sup>, …` + a `<small>` block with numbered
affiliations). The wikitext fragment comes from the app's public
`GET /export_authorlist.wiki` endpoint, fetched server-side from
`$wgAuthorDBInternalUrl`; the page's parser cache expires after
`$wgAuthorDBListCacheTtl` seconds, so database edits show up on the page
within that window (or immediately after a purge:
`…/index.php?title=<page>&action=purge`). If the app is unreachable, the
tag renders an error message instead and retries within a minute.

## Requirements

- MediaWiki ≥ 1.39
- The FastAPI app reachable at `$wgAuthorDBBaseUrl` (same origin recommended)
- For `<authordb-list/>`: the app reachable from the wiki server at
  `$wgAuthorDBInternalUrl`
