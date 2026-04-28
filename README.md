# SST-1M Authorship Database

Simple web interface to manage authors and affiliations and export lists in:
- TXT
- LaTeX
- XML

## Features
- Admin interface
- Author<-> affiliation many-to-many
- Export formats compatible with collaboration templates

## Run locally

```bash
pip install -r requirements.txt
uvicorn app:app --reload
Open: http://127.0.0.1:8000
