from __future__ import annotations

import re

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone, date
from typing import Optional, List
from xml.etree import ElementTree as ET
from xml.etree.ElementTree import Element, SubElement, tostring
from fastapi import FastAPI, Request, Form, Depends, HTTPException, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, Response, PlainTextResponse
from fastapi.templating import Jinja2Templates

from passlib.context import CryptContext
from sqlalchemy import create_engine, String, Integer, Boolean, DateTime, ForeignKey, UniqueConstraint, select
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker, Session, relationship

import hmac, hashlib, base64, json, os

from xml.sax.saxutils import escape

from fastapi.staticfiles import StaticFiles

APP_NAME = "Authorship DB"
DB_URL = "sqlite:///./authorship.db"

engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

app = FastAPI(title=APP_NAME)
app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")


def generate_xml_id(session):
    result = session.execute(
        select(Affiliation.xml_id)
            .where(Affiliation.xml_id.is_not(None))
    ).scalars().all()

    max_id = 0

    for xml_id in result:
        match = re.match(r"a(\d+)", xml_id or "")
        if match:
            max_id = max(max_id, int(match.group(1)))

    return f"a{max_id + 1}"

NS = {
    "foaf": "http://xmlns.com/foaf/0.1/",
    "cal": "http://inspirehep.net/info/HepNames/tools/authors_xml/",
}


def txt(el, path, default=""):
    found = el.find(path, NS)
    return found.text.strip() if found is not None and found.text else default


def split_address(address: str):
    parts = [p.strip() for p in address.split(",") if p.strip()]
    country = parts[-1] if len(parts) >= 1 else ""
    city = parts[-2] if len(parts) >= 2 else ""
    street = ", ".join(parts[1:-2]) if len(parts) > 3 else ""
    return street, "", city, country


# -------------------------
# Database models
# -------------------------
class Base(DeclarativeBase):
    pass


class AuthorAffiliation(Base):
    __tablename__ = "author_affiliations"
    __table_args__ = (UniqueConstraint("author_id", "affiliation_id", name="uq_author_aff"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    author_id: Mapped[int] = mapped_column(ForeignKey("authors.id"), index=True)
    affiliation_id: Mapped[int] = mapped_column(ForeignKey("affiliations.id"), index=True)


class Affiliation(Base):
    __tablename__ = "affiliations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    xml_id: Mapped[str] = mapped_column(String(32), default="", unique=True)
    short_name: Mapped[str] = mapped_column(String(200), unique=True, index=True)
    department: Mapped[str] = mapped_column(String(200), default="")
    institution: Mapped[str] = mapped_column(String(200), default="")
    street: Mapped[str] = mapped_column(String(200), default="")
    postal_code: Mapped[str] = mapped_column(String(32), default=None)
    city: Mapped[str] = mapped_column(String(120), default="")
    country: Mapped[str] = mapped_column(String(120), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(timezone.utc))

    def full_address(self) -> str:
        parts = [
            self.short_name,
            self.street,
            " ".join([p for p in [self.postal_code, self.city] if p]),
            self.country,
        ]

        return ", ".join([p for p in parts if p and p.strip()])


class Author(Base):
    __tablename__ = "authors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    first_name: Mapped[str] = mapped_column(String(120))
    last_name: Mapped[str] = mapped_column(String(120), index=True)
    email: Mapped[str] = mapped_column(String(200), default="")
    orcid: Mapped[str] = mapped_column(String(40), default="")
    qualified: Mapped[bool] = mapped_column(Boolean, default=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    member_since: Mapped[str] = mapped_column(String(120), default="")
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.now(timezone.utc))
    affiliations: Mapped[List[Affiliation]] = relationship(
        "Affiliation",
        secondary="author_affiliations",
        order_by="Affiliation.id",
        lazy="joined",
    )


class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(80), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))


Base.metadata.create_all(bind=engine)


# -------------------------
# Helpers / deps
# -------------------------


def get_db() -> Session:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


SESSION_COOKIE = "authorship_admin"


@dataclass
class SessionToken:
    username: str
    expires_at: datetime


SECRET = os.environ.get("AUTHOR_DB_SECRET", "dev-secret-change-me")


def _sign(data: bytes) -> str:
    sig = hmac.new(SECRET.encode("utf-8"), data, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(sig).decode("utf-8")


def make_cookie(username: str, minutes: int = 8 * 60) -> str:
    payload = {
        "u": username,
        "exp": (datetime.utcnow() + timedelta(minutes=minutes)).timestamp(),
    }
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(data).decode("utf-8") + "." + _sign(data)


def read_cookie(cookie_value: str) -> Optional[SessionToken]:
    try:
        b64, sig = cookie_value.split(".", 1)
        data = base64.urlsafe_b64decode(b64.encode("utf-8"))
        if not hmac.compare_digest(sig, _sign(data)):
            return None
        payload = json.loads(data.decode("utf-8"))
        exp = datetime.utcfromtimestamp(payload["exp"])
        if datetime.utcnow() > exp:
            return None
        return SessionToken(username=payload["u"], expires_at=exp)
    except Exception:
        return None


def require_admin(request: Request) -> str:
    """

    @rtype: object
    """
    cookie = request.cookies.get(SESSION_COOKIE)
    if not cookie:
        raise HTTPException(status_code=401, detail="Not logged in")
    token = read_cookie(cookie)
    if not token:
        raise HTTPException(status_code=401, detail="Invalid/expired session")
    return token.username


def ensure_default_admin(db: Session) -> None:
    # Create a default admin if none exists (MVP). Change immediately after first run.
    if db.query(AdminUser).count() == 0:
        username = "admin"
        password = "admin123"
        db.add(AdminUser(username=username, password_hash=pwd_context.hash(password)))
        db.commit()


# -------------------------
# Views
# -------------------------
@app.get("/", response_class=HTMLResponse)
def home(request: Request, db: Session = Depends(get_db)):
    ensure_default_admin(db)

    authors = (
        db.query(Author)
            .filter(Author.active == True)
            .order_by(Author.last_name.asc(), Author.first_name.asc())
            .all()
    )

    author_count = db.query(Author).count()

    return templates.TemplateResponse(
        "home.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "author_count": author_count,
            "authors": authors,
        },
    )


@app.get("/login", response_class=HTMLResponse)
def login_get(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "app_name": APP_NAME})


@app.post("/login")
def login_post(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
        db: Session = Depends(get_db),
):
    ensure_default_admin(db)
    user = db.query(AdminUser).filter(AdminUser.username == username).first()
    if not user or not pwd_context.verify(password, user.password_hash):
        return templates.TemplateResponse(
            "login.html",
            {"request": request, "app_name": APP_NAME, "error": "Login incorrect."},
            status_code=401,
        )

    resp = RedirectResponse(url="/admin", status_code=303)
    resp.set_cookie(SESSION_COOKIE, make_cookie(username), httponly=True, samesite="lax")
    return resp


@app.post("/logout")
def logout():
    resp = RedirectResponse(url="/", status_code=303)
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# -------------------------
# Admin CRUD
# -------------------------
@app.get("/admin", response_class=HTMLResponse)
def admin_list(request: Request, db: Session = Depends(get_db)):
    _ = require_admin(request)
    authors = db.query(Author).order_by(Author.last_name.asc(), Author.first_name.asc()).all()
    affiliations = db.query(Affiliation).order_by(Affiliation.short_name.asc()).all()
    return templates.TemplateResponse(
        "admin_list.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "authors": authors,
            "affiliations": affiliations
        },
    )


@app.get("/admin/author", response_class=HTMLResponse)
def author_list(request: Request, db: Session = Depends(get_db)):
    _ = require_admin(request)
    auths = db.query(Author).order_by(Author.last_name.asc(), Author.last_name.asc()).all()
    affiliations = db.query(Affiliation).order_by(Affiliation.short_name.asc()).all()
    return templates.TemplateResponse(
        "author_list.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "authors": auths,
            "affiliations": affiliations
        },
    )


@app.get("/admin/author/new", response_class=HTMLResponse)
def authors_new(request: Request, db: Session = Depends(get_db)):
    _ = require_admin(request)
    affiliations = db.query(Affiliation).order_by(Affiliation.short_name.asc()).all()
    return templates.TemplateResponse(
        "author_edit.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "author": None,
            "affiliations": affiliations
        },
    )


@app.post("/admin/author/new")
def author_new_post(
        request: Request,
        first_name: str = Form(...),
        last_name: str = Form(...),
        email: str = Form(""),
        orcid: str = Form(""),
        affiliation_ids: List[int] = Form([]),
        qualified: bool = Form(False),
        active: bool = Form(False),
        member_since: str = Form(""),
        db: Session = Depends(get_db),
):
    _ = require_admin(request)
    a = Author(
        first_name=first_name.strip(),
        last_name=last_name.strip(),
        affiliations=(
            db.query(Affiliation).filter(Affiliation.id.in_(affiliation_ids)).all()
            if affiliation_ids else []
        ),
        email=email.strip(),
        orcid=orcid.strip(),
        qualified=qualified,
        active=active,
        member_since=member_since.strip(),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(a)
    db.commit()
    return RedirectResponse(url="/admin", status_code=303)


@app.get("/admin/author/edit/{author_id}", response_class=HTMLResponse)
def author_edit(request: Request, author_id: int, db: Session = Depends(get_db)):
    _ = require_admin(request)
    auth = db.get(Author, author_id)
    if not auth:
        raise HTTPException(404, "Author not found")
    affs = db.query(Affiliation).order_by(Affiliation.short_name.asc()).all()
    return templates.TemplateResponse(
        "author_edit.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "author": auth,
            "affiliations": affs
        },
    )


@app.post("/admin/author/edit/{author_id}")
def author_edit_post(
        request: Request,
        author_id: int,
        first_name: str = Form(...),
        last_name: str = Form(...),
        affiliation_ids: List[int] = Form([]),
        email: str = Form(""),
        orcid: str = Form(""),
        member_since: str = Form(""),
        qualified: bool = Form(False),
        active: bool = Form(False),
        db: Session = Depends(get_db),
):
    _ = require_admin(request)
    author = db.get(Author, author_id)
    if not author:
        raise HTTPException(404, "Author not found")

    author.first_name = first_name.strip()
    author.last_name = last_name.strip()
    author.affiliations = (
                              db.query(Affiliation).filter(Affiliation.id.in_(affiliation_ids)).all()
                              if affiliation_ids else []
                          )
    author.email = email.strip()
    author.orcid = orcid.strip()
    author.member_since = member_since.strip()
    author.qualified = qualified
    author.active = active
    author.updated_at = datetime.utcnow()
    db.commit()
    return RedirectResponse(url="/admin/author", status_code=303)


@app.post("/admin/author/delete/{author_id}")
def author_delete(request: Request, author_id: int, db: Session = Depends(get_db)):
    _ = require_admin(request)
    author = db.get(Author, author_id)
    if author:
        db.delete(author)
        db.commit()
    return RedirectResponse(url="/admin/author", status_code=303)


@app.get("/admin/affiliation", response_class=HTMLResponse)
def affiliation_list(request: Request, db: Session = Depends(get_db)):
    _ = require_admin(request)
    affs = db.query(Affiliation).order_by(Affiliation.short_name.asc()).all()
    return templates.TemplateResponse(
        "affiliation_list.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "affiliations": affs
        },
    )


@app.get("/admin/affiliation/new", response_class=HTMLResponse)
def affiliation_new(request: Request):
    _ = require_admin(request)
    return templates.TemplateResponse(
        "affiliation_edit.html",
        {"request": request, "app_name": APP_NAME, "affiliation": None},
    )


@app.post("/admin/affiliation/new")
def affiliation_new_post(
        request: Request,
        short_name: str = Form(...),
        xml_id=None,
        department: str = Form(""),
        institution: str = Form(""),
        street: str = Form(""),
        city: str = Form(""),
        postal_code: str = Form(None),
        country: str = Form(""),
        db: Session = Depends(get_db),
):
    _ = require_admin(request)
    a = Affiliation(
        xml_id=generate_xml_id(db),
        short_name=short_name.strip(),
        department=department.strip(),
        institution=institution.strip(),
        street=street.strip(),
        city=city.strip(),
        postal_code=postal_code.strip(),
        country=country.strip(),
        updated_at=datetime.now(timezone.utc),
    )
    db.add(a)
    db.commit()
    return RedirectResponse(url="/admin/affiliation", status_code=303)


@app.get("/admin/affiliation/edit/{aff_id}", response_class=HTMLResponse)
def affiliation_edit(request: Request, aff_id: int, db: Session = Depends(get_db)):
    _ = require_admin(request)
    aff = db.get(Affiliation, aff_id)
    if not aff:
        raise HTTPException(404, "Affiliation not found")
    return templates.TemplateResponse(
        "affiliation_edit.html",
        {
            "request": request,
            "app_name": APP_NAME,
            "affiliation": aff
        },
    )


@app.post("/admin/affiliation/edit/{aff_id}")
def affiliation_edit_post(
        request: Request,
        aff_id: int,
        short_name: str = Form(...),
        department: str = Form(""),
        institution: str = Form(""),
        street: str = Form(""),
        city: str = Form(""),
        postal_code: str = Form(None),
        country: str = Form(""),
        db: Session = Depends(get_db),
):
    _ = require_admin(request)
    aff = db.get(Affiliation, aff_id)
    if not aff:
        raise HTTPException(404, "Affiliation not found")

    aff.short_name = short_name.strip()
    aff.department = department.strip()
    aff.institution = institution.strip()
    aff.street = street.strip()
    aff.city = city.strip()
    aff.postal_code = postal_code.strip()
    aff.country = country.strip()
    aff.updated_at = datetime.utcnow()
    db.commit()
    return RedirectResponse(url="/admin/affiliation", status_code=303)


@app.post("/admin/affiliation/delete/{aff_id}")
def affiliation_delete(request: Request, aff_id: int, db: Session = Depends(get_db)):
    _ = require_admin(request)
    affiliations = db.get(Affiliation, aff_id)
    if affiliations:
        used = db.query(AuthorAffiliation).filter(AuthorAffiliation.affiliation_id == aff_id).count()
        if used:
            raise HTTPException(400, "Affiliation is used by authors; unlink first.")
        db.delete(affiliations)
        db.commit()
    return RedirectResponse(url="/admin/affiliation", status_code=303)


# -------------------------
# Exports
# -------------------------
def fetch_active_qualified(db: Session) -> List[Author]:
    return (
        db.query(Author)
            .filter(Author.active == True, Author.qualified == True)  # noqa: E712
            .order_by(Author.last_name.asc(), Author.first_name.asc())
            .all()
    )


@app.get("/export.txt")
def export_txt(db: Session = Depends(get_db)):
    authors = fetch_active_qualified(db)
    lines = [a.display_name() for a in authors]
    return PlainTextResponse("\n".join(lines) + ("\n" if lines else ""), media_type="text/plain")


def fetch_active_qualified(db: Session) -> List[Author]:
    return (
        db.query(Author)
            .filter(Author.active == True, Author.qualified == True)  # noqa: E712
            .order_by(Author.last_name.asc(), Author.first_name.asc())
            .all()
    )


@app.get("/export.tex")
def export_tex(db: Session = Depends(get_db)):
    authors = fetch_active_qualified(db)

    # Affiliation indices 1..N (stables)
    used_affs = {}
    for au in authors:
        for aff in au.affiliations:
            used_affs[aff.id] = aff
    aff_list = [used_affs[k] for k in sorted(used_affs.keys())]
    aff_index = {aff.id: i + 1 for i, aff in enumerate(aff_list)}

    def initials(first: str) -> str:
        parts = [p for p in first.replace("-", " ").split() if p]
        return "~".join([p[0] + "." for p in parts]) if parts else ""

    author_entries = []
    for au in authors:
        init = initials(au.first_name)
        idxs = [aff_index[a.id] for a in au.affiliations if a.id in aff_index]
        if len(idxs) <= 1:
            sup = f"$^{idxs[0]}$" if idxs else ""
            author_entries.append(f"{init}~{au.last_name}{sup}")
        else:
            sup = ",".join(str(i) for i in idxs)
            author_entries.append(f"{init}~{au.last_name}\\inst$^{{{sup}}}$")  # like template

    author_block = ",\n".join([e + "," for e in author_entries]).rstrip(",") + " \\\\"

    aff_lines = [f"$^{aff_index[a.id]}$" + a.full_address() for a in aff_list]

    tex = (
            "%% Full authors list (ONLY FOR COLLABORATIONS)\n"
            "\\clearpage\n"
            "\\section*{Full Authors List: SST-1M Collaboration}\n"
            "%\n"
            "\\scriptsize\n"
            "\\noindent\n"
            + author_block
            + "\n\n\\noindent\n"
            + "\n".join(aff_lines)
            + "\n"
    )
    return PlainTextResponse(tex, media_type="application/x-tex")


COLLAB_ID = "SST-1M"
COLLAB_NAME = "The SST-1M Collaboration"
PUBREF = "INSERT ARXIV LINK"  # ou mets ça en variable d'env


def paper_initials(first: str) -> str:
    parts = [p for p in first.replace("-", " ").split() if p]
    return " ".join([p[0] + "." for p in parts]) if parts else ""


@app.get("/export.xml")
def export_xml(db: Session = Depends(get_db)):
    authors = fetch_active_qualified(db)

    # collect used affiliations
    used = {}
    for au in authors:
        for aff in au.affiliations:
            used[aff.id] = aff
    aff_list = [used[k] for k in sorted(used.keys())]

    # organization ids: prefer stored xml_id; else auto a1,a2,...
    auto_idx = 1
    aff_to_orgid = {}
    for aff in aff_list:
        if aff.xml_id:
            aff_to_orgid[aff.id] = aff.xml_id
        else:
            aff_to_orgid[aff.id] = f"a{auto_idx}"
            auto_idx += 1

    creation = datetime.utcnow().strftime("%Y-%m-%d_%H:%M")

    out = []
    out.append('<?xml version="1.0" encoding="UTF-8"?>')
    out.append('<!DOCTYPE collaborationauthorlist SYSTEM')
    out.append('  "http://inspirehep.net/info/HepNames/tools/authors_xml/author.dtd">')
    out.append(
        '<collaborationauthorlist\n'
        '    xmlns:foaf="http://xmlns.com/foaf/0.1/"\n'
        '    xmlns:cal="http://inspirehep.net/info/HepNames/tools/authors_xml/">\n'
    )
    out.append(f"    <cal:creationDate>{escape(creation)}</cal:creationDate>")
    out.append(f"    <cal:publicationReference>{escape(PUBREF)}</cal:publicationReference>\n")

    out.append("    <cal:collaborations>")
    out.append(f'       <cal:collaboration id="{COLLAB_ID}">')
    out.append(f"          <foaf:name>{escape(COLLAB_NAME)}</foaf:name>")
    out.append("          <cal:experimentNumber></cal:experimentNumber>")
    out.append("       </cal:collaboration>")
    out.append("    </cal:collaborations>\n")

    out.append("    <cal:organizations>")
    for aff in aff_list:
        orgid = aff_to_orgid[aff.id]
        out.append(f'      <foaf:Organization id="{escape(orgid)}">')
        out.append("         <cal:orgDomain></cal:orgDomain>")
        out.append(f"         <foaf:name>{escape(aff.short_name)}</foaf:name>")
        out.append('         <cal:orgName source=""></cal:orgName>')
        out.append(f'         <cal:orgStatus collaborationid="{COLLAB_ID}">Member</cal:orgStatus>')
        out.append(f"         <cal:orgAddress>{escape(aff.full_address())}</cal:orgAddress>")
        out.append(f'         <cal:group with="{escape(orgid)}"/>')
        out.append("      </foaf:Organization>")
    out.append("    </cal:organizations>\n")

    out.append("    <cal:authors>")
    for au in authors:
        given_p = paper_initials(au.first_name)
        fam = au.last_name
        paper = (given_p + " " + fam).strip()

        out.append("      <foaf:Person>")
        out.append(f"         <foaf:name>{escape(au.first_name + ' ' + au.last_name)}</foaf:name>")
        out.append("         <cal:authorNameNative></cal:authorNameNative>")
        out.append(f"         <foaf:givenName>{escape(au.first_name)}</foaf:givenName>")
        out.append(f"         <foaf:familyName>{escape(au.last_name)}</foaf:familyName>")
        out.append("         <cal:authorSuffix></cal:authorSuffix>")
        out.append("         <cal:authorStatus></cal:authorStatus>")
        out.append(f"         <cal:authorNamePaper>{escape(paper)}</cal:authorNamePaper>")
        out.append(f"         <cal:authorNamePaperGiven>{escape(given_p)}</cal:authorNamePaperGiven>")
        out.append(f"         <cal:authorNamePaperFamily>{escape(fam)}</cal:authorNamePaperFamily>")
        out.append(f'         <cal:authorCollaboration collaborationid="{COLLAB_ID}" position="" />')
        out.append("         <cal:authorAffiliations>")
        for aff in au.affiliations:
            orgid = aff_to_orgid.get(aff.id)
            if orgid:
                out.append(f'            <cal:authorAffiliation organizationid="{escape(orgid)}" connection="" />')
        out.append("         </cal:authorAffiliations>")
        out.append("         <cal:authorids>")
        out.append('            <cal:authorid source="INSPIRE"></cal:authorid>')
        out.append(f'            <cal:authorid source="ORCID">{escape(au.orcid or "")}</cal:authorid>')
        out.append("         </cal:authorids>")
        out.append("         <cal:authorFunding></cal:authorFunding>")
        out.append("      </foaf:Person>")
    out.append("    </cal:authors>")
    out.append("</collaborationauthorlist>\n")

    return Response(content="\n".join(out).encode("utf-8"), media_type="application/xml")

@app.post("/admin/import/xml")
async def import_xml(
        request: Request,
        xml_file: UploadFile = File(...),
        db: Session = Depends(get_db),
):
    _ = require_admin(request)

    content = await xml_file.read()

    try:
        root = ET.fromstring(content)
    except ET.ParseError as e:
        raise HTTPException(400, f"Invalid XML file: {e}")

    org_by_xml_id = {}

    # ---- import affiliations / organizations
    for org in root.findall(".//foaf:Organization", NS):
        xml_id = org.attrib.get("id", "").strip()
        short_name = txt(org, "foaf:name")
        address = txt(org, "cal:orgAddress")

        if not short_name:
            continue

        aff = None

        if xml_id:
            aff = db.query(Affiliation).filter(Affiliation.xml_id == xml_id).first()

        if aff is None:
            aff = db.query(Affiliation).filter(Affiliation.short_name == short_name).first()

        street, postal_code, city, country = split_address(address)

        if aff is None:
            aff = Affiliation(
                xml_id=xml_id or generate_xml_id(db),
                short_name=short_name,
                institution=short_name,
                street=street,
                postal_code=postal_code,
                city=city,
                country=country,
                updated_at=datetime.now(timezone.utc),
            )
            db.add(aff)
            db.flush()
        else:
            aff.xml_id = aff.xml_id or xml_id or generate_xml_id(db)
            aff.short_name = aff.short_name or short_name
            aff.institution = aff.institution or short_name
            aff.street = aff.street or street
            aff.postal_code = aff.postal_code or postal_code
            aff.city = aff.city or city
            aff.country = aff.country or country
            aff.updated_at = datetime.now(timezone.utc)

        if xml_id:
            org_by_xml_id[xml_id] = aff

    # ---- import authors
    for person in root.findall(".//foaf:Person", NS):
        first_name = txt(person, "foaf:givenName")
        last_name = txt(person, "foaf:familyName")

        if not first_name and not last_name:
            full_name = txt(person, "foaf:name")
            pieces = full_name.split()
            first_name = " ".join(pieces[:-1])
            last_name = pieces[-1] if pieces else ""

        if not last_name:
            continue

        orcid = ""
        for aid in person.findall(".//cal:authorid", NS):
            if aid.attrib.get("source", "").upper() == "ORCID":
                orcid = aid.text.strip() if aid.text else ""

        author = (
            db.query(Author)
                .filter(
                Author.first_name == first_name,
                Author.last_name == last_name,
                )
                .first()
        )

        if author is None:
            author = Author(
                first_name=first_name,
                last_name=last_name,
                orcid=orcid,
                qualified=True,
                active=True,
                member_since=str(datetime.utcnow().year),
                updated_at=datetime.now(timezone.utc),
            )
            db.add(author)
            db.flush()
        else:
            if orcid and not author.orcid:
                author.orcid = orcid
            author.updated_at = datetime.now(timezone.utc)

        affiliations = []
        for aa in person.findall(".//cal:authorAffiliation", NS):
            org_id = aa.attrib.get("organizationid", "").strip()
            aff = org_by_xml_id.get(org_id)
            if aff and aff not in affiliations:
                affiliations.append(aff)

        if affiliations:
            author.affiliations = affiliations

    db.commit()

    return RedirectResponse(url="/admin", status_code=303)