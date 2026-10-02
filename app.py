#!/usr/bin/env python3
"""MojeSkola - vlastni skolni system kompatibilni s mobilni aplikaci Bakalari Online (API v3)
+ vlastni webova online verze na /.
Bez externich knihoven. Data v school_data.json.
"""
import base64
import hashlib
import hmac
import json
import os
import secrets
import datetime
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_FILE = os.path.join(BASE_DIR, "school_data.json")

API_VERSION = "3.23.0"
APP_VERSION = "1.52.1102.1"

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
APP_SECRET = os.environ.get("APP_SECRET", "dev-secret-zmenit-na-renderu-i-vercelu")
SCHOOL_NAME_DEFAULT = "Soukromá zábavná škola, Bukovany u Sokolova"
ON_VERCEL = os.environ.get("VERCEL", "") == "1"

def sb_request(method, path, body=None):
    """Minimalni Supabase REST klient bez externich knihoven. Vraci dict/list nebo None."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return None
    url = SUPABASE_URL + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("apikey", SUPABASE_KEY)
    req.add_header("Authorization", "Bearer " + SUPABASE_KEY)
    req.add_header("Content-Type", "application/json")
    req.add_header("Prefer", "resolution=merge-duplicates")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read().decode() or "null"
            return json.loads(raw)
    except urllib.error.HTTPError as e:
        try:
            print("supabase", method, path, e.code, e.read()[:300])
        except Exception:
            pass
        return None
    except Exception as e:
        print("supabase error", e)
        return None

def load_data():
    with open(DATA_FILE, encoding="utf-8") as f:
        local = json.load(f)
    local["school_name"] = SCHOOL_NAME_DEFAULT
    if not SUPABASE_URL or not SUPABASE_KEY:
        return local
    # zkus nacist ze Supabase (klice: school_name, users, marks, ...)
    try:
        rows = sb_request("GET", "/rest/v1/school_store?select=key,value")
        if isinstance(rows, list) and rows:
            remote = dict((r["key"], r["value"]) for r in rows if "key" in r)
            if remote:
                local.update(remote)
                print(f"nacteno ze Supabase: {sorted(remote.keys())}")
                return local
        if isinstance(rows, list) and not rows:
            if ON_VERCEL:
                # na Vercelu neseedujeme automaticky (cold-start limit) - seed pres /web/admin/seed
                print("Supabase prazdna (Vercel rezim) - jedu z lokalniho souboru.")
                return local
            # tabulka existuje ale je prazdna -> seeduj z lokalniho souboru
            print("Supabase prazdna, seeduji...")
            for k, v in local.items():
                sb_request("POST", "/rest/v1/school_store", {"key": k, "value": v})
            return local
        if rows is None:
            print("Supabase tabulka school_store zatim neexistuje - jedu z lokalniho souboru. Vytvor ji pomoci supabase_schema.sql.")
        return local
    except Exception as e:
        print("Supabase load fallback:", e)
        return local

DATA = load_data()

def save_data(section=None):
    try:
        with open(DATA_FILE, "w", encoding="utf-8") as f:
            json.dump(DATA, f, ensure_ascii=False, indent=1)
    except Exception as e:
        # na Vercelu je filesystem read-only - normalni, data jdou do Supabase
        print("save file skipped:", e)
    if not SUPABASE_URL or not SUPABASE_KEY:
        return
    # uloz jen zmenenou sekci (na Vercelu limit casu funkce)
    try:
        keys = [section] if section and section in DATA else list(DATA.keys())
        for k in keys:
            sb_request("POST", "/rest/v1/school_store", {"key": k, "value": DATA[k]})
    except Exception as e:
        print("supabase save error", e)

def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def issue_token(username: str, kind: str = "access") -> str:
    """Stateless HMAC token ve tvaru JWT (header.payload.signature),
    aby ho mobilni aplikace mohla dekodovat jako normalni token."""
    exp = int(time.time()) + (3600 if kind == "access" else 30 * 24 * 3600)
    header = _b64e(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = _b64e(json.dumps({
        "sub": username, "kind": kind, "exp": exp, "iat": int(time.time()),
        "azp": "ANDR", "iss": DATA.get("school_name", "MojeSkola")}).encode())
    sig = _b64e(hmac.new(APP_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

def verify_token(token: str, kind: str = "access"):
    # novy JWT tvar
    try:
        h_b64, p_b64, s_b64 = token.split(".")
        expect = hmac.new(APP_SECRET.encode(), f"{h_b64}.{p_b64}".encode(), hashlib.sha256).digest()
        if not hmac.compare_digest(_b64d(s_b64), expect):
            raise ValueError
        payload = json.loads(_b64d(p_b64).decode())
        if payload.get("kind") != kind or int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload.get("sub")
    except Exception:
        pass
    # stary 2-dilny tvar (zpetna kompatibilita)
    try:
        p_b64, s_b64 = token.split(".", 1)
        payload = _b64d(p_b64)
        sig = _b64d(s_b64)
        expect = hmac.new(APP_SECRET.encode(), payload, hashlib.sha256).digest()
        if not hmac.compare_digest(sig, expect):
            return None
        k, username, exp = payload.decode().split(".", 2)
        if k != kind or int(exp) < int(time.time()):
            return None
        return username
    except Exception:
        return None

def make_id_token(username: str, client_id: str, host: str) -> str:
    """Fake OIDC id_token - nova aplikace ho muze vyzadovat pro identitu uzivatele."""
    now = int(time.time())
    header = _b64e(json.dumps({"alg": "HS256", "kid": "mojeskola1", "typ": "JWT"}).encode())
    payload = _b64e(json.dumps({
        "sub": username, "oi_au_id": _b64e(secrets.token_bytes(12)),
        "azp": client_id or "ANDR", "aud": client_id or "ANDR",
        "exp": now + 1800, "iat": now,
        "iss": f"https://{(host or 'mojeskola').split(',')[0].strip()}/"}).encode())
    sig = _b64e(hmac.new(APP_SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"

def new_token(nbytes=48):
    return base64.urlsafe_b64encode(secrets.token_bytes(nbytes)).decode()

def campaign_code():
    raw = json.dumps({"sid": "1234", "ut": 69, "sy": 1}).encode()
    return base64.urlsafe_b64encode(raw).decode()

# sessions: access_token -> username, refresh_token -> username
sessions_access = {}
sessions_refresh = {}

def find_user(username):
    for u in DATA.get("users", []):
        if u["username"] == username:
            return u
    return None

def user_from_token(token):
    username = sessions_access.get(token)
    if not username:
        # stateless HMAC token (Vercel / vic instanci)
        username = verify_token(token, "access")
    if not username:
        return None
    return find_user(username)

def class_info(cid):
    for c in DATA.get("classes", []):
        if c["Id"] == cid:
            return c
    return {"Id": cid or "3A", "Abbrev": "3.A", "Name": "3. A"}

def iso(dt):
    # vrat ISO s offsetem +02:00 (zjednodusene)
    if isinstance(dt, datetime.date) and not isinstance(dt, datetime.datetime):
        dt = datetime.datetime(dt.year, dt.month, dt.day, 0, 0, 0)
    return dt.strftime("%Y-%m-%dT%H:%M:%S+02:00")

def monday_of(d):
    return d - datetime.timedelta(days=d.weekday())

def build_timetable(monday):
    hours = DATA.get("hours", [])
    tt = DATA.get("timetable", {})
    subjects_map = {s.get("SubjectID") or s.get("Id"): s for s in DATA.get("subjects", [])}
    days = []
    for dow in range(1, 6):
        day_date = monday + datetime.timedelta(days=dow - 1)
        lessons = tt.get(str(dow), [])
        atoms = []
        for i, les in enumerate(lessons):
            sid, tid, rid = (les + [None, None, None])[:3]
            atoms.append({
                "HourId": 3 + i,
                "GroupIds": [DATA.get("classes", [{"Id": "3A"}])[0]["Id"]],
                "SubjectId": sid,
                "TeacherId": tid,
                "RoomId": rid,
                "CycleIds": ["0"],
                "Change": None,
                "HomeworkIds": [],
                "Theme": ""
            })
        days.append({
            "Atoms": atoms,
            "DayOfWeek": dow,
            "Date": iso(day_date),
            "DayDescription": "",
            "DayType": "WorkDay"
        })
    # rozliseni nazvu pro mobilni app: potrebuje Classes, Groups, Subjects, Teachers, Rooms
    subjects = [{"Id": s.get("SubjectID", s.get("Id")), "Abbrev": s.get("SubjectAbbrev", "?"), "Name": s.get("SubjectName", s.get("Name", "?"))} for s in DATA.get("subjects", [])]
    return {
        "Hours": hours,
        "Days": days,
        "Classes": DATA.get("classes", []),
        "Groups": DATA.get("groups", []),
        "Subjects": subjects,
        "Teachers": DATA.get("teachers", []),
        "Rooms": DATA.get("rooms", []),
        "Cycles": [{"Id": "0", "Abbrev": "A", "Name": "Stálá"}]
    }

def enabled_modules():
    return [
        {"Module": "Komens", "Rights": ["ShowReceivedMessages","ShowSentMessages","ShowNoticeBoardMessages","SendMessages","ShowRatingDetails","SendAttachments"]},
        {"Module": "Absence", "Rights": ["ShowAbsence","ShowAbsencePercentage"]},
        {"Module": "Events", "Rights": ["ShowEvents"]},
        {"Module": "Marks", "Rights": ["ShowMarks","ShowFinalMarks","PredictMarks"]},
        {"Module": "Timetable", "Rights": ["ShowTimetable"]},
        {"Module": "Substitutions", "Rights": ["ShowSubstitutions"]},
        {"Module": "Subjects", "Rights": ["ShowSubjects","ShowSubjectThemes"]},
        {"Module": "Homeworks", "Rights": ["ShowHomeworks"]},
        {"Module": "Gdpr", "Rights": ["ShowOwnConsents","ShowChildConsents","ShowCommissioners"]},
    ]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        print(fmt % args)

    def send_json(self, obj, status=200):
        body = json.dumps(obj, ensure_ascii=False).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def send_file(self, name, ctype):
        p = os.path.join(BASE_DIR, name)
        try:
            with open(p, "rb") as f:
                body = f.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except FileNotFoundError:
            self.send_response(404); self.end_headers()

    def body_params(self):
        length = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(length) if length else b""
        ctype = self.headers.get("Content-Type", "")
        if "application/json" in ctype:
            try:
                return json.loads(raw.decode() or "{}")
            except Exception:
                return {}
        try:
            qs = parse_qs(raw.decode())
            return {k: v[0] for k, v in qs.items()}
        except Exception:
            return {}

    def auth_user(self):
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        u = user_from_token(token)
        return u, token

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        qs = parse_qs(u.query)
        if path.startswith("/api") or path.startswith("/web"):
            print(f"API {self.command} {self.path} ct={self.headers.get('Content-Type','-')} auth={'yes' if self.headers.get('Authorization') else 'no'}")
        # --- webova online verze ---
        if path == "/":
            return self.send_file("index.html", "text/html; charset=utf-8")
        if path in ("/app.js", "/style.css"):
            ct = "application/javascript" if path.endswith(".js") else "text/css"
            return self.send_file(path.lstrip("/"), ct)

        # --- zakladni info (GET /api vraci POLE, GET /api/3 vraci OBJEKT - dle docs) ---
        if path == "/api":
            return self.send_json([{"ApiVersion": API_VERSION, "ApplicationVersion": APP_VERSION, "BaseUrl": "api/3"}])
        if path == "/api/3":
            return self.send_json({"ApiVersion": API_VERSION, "ApplicationVersion": APP_VERSION, "BaseUrl": "api/3"})

        # vse dale vyzaduje auth, krome logintoken/webmodule (ty app vola i s tokenem, ale vratime i bez)
        if path == "/api/3/logintoken":
            return self.send_json("mojeskola")
        if path == "/api/3/webmodule":
            return self.send_json({"WebModules": [{"IconId": "dokumenty", "SubMenu": None, "Url": "", "Name": "Dokumenty"}],
                            "Dashboard": {"IconId": None, "SubMenu": None, "Url": "", "Name": None}})

        me, _ = self.auth_user()
        if not me and path.startswith("/api/3/"):
            # webova verze si rika o /web/config bez tokenu? ne, vse api chce token
            return self.send_json({"Message": "Authorization has been denied for this request."}, 401)

        if path == "/api/3/user":
            ci = class_info(me.get("class_id"))
            dtype = me.get("type", "student")
            utype = {"student": "student", "teacher": "teacher", "admin": "teacher"}.get(dtype, "student")
            return self.send_json({
                "UserUID": "1234/" + me["username"],
                "CampaignCategoryCode": campaign_code(),
                "Class": ci,
                "FullName": f'{me["name"]}, {ci["Abbrev"]}' if me.get("class_id") else me["name"],
                "SchoolOrganizationName": DATA.get("school_name", "Moje škola"),
                "SchoolType": None, "UserType": utype, "UserTypeText": utype,
                "bak:Role": me.get("type", "student"),
                "StudyYear": 3, "EnabledModules": enabled_modules(),
                "SettingModules": {"Common": {"$type": "CommonModuleSettings",
                    "ActualSemester": {"SemesterId": "1", "From": "2026-09-01T00:00:00+02:00", "To": "2027-01-30T23:59:59+01:00"}}},
            })

        if path == "/api/3/marks":
            return self.send_json({"Subjects": DATA.get("marks", [])})
        if path == "/api/3/marks/final":
            return self.send_json({"CertificateTerms": DATA.get("final_terms", [])})
        if path == "/api/3/marks/count-new":
            n = sum(1 for s in DATA.get("marks", []) for m in s.get("Marks", []) if m.get("IsNew"))
            return self.send_json(n)
        if path == "/api/3/marks/what-if":
            return self.send_json({"Subjects": []})
        if path == "/api/3/marks/measures":
            return self.send_json({"Measures": []})
        if path == "/api/3/subjects":
            return self.send_json({"Subjects": DATA.get("subjects", [])})
        if path.startswith("/api/3/subjects/themes"):
            return self.send_json({"Themes": []})

        if path == "/api/3/timetable/permanent":
            mon = monday_of(datetime.date.today())
            return self.send_json(build_timetable(mon))
        if path == "/api/3/timetable/actual":
            datestr = (qs.get("date", [None])[0])
            try:
                d = datetime.datetime.strptime(datestr, "%Y-%m-%d").date() if datestr else datetime.date.today()
            except Exception:
                return self.send_json({"Message": "The request is invalid."}, 400)
            return self.send_json(build_timetable(monday_of(d)))

        if path == "/api/3/absence/student":
            return self.send_json({"PercentageThreshold": 0.18,
                "Absences": DATA.get("absences", []),
                "AbsencesPerSubject": DATA.get("absence_per_subject", [])})

        if path == "/api/3/substitutions":
            return self.send_json({"From": iso(datetime.date.today()), "To": iso(datetime.date.today() + datetime.timedelta(days=14)),
                                   "Changes": DATA.get("substitutions", [])})

        if path in ("/api/3/events", "/api/3/events/my", "/api/3/events/public"):
            return self.send_json({"Events": DATA.get("events", [])})

        if path == "/api/3/homeworks":
            return self.send_json({"Homeworks": DATA.get("homeworks", [])})
        if path == "/api/3/homeworks/count-actual":
            return self.send_json(len([h for h in DATA.get("homeworks", []) if not h.get("Done")]))

        if path == "/api/3/komens/messages/received/unread":
            n = sum(1 for m in DATA.get("messages_received", []) if not m.get("Read"))
            return self.send_json(n)
        if path == "/api/3/komens/messages/noticeboard/unread":
            return self.send_json(0)
        if path == "/api/3/komens/message-types":
            return self.send_json([])
        if path == "/api/3/user/student-at-school":
            return self.send_json(True)

        # prazdne moduly at app nepadá
        if path.startswith("/api/3/gdpr") or path.startswith("/api/3/classbook") or path.startswith("/api/3/payments") or path.startswith("/api/3/marking") or path.startswith("/api/3/lesson"):
            if "commissioners" in path:
                return self.send_json([])
            if "atoms" in path:
                return self.send_json([])
            return self.send_json({})

        # webove pomocne: seznam trid/predmetu pro admin UI
        if path == "/web/config":
            return self.send_json({"school_name": DATA.get("school_name"), "classes": DATA.get("classes"), "subjects": DATA.get("subjects"), "users": [{"username": x["username"], "name": x["name"], "type": x["type"], "class_id": x.get("class_id")} for x in DATA.get("users", [])]})

        print("Unhandled GET", self.path)
        return self.send_json({}, 200)

    def do_POST(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        params = self.body_params()
        if path.startswith("/api") or path.startswith("/web"):
            print(f"API {self.command} {u.path} ct={self.headers.get('Content-Type','-')} auth={'yes' if self.headers.get('Authorization') else 'no'} keys={sorted(params.keys())}")
        if path in ("/api/login", "/api/3/login"):
            grant = params.get("grant_type", "")
            if grant == "password":
                username = str(params.get("username", ""))[:255]
                password = str(params.get("password", ""))
                user = find_user(username)
                if not user or user.get("password") != password:
                    # zpetna kompatibilita: dynamicky ucet jako driv (jmeno=uzivatel, heslo=trida)
                    # aby se dalo prihlasit i bez seed uctu
                    if username and password and not user:
                        user = {"username": username, "password": password, "name": username, "class_id": "3A", "type": "student"}
                        DATA.setdefault("users", []).append(user)
                        save_data("users")
                    else:
                        return self.send_json({"error": "invalid_grant"}, 400)
                access, refresh = issue_token(user["username"], "access"), issue_token(user["username"], "refresh")
                sessions_access[access] = user["username"]
                sessions_refresh[refresh] = user["username"]
                cid = str(params.get("client_id", "ANDR"))
                host = self.headers.get("Host", "")
                return self.send_json({"bak:ApiVersion": API_VERSION, "bak:AppVersion": APP_VERSION,
                    "token_type": "Bearer", "expires_in": 3599, "scope": "openid profile offline_access bakalari_api",
                    "bak:UserId": "1", "refresh_token": refresh, "access_token": access,
                    "id_token": make_id_token(user["username"], cid, host)})
            elif grant == "refresh_token":
                rt = params.get("refresh_token", "")
                username = sessions_refresh.get(rt) or verify_token(rt, "refresh")
                if not username:
                    return self.send_json({"error": "invalid_grant"}, 400)
                access = issue_token(username, "access")
                sessions_access[access] = username
                cid = str(params.get("client_id", "ANDR"))
                host = self.headers.get("Host", "")
                return self.send_json({"bak:ApiVersion": API_VERSION, "bak:AppVersion": APP_VERSION,
                    "token_type": "Bearer", "expires_in": 3599, "scope": "openid profile offline_access bakalari_api",
                    "bak:UserId": "1", "refresh_token": rt, "access_token": access,
                    "id_token": make_id_token(username, cid, host)})
            return self.send_json({"error": "unsupported_grant"}, 400)

        if path == "/api/3/register-notification" or path == "/api/3/unregister-user-notification":
            return self.send_json({}, 200)

        if path == "/api/3/komens/messages/received":
            return self.send_json({"Messages": DATA.get("messages_received", [])})
        if path == "/api/3/komens/messages/sent":
            return self.send_json({"Messages": DATA.get("messages_sent", [])})
        if path == "/api/3/komens/messages/noticeboard":
            return self.send_json({"Messages": DATA.get("messages_noticeboard", [])})
        if path == "/api/3/komens/message":
            # odeslani zpravy z mobilu -> uloz do odeslanych
            me, _ = self.auth_user()
            msg = {"Id": "S" + secrets.token_hex(3), "Title": params.get("Title", "Zpráva z mobilu"),
                   "Text": f"<div>{params.get('Text', '')}</div>", "SentDate": iso(datetime.datetime.now()),
                   "Sender": {"Id": me["username"] if me else "?", "Type": "student", "Name": me["name"] if me else "?"},
                   "Attachments": [], "Read": True, "LifeTime": "ToRead", "Type": "OBECNA", "CanAnswer": False}
            DATA.setdefault("messages_sent", []).append(msg)
            save_data("messages_sent")
            return self.send_json({}, 200)

        # --- admin web akce (vyzaduje prihlaseneho ucitele/admina) ---
        me, _ = self.auth_user()
        if path == "/web/admin/add-mark":
            if not me or me.get("type") not in ("teacher", "admin"):
                return self.send_json({"error": "forbidden"}, 403)
            sid = params.get("subject_id", "10")
            # najdi predmet v marks, nebo vytvor
            target = next((s for s in DATA.get("marks", []) if s["Subject"]["Id"] == sid), None)
            if not target:
                subj = next((s for s in DATA.get("subjects", []) if (s.get("SubjectID") == sid)), {"SubjectName": sid, "SubjectAbbrev": sid})
                target = {"Subject": {"Id": sid, "Abbrev": subj.get("SubjectAbbrev", sid), "Name": subj.get("SubjectName", sid)},
                          "Marks": [], "AverageText": "", "TemporaryMark": "", "SubjectNote": "", "TemporaryMarkNote": "", "PointsOnly": False, "MarkPredictionEnabled": True}
                DATA.setdefault("marks", []).append(target)
            target["Marks"].append({"MarkDate": iso(datetime.datetime.now()), "EditDate": iso(datetime.datetime.now()),
                "Caption": params.get("caption", "Známka"), "Theme": "", "MarkText": str(params.get("mark", "1")),
                "TeacherId": "U001", "Type": "O", "TypeNote": "známka", "Weight": int(params.get("weight", 3)),
                "SubjectId": sid, "IsNew": True, "IsPoints": False, "CalculatedMarkText": "", "ClassRankText": None,
                "Id": "M" + secrets.token_hex(3), "PointsText": "", "MaxPoints": 0})
            save_data("marks")
            return self.send_json({"ok": True})
        if path == "/web/admin/add-homework":
            if not me or me.get("type") not in ("teacher", "admin"):
                return self.send_json({"error": "forbidden"}, 403)
            sid = params.get("subject_id", "10")
            subj = next((s for s in DATA.get("subjects", []) if s.get("SubjectID") == sid), {"SubjectName": "Předmět", "SubjectAbbrev": "?"})
            DATA.setdefault("homeworks", []).append({"ID": "HW" + secrets.token_hex(3),
                "DateStart": iso(datetime.datetime.now()), "DateEnd": params.get("date_end", iso(datetime.date.today() + datetime.timedelta(days=3))),
                "Content": params.get("content", ""), "Notice": "", "Done": False, "Closed": False, "Electronic": False, "Hour": 1,
                "Class": DATA.get("classes", [{"Id": "3A", "Abbrev": "3.A", "Name": "3. A"}])[0],
                "Group": {"Id": "3A", "Abbrev": "3.A", "Name": "3. A"},
                "Subject": {"Id": sid, "Abbrev": subj.get("SubjectAbbrev", "?"), "Name": subj.get("SubjectName", "?")},
                "Teacher": {"Id": "U001", "Abbrev": "NU", "Name": me["name"]},
                "Attachments": [], "Finished": False})
            save_data("homeworks")
            return self.send_json({"ok": True})
        if path == "/web/admin/add-message":
            if not me or me.get("type") not in ("teacher", "admin"):
                return self.send_json({"error": "forbidden"}, 403)
            DATA.setdefault("messages_received", []).append({"Id": "MSG" + secrets.token_hex(3),
                "Title": params.get("title", "Oznámení"), "Text": f"<div>{params.get('text', '')}</div>",
                "SentDate": iso(datetime.datetime.now()),
                "Sender": {"Id": me["username"], "Type": "teacher", "Name": me["name"]},
                "Attachments": [], "Read": False, "LifeTime": "ToRead", "DateFrom": None, "DateTo": None,
                "Confirmed": True, "CanConfirm": False, "Type": "OBECNA", "CanAnswer": True, "Hidden": False, "CanHide": True,
                "RelevantName": me["name"], "RelevantPersonType": "teacher"})
            save_data("messages_received")
            return self.send_json({"ok": True})
        if path == "/web/admin/add-substitution":
            if not me or me.get("type") not in ("teacher", "admin"):
                return self.send_json({"error": "forbidden"}, 403)
            DATA.setdefault("substitutions", []).append({"ChangeSubject": None, "Day": params.get("day", iso(datetime.date.today())),
                "Hours": params.get("hours", "1. hod"), "ChangeType": params.get("type", "Substitution"),
                "Description": params.get("description", ""), "Time": "", "TypeAbbrev": None, "TypeName": None})
            save_data("substitutions")
            return self.send_json({"ok": True})

        if path == "/web/admin/seed":
            # jednorazove naplneni Supabase z lokalniho souboru (jen admin)
            if not me or me.get("type") != "admin":
                return self.send_json({"error": "forbidden"}, 403)
            if not SUPABASE_URL or not SUPABASE_KEY:
                return self.send_json({"error": "no-supabase"}, 400)
            n = 0
            for k, v in DATA.items():
                if sb_request("POST", "/rest/v1/school_store", {"key": k, "value": v}) is not None:
                    n += 1
            return self.send_json({"ok": True, "seeded": n})

        if path == "/web/admin/add-user":
            if not me or me.get("type") != "admin":
                return self.send_json({"error": "forbidden"}, 403)
            username = str(params.get("username", "")).strip()[:64]
            password = str(params.get("password", ""))[:255]
            name = str(params.get("name", username)).strip()[:255] or username
            class_id = str(params.get("class_id", "") or "").strip() or None
            utype = str(params.get("type", "student")).strip()
            if utype not in ("student", "teacher", "admin"):
                utype = "student"
            if not username or not password:
                return self.send_json({"error": "missing-username-or-password"}, 400)
            if find_user(username):
                return self.send_json({"error": "user-exists"}, 400)
            if utype == "student" and not class_id:
                classes = DATA.get("classes", [])
                class_id = classes[0]["Id"] if classes else "3A"
            DATA.setdefault("users", []).append({
                "username": username, "password": password, "name": name,
                "class_id": class_id, "type": utype})
            save_data("users")
            return self.send_json({"ok": True})

        if path == "/web/admin/delete-user":
            if not me or me.get("type") != "admin":
                return self.send_json({"error": "forbidden"}, 403)
            username = str(params.get("username", "")).strip()
            if username == me["username"]:
                return self.send_json({"error": "cannot-delete-self"}, 400)
            before = len(DATA.get("users", []))
            DATA["users"] = [x for x in DATA.get("users", []) if x["username"] != username]
            if len(DATA["users"]) == before:
                return self.send_json({"error": "not-found"}, 404)
            save_data("users")
            return self.send_json({"ok": True})

        print("Unhandled POST", self.path)
        return self.send_json({}, 200)

    def do_PUT(self):
        u = urlparse(self.path)
        path = u.path.rstrip("/") or "/"
        if "mark-as-read" in path:
            mid = path.split("/")[-2] if "mark-as-read" in path else ""
            for m in DATA.get("messages_received", []):
                if m.get("Id") == mid:
                    m["Read"] = True
            save_data("messages_received")
            self.send_response(204); self.end_headers(); return
        self.send_response(200); self.end_headers()

    def do_DELETE(self):
        self.send_response(200); self.end_headers()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    if os.environ.get("APP_ADDRESS", "").startswith(":"):
        try:
            port = int(os.environ["APP_ADDRESS"][1:])
        except ValueError:
            pass
    print(f"MojeSkola listening on :{port}")
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
