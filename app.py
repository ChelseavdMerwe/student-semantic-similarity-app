import streamlit as st
from typing import List, Dict, Any
import networkx as nx
from pyvis.network import Network
import tempfile, os, uuid
import base64
from openai import OpenAI
import logging
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()
import json
import secrets
import string
import hashlib

CREDENTIALS_PATH = os.path.join(os.path.dirname(__file__), "credentials.json")
PARTICIPANTS_PATH = os.path.join(os.path.dirname(__file__), "participants.json")
SESSIONS_PATH = os.path.join(os.path.dirname(__file__), "sessions.json")
USER_SESSIONS_PATH = os.path.join(os.path.dirname(__file__), "user_sessions.json")

def load_credentials() -> Dict[str, Any]:
    file_creds: Dict[str, Any] = {}
    if os.path.exists(CREDENTIALS_PATH):
        try:
            with open(CREDENTIALS_PATH, "r", encoding="utf-8") as f:
                file_creds = json.load(f)
        except Exception:
            file_creds = {}

    # Helper to parse student list from secrets (accept list or comma/newline-separated string)
    from collections.abc import Mapping

    def _parse_student_pw_list(raw):
        if raw is None:
            return []
        # Handle mapping-like objects (Streamlit secrets may provide a mapping)
        if isinstance(raw, Mapping):
            # If it's a mapping, assume values are the passwords
            return [str(v) for v in raw.values()]
        if isinstance(raw, list):
            return [str(x) for x in raw]
        # assume string
        s = str(raw)
        # split on commas or newlines
        parts = [p.strip() for p in s.replace('\r', '\n').split('\n') if p.strip()]
        result = []
        for part in parts:
            for sub in part.split(','):
                if sub.strip():
                    result.append(sub.strip())
        return result
    
    def _parse_student_map(raw):
        # Accept either a mapping-like object or a JSON string mapping username->password
        if raw is None:
            return {}
        if isinstance(raw, Mapping):
            return {str(k): str(v) for k, v in raw.items()}
        try:
            # try parse as JSON string
            parsed = json.loads(str(raw))
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}
            return {}
        except Exception:
            return {}
    
    def _parse_admin_map(raw):
        # Accept either a mapping-like object or a JSON string mapping admin_username->password
        if raw is None:
            return {}
        if isinstance(raw, Mapping):
            return {str(k): str(v) for k, v in raw.items()}
        try:
            parsed = json.loads(str(raw))
            if isinstance(parsed, dict):
                return {str(k): str(v) for k, v in parsed.items()}
            return {}
        except Exception:
            return {}

    # Detect secrets-managed credentials (Streamlit secrets take precedence)
    secrets_mode = False
    admin_pw = None
    student_pw_list: List[str] = []
    try:
        if hasattr(st, "secrets") and st.secrets:
            # Streamlit secrets is a Mapping-like object
            if "ADMIN_PASSWORD" in st.secrets:
                admin_pw = st.secrets.get("ADMIN_PASSWORD")
                secrets_mode = True
            if "ADMIN_MAP" in st.secrets:
                admin_map = _parse_admin_map(st.secrets.get("ADMIN_MAP"))
                secrets_mode = True
            else:
                admin_map = {}

            if "STUDENT_PASSWORDS" in st.secrets:
                student_pw_list = _parse_student_pw_list(st.secrets.get("STUDENT_PASSWORDS"))
                secrets_mode = True
            if "STUDENT_MAP" in st.secrets:
                student_map = _parse_student_map(st.secrets.get("STUDENT_MAP"))
                secrets_mode = True
            else:
                student_map = {}
    except Exception:
        # If accessing st.secrets fails for any reason, fall back to file-backed creds
        pass

    # Build students structure: prefer secrets, otherwise use file
    students: List[Dict[str, Any]] = []
    used_hashes = set(file_creds.get("used_hashes", []))

    if student_pw_list:
        for pw in student_pw_list:
            h = hashlib.sha256(pw.encode("utf-8")).hexdigest()
            students.append({"pw": pw, "used": h in used_hashes, "assigned_to": None})
    elif student_map:
        for username, pw in student_map.items():
            h = hashlib.sha256(f"{username}:{pw}".encode("utf-8")).hexdigest()
            students.append({"username": username, "pw": pw, "used": h in used_hashes, "assigned_to": None})
    else:
        # fallback to file-backed student list (legacy)
        students = file_creds.get("students", [])
        # Recompute 'used' flags based on stored hashes to avoid stale state
        if isinstance(students, list):
            recomputed = []
            for s in students:
                try:
                    if not isinstance(s, dict):
                        continue
                    username = s.get("username")
                    pw = s.get("pw", "")
                    token = f"{username}:{pw}" if username else pw
                    h = hashlib.sha256(str(token).encode("utf-8")).hexdigest()
                    s["used"] = h in used_hashes
                    # Ensure expected fields exist
                    if "assigned_to" not in s:
                        s["assigned_to"] = None
                    recomputed.append(s)
                except Exception:
                    recomputed.append(s)
            students = recomputed

    # Admin: return both single password and admin_map (if present)
    if admin_pw is None:
        admin_pw = file_creds.get("admin")
    admin_map_file = file_creds.get("admin_map", {})

    # Merge file-admin-map only if secrets not provided
    if not admin_map and isinstance(admin_map_file, dict):
        admin_map = {str(k): str(v) for k, v in admin_map_file.items()}

    return {"admin": admin_pw, "admin_map": admin_map, "students": students, "created_at": file_creds.get("created_at")}

def save_credentials(creds: Dict[str, Any]):
    with open(CREDENTIALS_PATH, "w", encoding="utf-8") as f:
        json.dump(creds, f, indent=2)


def load_participants() -> List[Dict[str, Any]]:
    """Load persisted participants from disk. Decodes any base64-encoded image data.

    Returns empty list when missing/invalid.
    """
    try:
        if os.path.exists(PARTICIPANTS_PATH):
            with open(PARTICIPANTS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    # Decode any base64 image payloads back into bytes for in-memory use
                    for p in data:
                        try:
                            # New format: images -> [{ name, data_b64, ai }]
                            if isinstance(p, dict) and isinstance(p.get("images"), list):
                                decoded_images = []
                                for img in p["images"]:
                                    if not isinstance(img, dict):
                                        continue
                                    name = img.get("name")
                                    ai = img.get("ai")
                                    data_b64 = img.get("data_b64")
                                    payload = None
                                    if isinstance(data_b64, str):
                                        try:
                                            payload = base64.b64decode(data_b64)
                                        except Exception:
                                            payload = None
                                    decoded_images.append({
                                        "name": name,
                                        "data": payload,
                                        "ai": ai or {"themes": [], "description": "", "embedding": []}
                                    })
                                p["images"] = decoded_images

                            # Back-compat: single image_data_b64 field
                            if "image_data_b64" in p and isinstance(p.get("image_data_b64"), str):
                                try:
                                    p["image_data"] = base64.b64decode(p["image_data_b64"])
                                except Exception:
                                    p["image_data"] = None
                        except Exception:
                            # Keep participant entry even if one image fails to decode
                            logger.exception("Failed to decode participant image data")
                    return data
    except Exception:
        logger.exception("Failed to load participants from disk")
    return []


def save_participants(participants: List[Dict[str, Any]]):
    """Persist participants to disk atomically.

    Ensures JSON-serializability by base64-encoding any image bytes.
    """
    try:
        # Build a JSON-safe copy
        safe_list: List[Dict[str, Any]] = []
        for p in participants:
            try:
                if not isinstance(p, dict):
                    continue
                q = {k: v for k, v in p.items() if k not in ("images", "image_data")}

                # Handle images list
                if isinstance(p.get("images"), list):
                    safe_images = []
                    for img in p["images"]:
                        if not isinstance(img, dict):
                            continue
                        name = img.get("name")
                        ai = img.get("ai")
                        data_bytes = img.get("data")
                        data_b64 = None
                        if isinstance(data_bytes, (bytes, bytearray)):
                            try:
                                data_b64 = base64.b64encode(bytes(data_bytes)).decode("utf-8")
                            except Exception:
                                data_b64 = None
                        safe_images.append({
                            "name": name,
                            "data_b64": data_b64,
                            "ai": ai or {"themes": [], "description": "", "embedding": []}
                        })
                    q["images"] = safe_images

                # Back-compat: single image_data -> image_data_b64
                if isinstance(p.get("image_data"), (bytes, bytearray)):
                    try:
                        q["image_data_b64"] = base64.b64encode(bytes(p["image_data"])).decode("utf-8")
                    except Exception:
                        q["image_data_b64"] = None

                safe_list.append(q)
            except Exception:
                logger.exception("Failed to serialize a participant; skipping entry")

        tmp = PARTICIPANTS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(safe_list, f, indent=2)
        # atomic replace
        os.replace(tmp, PARTICIPANTS_PATH)
    except Exception:
        logger.exception("Failed to save participants to disk")


def load_sessions() -> Dict[str, Any]:
    """Load sessions mapping (sid -> session data). Returns empty dict if missing/invalid."""
    try:
        if os.path.exists(SESSIONS_PATH):
            with open(SESSIONS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
    except Exception:
        logger.exception("Failed to load sessions from disk")
    return {}


def save_sessions(sessions: Dict[str, Any]):
    """Persist sessions mapping atomically."""
    try:
        tmp = SESSIONS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(sessions, f, indent=2)
        os.replace(tmp, SESSIONS_PATH)
    except Exception:
        logger.exception("Failed to save sessions to disk")


# --- Username-scoped session persistence (for re-login across devices) ---
def _minimal_state_from_session() -> Dict[str, Any]:
    return {
        "authenticated": bool(st.session_state.get("authenticated", False)),
        "is_admin": bool(st.session_state.get("is_admin", False)),
        "admin_username": st.session_state.get("admin_username"),
        "student_username": st.session_state.get("student_username"),
        "current_step": int(st.session_state.get("current_step", 1)),
        "user_profile": st.session_state.get("user_profile", {}),
        "user_completed": bool(st.session_state.get("user_completed", False)),
    }

def load_user_sessions() -> Dict[str, Any]:
    try:
        if os.path.exists(USER_SESSIONS_PATH):
            with open(USER_SESSIONS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
    except Exception:
        logger.exception("Failed to load user sessions from disk")
    return {}

def save_user_sessions(mapping: Dict[str, Any]):
    try:
        tmp = USER_SESSIONS_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(mapping, f, indent=2)
        os.replace(tmp, USER_SESSIONS_PATH)
    except Exception:
        logger.exception("Failed to save user sessions to disk")

def save_user_session_for_current(username: str):
    if not username:
        return
    mapping = load_user_sessions()
    mapping[str(username)] = _minimal_state_from_session()
    save_user_sessions(mapping)

def load_user_session(username: str) -> Dict[str, Any]:
    if not username:
        return {}
    mapping = load_user_sessions()
    return mapping.get(str(username), {})


def save_current_session(sid: str):
    """Save minimal, non-sensitive parts of st.session_state under sid."""
    if not sid:
        return
    sessions = load_sessions()
    # Minimal session shape
    sessions[sid] = {
        "authenticated": bool(st.session_state.get("authenticated", False)),
        "is_admin": bool(st.session_state.get("is_admin", False)),
        "admin_username": st.session_state.get("admin_username"),
        "student_username": st.session_state.get("student_username"),
        "current_step": int(st.session_state.get("current_step", 1)),
        "user_profile": st.session_state.get("user_profile", {}),
        "user_completed": bool(st.session_state.get("user_completed", False)),
    }
    save_sessions(sessions)


def load_session_into_state(sid: str):
    """Load a saved session (if present) into st.session_state. Returns True when loaded."""
    if not sid:
        return False
    sessions = load_sessions()
    data = sessions.get(sid)
    if not data:
        return False
    # Populate safe fields
    st.session_state.authenticated = bool(data.get("authenticated", False))
    st.session_state.is_admin = bool(data.get("is_admin", False))
    if data.get("admin_username"):
        st.session_state.admin_username = data.get("admin_username")
    if data.get("student_username"):
        st.session_state.student_username = data.get("student_username")
    st.session_state.current_step = int(data.get("current_step", 1))
    st.session_state.user_profile = data.get("user_profile", {})
    st.session_state.user_completed = bool(data.get("user_completed", False))
    return True


def _hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


def mark_student_used(token: str):
    """Record a student's credential token as used by hashing it and storing the hash in the file-backed credentials.

    token should be either a password (legacy) or a "username:password" string when STUDENT_MAP is used.
    We avoid writing raw secrets to disk; only the hash is persisted to enforce single-use.
    """
    file_creds = {}
    if os.path.exists(CREDENTIALS_PATH):
        try:
            with open(CREDENTIALS_PATH, "r", encoding="utf-8") as f:
                file_creds = json.load(f)
        except Exception:
            file_creds = {}

    used_hashes = set(file_creds.get("used_hashes", []))
    used_hashes.add(_hash_pw(token))
    file_creds["used_hashes"] = list(used_hashes)
    file_creds["created_at"] = datetime.utcnow().isoformat()
    # Only persist used_hashes (and created_at) to avoid storing raw passwords from secrets
    try:
        with open(CREDENTIALS_PATH, "w", encoding="utf-8") as f:
            json.dump({"used_hashes": file_creds["used_hashes"], "created_at": file_creds.get("created_at")}, f, indent=2)
    except Exception:
        # If saving fails, do not crash the app; just log
        logger.exception("Failed to persist used student credential hash")


# Removed automatic rerun logic per user request. The app will not attempt to programmatically
# trigger reruns; the user will refresh or restart the app manually when needed.

def generate_password(length: int = 8) -> str:
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def init_credentials():
    creds = load_credentials()
    if not creds:
        # Create admin and 20 student passwords
        admin_pw = generate_password(10)
        students = []
        for _ in range(20):
            students.append({"pw": generate_password(8), "used": False, "assigned_to": None})

        creds = {
            "admin": admin_pw,
            "students": students,
            "created_at": datetime.utcnow().isoformat()
        }
        save_credentials(creds)
    return creds

# Initialize credentials (if not present)
_CREDS = init_credentials()

def regenerate_student_passwords(count: int = 20):
    creds = load_credentials()
    students = []
    for _ in range(count):
        students.append({"pw": generate_password(8), "used": False, "assigned_to": None})
    creds["students"] = students
    creds["created_at"] = datetime.utcnow().isoformat()
    save_credentials(creds)
    return creds

def regenerate_admin_password(length: int = 10):
    creds = load_credentials()
    new_admin = generate_password(length)
    creds["admin"] = new_admin
    creds["created_at"] = datetime.utcnow().isoformat()
    save_credentials(creds)
    return creds

st.set_page_config(page_title="Who Might Get Along?", page_icon="🕸️", layout="wide")

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# --- Session handling (query params + server-side sessions) ---
# Generate or retrieve a stable sid via query parameters (no custom JS required).
sid = None
try:
    params = st.query_params
    sid = params.get("sid")
    if isinstance(sid, list):
        sid = sid[0] if sid else None
except Exception:
    sid = None

if not sid:
    # Create a new sid and set it in the URL so it survives refreshes
    sid = str(uuid.uuid4())
    try:
        # Set or update a single key without clobbering others
        st.query_params["sid"] = sid
    except Exception:
        pass

# If we have a sid, attempt to rehydrate minimal session state (non-sensitive)
if sid and not st.session_state.get("rehydrated_from_sid"):
    try:
        loaded = load_session_into_state(sid)
        if loaded:
            logger.info(f"Session {sid} rehydrated into st.session_state")
        else:
            # Quietly continue without a user-facing notice
            logger.debug("Session token present but no saved session data; proceeding silently")
    except Exception:
        logger.exception("Failed to load session into state")
    finally:
        # Ensure we don't overwrite live session changes on subsequent reruns
        st.session_state.rehydrated_from_sid = True

# Initialize logs in session state
if "logs" not in st.session_state:
    st.session_state.logs = []

# ---------- Authentication / Credentials (simple, file-backed) ----------
if "authenticated" not in st.session_state:
    st.session_state.authenticated = False
if "is_admin" not in st.session_state:
    st.session_state.is_admin = False
if "student_pw" not in st.session_state:
    st.session_state.student_pw = None

# If not authenticated, show a simple login screen and stop further rendering
if not st.session_state.authenticated:
    st.title("🕸️ Who Might Get Along? — Login")
    st.caption("Provide your credentials to continue. If credentials are set in Streamlit Secrets, manage them there.")
    
    # --- DEBUG: show non-sensitive secrets presence (keys and counts only) ---
    try:
        secrets_keys = list(st.secrets.keys()) if hasattr(st, "secrets") and st.secrets else []
    except Exception:
        secrets_keys = []

    creds = load_credentials()
    students = creds.get("students", [])
    # Detect whether students are username->password mapped OR an admin_map exists
    # (if admin_map is present we need a username field for admin login too)
    username_mode = bool(creds.get("admin_map")) or any(isinstance(s, dict) and s.get("username") for s in students)

    with st.form("login_form"):
        # Always show username field (user can leave it blank for legacy admin-password-only flow)
        username = st.text_input("Username (leave blank if not applicable)")
        pw = st.text_input("Password", type="password")

        submit = st.form_submit_button("Log in")

        if submit:
            creds = load_credentials()
            admin_pw = creds.get("admin")
            admin_map = creds.get("admin_map", {})
            logged_in = False

            # Admin login
            # If an admin_map is provided (secrets-managed), require admin username+password
            if admin_map:
                if username and pw and username in admin_map and pw == admin_map.get(username):
                    st.session_state.authenticated = True
                    st.session_state.is_admin = True
                    st.session_state.admin_username = username
                    st.success("Logged in as admin")
                    try:
                        save_current_session(sid)
                    except Exception:
                        logger.exception("Failed to save session after admin login")
                    logged_in = True
            else:
                # Legacy admin: password-only (no username required)
                if pw and admin_pw and pw == admin_pw:
                    st.session_state.authenticated = True
                    st.session_state.is_admin = True
                    st.success("Logged in as admin")
                    try:
                        save_current_session(sid)
                    except Exception:
                        logger.exception("Failed to save session after admin login")
                    logged_in = True

            # Student login (only if not already logged in as admin)
            if not st.session_state.get("authenticated"):
                matched = None

                if username_mode:
                    # Require both username and password
                    if not username or not pw:
                        st.error("Please enter both username and password.")
                    else:
                        for s in students:
                            if s.get("username") == username and s.get("pw") == pw:
                                matched = s
                                break
                else:
                    # Legacy: password-only list
                    for s in students:
                        if s.get("pw") == pw:
                            matched = s
                            break

                if matched is None:
                    st.error("Invalid credentials. Please check your username/password or use the admin password.")
                else:
                    if matched.get("used") and not (username_mode and matched.get("username") == username):
                        # In username+password mode, allow the same student to log in again with their own credentials.
                        # In password-only mode, keep single-use enforcement.
                        st.error("This credential was already used. If this is your account, ask the teacher to enable re-login with username.")
                    else:
                        # mark as used (persist only the hash) so secrets-managed credentials remain secret
                        try:
                            if username_mode:
                                token = f"{matched.get('username')}:{matched.get('pw')}"
                            else:
                                token = matched.get("pw")
                            mark_student_used(token)
                        except Exception:
                            logger.exception("Failed to mark student credential as used")

                        st.session_state.authenticated = True
                        st.session_state.is_admin = False
                        # store minimal indicator (do not store raw password)
                        st.session_state.student_pw = matched.get("pw")
                        st.session_state.student_username = matched.get("username") if matched.get("username") else None
                        st.success("Logged in as student")
                        # If we are in username mode, try loading their saved session state
                        try:
                            if username_mode and st.session_state.student_username:
                                prior = load_user_session(st.session_state.student_username)
                                if prior:
                                    st.session_state.current_step = int(prior.get("current_step", st.session_state.current_step))
                                    st.session_state.user_profile = prior.get("user_profile", st.session_state.user_profile)
                                    st.session_state.user_completed = bool(prior.get("user_completed", st.session_state.user_completed))
                        except Exception:
                            logger.exception("Failed to load prior user session by username")
                        try:
                            save_current_session(sid)
                        except Exception:
                            logger.exception("Failed to save session after student login")
                        try:
                            if username_mode and st.session_state.student_username:
                                save_user_session_for_current(st.session_state.student_username)
                        except Exception:
                            logger.exception("Failed to save user-scoped session after login")
                        logged_in = True

            # If we logged in successfully (admin or student), rerun to render the app
            if logged_in:
                st.rerun()

    # Stop further rendering until logged in (if login didn't happen this run)
    if not st.session_state.authenticated:
        st.stop()

def log(message: str, level: str = "INFO"):
    """Add a log entry with timestamp"""
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = f"[{timestamp}] {level}: {message}"
    st.session_state.logs.append(log_entry)
    logger.info(log_entry)

# ---------- Participants (shared across sessions) ----------
# Load persisted participants from disk so different users see the same network
if "participants" not in st.session_state:
    st.session_state.participants = load_participants()

# Initialize user session state
if "current_step" not in st.session_state:
    st.session_state.current_step = 1
if "user_profile" not in st.session_state:
    st.session_state.user_profile = {}
if "user_completed" not in st.session_state:
    st.session_state.user_completed = False
if "openai_api_key" not in st.session_state:
    # Read from environment (or .env). Keep empty string if not set to avoid accidental costs.
    st.session_state.openai_api_key = os.getenv("OPENAI_API_KEY", "")
if "use_ai" not in st.session_state:
    st.session_state.use_ai = True

# ---------- AI Image Analysis ----------
def get_embedding(text: str, client: OpenAI) -> list:
    """
    Get embedding vector for semantic similarity.
    Returns a list of floats representing the text's semantic meaning.
    """
    try:
        log(f"Requesting embedding for text: {text[:50]}...")
        response = client.embeddings.create(
            model="text-embedding-3-small",
            input=text
        )
        log(f"✅ Embedding generated successfully ({len(response.data[0].embedding)} dimensions)")
        return response.data[0].embedding
    except Exception as e:
        log(f"❌ Embedding failed: {str(e)}", "ERROR")
        return []

def cosine_similarity(vec1: list, vec2: list) -> float:
    """
    Calculate cosine similarity between two embedding vectors.
    Returns value between 0 (completely different) and 1 (identical).
    """
    if not vec1 or not vec2:
        return 0.0
    
    import math
    dot_product = sum(a * b for a, b in zip(vec1, vec2))
    magnitude1 = math.sqrt(sum(a * a for a in vec1))
    magnitude2 = math.sqrt(sum(b * b for b in vec2))
    
    if magnitude1 == 0 or magnitude2 == 0:
        return 0.0
    
    return dot_product / (magnitude1 * magnitude2)

def analyze_image_with_ai(image_data: bytes, api_key: str) -> dict:
    """
    Use OpenAI Vision API to analyze image content.
    Also generates semantic embeddings for intelligent matching.
    Returns dict with 'themes', 'description', 'keywords', and 'embedding'
    """
    log("🤖 Starting AI image analysis...")
    
    if not api_key or api_key == "YOUR_API_KEY_HERE":
        log("❌ No valid API key provided", "ERROR")
        return {"themes": [], "description": "AI analysis not available - no API key", "keywords": [], "embedding": []}
    
    try:
        log("Creating OpenAI client...")
        client = OpenAI(api_key=api_key)
        
        # Encode image to base64
        log("Encoding image to base64...")
        base64_image = base64.b64encode(image_data).decode('utf-8')
        log(f"✅ Image encoded ({len(base64_image)} bytes)")
        
        # Call OpenAI Vision API
        log("📸 Calling OpenAI Vision API (gpt-4o-mini)...")
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "text",
                            "text": """Analyze this image and provide:
1. A brief description (one sentence)
2. 5-7 descriptive keywords/themes (like: nature, music, sports, art, technology, food, animals, etc.)

Format your response as:
DESCRIPTION: [description]
KEYWORDS: [keyword1, keyword2, keyword3, ...]"""
                        },
                        {
                            "type": "image_url",
                            "image_url": {
                                "url": f"data:image/jpeg;base64,{base64_image}"
                            }
                        }
                    ]
                }
            ],
            max_tokens=150
        )
        
        log("✅ Vision API responded successfully")
        
        # Parse response
        content = response.choices[0].message.content
        log(f"Raw AI response: {content[:100]}...")
        lines = content.split('\n')
        
        description = ""
        keywords = []
        
        for line in lines:
            if line.startswith("DESCRIPTION:"):
                description = line.replace("DESCRIPTION:", "").strip()
            elif line.startswith("KEYWORDS:"):
                keywords_str = line.replace("KEYWORDS:", "").strip()
                keywords = [k.strip() for k in keywords_str.split(',')]
        
        log(f"Parsed {len(keywords)} keywords: {keywords}")
        
        # Generate semantic embedding from keywords for intelligent matching
        # This allows "plant" and "tree" to be recognized as similar concepts
        embedding = []
        if keywords:
            combined_text = ", ".join(keywords)
            log(f"Generating semantic embedding for: {combined_text}")
            embedding = get_embedding(combined_text, client)
        
        log(f"✅ AI analysis complete! Themes: {keywords}, Embedding: {len(embedding)} dims")
        
        return {
            "description": description,
            "keywords": keywords,
            "themes": keywords,  # Use keywords as themes
            "embedding": embedding  # Semantic vector for similarity matching
        }
        
    except Exception as e:
        # Show the actual error so we know what's wrong
        import traceback
        error_details = traceback.format_exc()
        error_msg = str(e)
        
        log(f"❌ AI analysis failed: {error_msg}", "ERROR")
        
        # Check for specific error types
        if "429" in error_msg or "rate_limit" in error_msg.lower():
            log("⚠️ Rate limit hit - too many requests. Wait a minute and try again.", "WARNING")
        elif "401" in error_msg or "authentication" in error_msg.lower():
            log("⚠️ Authentication failed - check your API key", "WARNING")
        
        return {
            "description": f"AI analysis failed: {error_msg}",
            "keywords": [],
            "themes": [],
            "embedding": [],
            "error": error_details
        }

# ---------- Similarity logic ----------
def jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 0.0
    return len(a & b) / len(a | b)

def similarity(p1: Dict[str, Any], p2: Dict[str, Any], debug: bool = False) -> float:
    # Tuneable weights (now includes semantic AI similarity)
    w_hobby, w_music, w_tags, w_ai, w_free = 0.3, 0.15, 0.15, 0.3, 0.1
    
    if debug:
        log(f"Calculating similarity between {p1['name']} and {p2['name']}")
    
    s_hobby = jaccard(set(p1["hobbies"]), set(p2["hobbies"]))
    s_music = 1.0 if p1["music"] and p1["music"] == p2["music"] else 0.0
    s_tags  = jaccard(set(p1["image_tags"]), set(p2["image_tags"]))
    
    if debug:
        log(f"  Hobby similarity: {s_hobby:.2f}")
        log(f"  Music match: {s_music:.2f}")
        log(f"  Tag similarity: {s_tags:.2f}")
    
    # AI-powered SEMANTIC image similarity (understands "plant" ≈ "tree")
    # Try semantic embedding similarity first (more intelligent)
    embedding1 = p1.get("ai_embedding", [])
    embedding2 = p2.get("ai_embedding", [])
    
    if embedding1 and embedding2:
        # Use cosine similarity on embeddings - understands semantic relationships
        s_ai = cosine_similarity(embedding1, embedding2)
        if debug:
            log(f"  AI semantic similarity: {s_ai:.2f} (using embeddings)")
    else:
        # Fallback to keyword matching if embeddings not available
        ai_themes1 = set(p1.get("ai_themes", []))
        ai_themes2 = set(p2.get("ai_themes", []))
        s_ai = jaccard(ai_themes1, ai_themes2) if ai_themes1 and ai_themes2 else 0.0
        if debug:
            log(f"  AI keyword similarity: {s_ai:.2f} (no embeddings available)")
    
    # SEMANTIC fun fact comparison using embeddings (understands "labradors" ≈ "dogs")
    fun_fact_embed1 = p1.get("fun_fact_embedding", [])
    fun_fact_embed2 = p2.get("fun_fact_embedding", [])
    
    if fun_fact_embed1 and fun_fact_embed2:
        # Use semantic similarity - understands meaning, not just words
        s_free = cosine_similarity(fun_fact_embed1, fun_fact_embed2)
        if debug:
            log(f"  Fun fact SEMANTIC similarity: {s_free:.2f} ('{p1['fun_fact'][:30]}...' vs '{p2['fun_fact'][:30]}...')")
    else:
        # Fallback to word overlap if embeddings not available
        ff1 = set(p1["fun_fact"].lower().split())
        ff2 = set(p2["fun_fact"].lower().split())
        s_free = jaccard(ff1, ff2)
        if debug:
            log(f"  Fun fact word overlap: {s_free:.2f} (basic matching)")
    
    total = w_hobby*s_hobby + w_music*s_music + w_tags*s_tags + w_ai*s_ai + w_free*s_free
    
    if debug:
        log(f"  TOTAL SIMILARITY: {total:.2%}")
    
    return total

def build_graph(participants: List[Dict[str, Any]], threshold: float = 0.35):
    G = nx.Graph()
    for p in participants:
        # Build simple tooltip (PyVis shows this as plain text on hover)
        tooltip_parts = [f"Name: {p['name']}"]
        if p['music']:
            tooltip_parts.append(f"Music: {p['music']}")
        if p['hobbies']:
            tooltip_parts.append(f"Hobbies: {', '.join(p['hobbies'])}")
        if p['image_tags']:
            tooltip_parts.append(f"Tags: {', '.join(p['image_tags'])}")
        if p.get('ai_themes'):
            tooltip_parts.append(f"AI detected: {', '.join(p.get('ai_themes', []))}")
        
        tooltip = " | ".join(tooltip_parts)
        
        G.add_node(p["id"], 
                  label=p["name"], 
                  title=tooltip)
    
    for i in range(len(participants)):
        for j in range(i+1, len(participants)):
            s = similarity(participants[i], participants[j])
            if s >= threshold:
                # Edge weight controls thickness in PyVis; keep tooltip simple for students
                G.add_edge(
                    participants[i]["id"],
                    participants[j]["id"],
                    weight=1 + 5*s,
                    title=f"Match: {s:.0%}",
                )
    return G

def render_pyvis(G: nx.Graph, height: str = "650px"):
    from pyvis.network import Network

    try:
        nt = Network(height=height, width="100%", bgcolor="#ffffff", font_color="black", notebook=False, directed=False)
        nt.force_atlas_2based(gravity=-50)  # optional, nice default layout
        
        # Add nodes manually instead of using from_nx
        for node_id, node_data in G.nodes(data=True):
            nt.add_node(node_id, 
                       label=node_data.get('label', str(node_id)),
                       title=node_data.get('title', ''),
                       size=18)
        
        # Add edges manually
        for edge in G.edges(data=True):
            nt.add_edge(edge[0], edge[1], 
                       width=edge[2].get('weight', 1),
                       title=edge[2].get('title', ''))

        # Set options using the physics configuration
        nt.set_options("""
        {
          "nodes": { "shape": "dot", "size": 18, "borderWidth": 1 },
          "edges": { "smooth": true, "color": { "inherit": true }, "width": 1 },
          "physics": { "stabilization": { "iterations": 150 } }
        }
        """)

        # Generate HTML directly in memory (no file saving)
        html = nt.generate_html()

        st.components.v1.html(html, height=int(height.replace("px", "")), scrolling=True)
        
    except Exception as e:
        st.error(f"Error rendering network: {str(e)}")
        st.info("Displaying participant connections as text instead:")
        for edge in G.edges(data=True):
            node1_name = G.nodes[edge[0]]['label']
            node2_name = G.nodes[edge[1]]['label']
            similarity = edge[2].get('title', 'Unknown similarity')
            st.write(f"🔗 {node1_name} ↔ {node2_name} ({similarity})")

# ---------- UI ----------
st.title("🕸️ Who Might Get Along?")
st.caption("✨ Powered by AI image analysis")

# Show AI status in sidebar (no key exposure)
with st.sidebar:
    st.markdown("---")
    
    # AI Mode Toggle - store in session state
    use_ai = st.checkbox("Enable AI Analysis", 
                         value=st.session_state.get("use_ai", True), 
                         help="Requires OpenAI API credits",
                         key="ai_toggle")
    st.session_state.use_ai = use_ai
    
    if use_ai:
        if st.session_state.openai_api_key and st.session_state.openai_api_key != "YOUR_API_KEY_HERE":
            st.success("🤖 AI Image Analysis: Active")
            st.caption("Images will be analyzed automatically")
        else:
            st.info("🤖 AI Image Analysis: Inactive")
            st.caption("Add your OpenAI API key in the code to enable AI features")
    else:
        st.warning("🤖 AI Analysis: Disabled")
        st.caption("Using manual tags only (no API costs)")
    
    st.markdown("---")
    # Logout control for any authenticated user
    if st.session_state.get("authenticated"):
        if st.button("🚪 Log out"):
            st.session_state.authenticated = False
            st.session_state.is_admin = False
            st.session_state.admin_username = None
            st.session_state.student_username = None
            st.session_state.student_pw = None
            # Keep participants; reset wizard step for a fresh start next time
            st.session_state.current_step = 1
            try:
                save_current_session(sid)
            except Exception:
                logger.exception("Failed to save session on logout")
            st.rerun()
    
    # Admin panel (only visible to admin users)
    if st.session_state.get("authenticated") and st.session_state.get("is_admin"):
        with st.expander("🔒 Admin Panel", expanded=False):
            creds = load_credentials()
            # Detect if Streamlit secrets are being used
            secrets_in_use = False
            try:
                if hasattr(st, "secrets") and st.secrets:
                    if "ADMIN_PASSWORD" in st.secrets or "STUDENT_PASSWORDS" in st.secrets or "ADMIN_MAP" in st.secrets or "STUDENT_MAP" in st.secrets:
                        secrets_in_use = True
            except Exception:
                secrets_in_use = False

            if secrets_in_use:
                st.info("Credentials are managed via Streamlit Secrets. Raw passwords are not shown here.")
                students = creds.get("students", [])
                total = len(students)
                used = sum(1 for s in students if s.get("used"))
                st.write(f"Student passwords: {total} total ({used} used)")

                st.write("Admin password: Managed in Streamlit Secrets")

            else:
                st.write("**Admin password (current):**")
                st.code(creds.get("admin", "(not set)"))

                st.write("**Student passwords (pw / used)**")
                students = creds.get("students", [])
                for i, s in enumerate(students, start=1):
                    used = s.get("used", False)
                    st.write(f"{i}. {s.get('pw')} — {'USED' if used else 'AVAILABLE'}")

                if st.button("🔁 Regenerate all student passwords"):
                    creds = regenerate_student_passwords(len(students) if students else 20)
                    st.success("Student passwords regenerated. Check the displayed list or download credentials.json")

                if st.button("🔐 Regenerate admin password"):
                    creds = regenerate_admin_password()
                    st.success("Admin password regenerated and stored in credentials.json")

            # Allow download of credentials.json
            try:
                with open(CREDENTIALS_PATH, "r", encoding="utf-8") as f:
                    data_bytes = f.read().encode("utf-8")
                st.download_button("📥 Download credentials.json", data=data_bytes, file_name="credentials.json", mime="application/json")
            except Exception as e:
                st.warning("Could not read credentials.json for download: " + str(e))

    # Log viewer
    st.subheader("📋 Activity Logs")
    if st.button("Clear Logs"):
        st.session_state.logs = []
    
    if st.session_state.logs:
        log_container = st.container(height=400)
        with log_container:
            for log_entry in st.session_state.logs[-50:]:  # Show last 50 logs
                # Color code by level
                if "ERROR" in log_entry:
                    st.error(log_entry)
                elif "WARNING" in log_entry:
                    st.warning(log_entry)
                elif "✅" in log_entry:
                    st.success(log_entry)
                else:
                    st.caption(log_entry)
    else:
        st.caption("No logs yet")

# Progress indicator
progress_cols = st.columns(3)
with progress_cols[0]:
    if st.session_state.current_step >= 1:
        st.success("✅ Step 1: Profile Info")
    else:
        st.info("1️⃣ Profile Info")

with progress_cols[1]:
    if st.session_state.current_step >= 2:
        st.success("✅ Step 2: Images & Tags")
    else:
        st.info("2️⃣ Images & Tags")

with progress_cols[2]:
    if st.session_state.current_step >= 3:
        st.success("✅ Step 3: View Network")
    else:
        st.info("3️⃣ View Network")

st.markdown("---")

# STEP 1: Profile Information
if st.session_state.current_step == 1:
    st.subheader("Step 1: Tell us about yourself!")
    st.caption("Fill in all required fields to continue")
    
    with st.form("profile_form"):
        name = st.text_input("Name or alias *", value=st.session_state.user_profile.get("name", ""))
        hobbies = st.multiselect(
            "Pick some hobbies *",
            ["Gaming", "Football", "Basketball", "Coding", "Music", "Art", "Reading", "Skateboarding", "Cooking", "Photography"],
            default=st.session_state.user_profile.get("hobbies", [])
        )
        music = st.selectbox(
            "Favourite music *", 
            ["", "Pop", "Hip-Hop", "Rock", "Indie", "Electronic", "Classical", "Metal", "K-Pop"],
            index=0 if not st.session_state.user_profile.get("music") else 
                  ["", "Pop", "Hip-Hop", "Rock", "Indie", "Electronic", "Classical", "Metal", "K-Pop"].index(st.session_state.user_profile.get("music"))
        )
        fun_fact = st.text_input("One-liner fun fact *", value=st.session_state.user_profile.get("fun_fact", ""), 
                                placeholder="e.g., 'I love ramen and can eat it every day!'")
        
        submitted = st.form_submit_button("Continue to Step 2 →")
        
        if submitted:
            if not name.strip():
                st.error("Please enter your name or alias")
            elif not hobbies:
                st.error("Please select at least one hobby")
            elif not music:
                st.error("Please select your favorite music genre")
            elif not fun_fact.strip():
                st.error("Please share a fun fact about yourself")
            else:
                st.session_state.user_profile = {
                    "name": name.strip(),
                    "hobbies": hobbies,
                    "music": music,
                    "fun_fact": fun_fact.strip()
                }
                st.session_state.current_step = 2
                try:
                    save_current_session(sid)
                except Exception:
                    logger.exception("Failed to save session after moving to step 2")
                # Immediately navigate to Step 2 after a valid submission
                try:
                    if st.session_state.get("student_username"):
                        save_user_session_for_current(st.session_state.get("student_username"))
                except Exception:
                    logger.exception("Failed to save user session after moving to step 2")
                st.rerun()
# STEP 2: Images and Tags
elif st.session_state.current_step == 2:
    st.subheader("Step 2: Show us your personality!")
    st.caption("Upload images and add tags that represent you")
    
    uploaded_files = st.file_uploader("Upload up to 2 images that represent you", type=["png","jpg","jpeg"], accept_multiple_files=True)

    # Show preview if uploaded
    if uploaded_files:
        # uploaded_files is a list when accept_multiple_files=True
        if len(uploaded_files) > 2:
            st.error("Please upload at most 2 images.")
        else:
            cols = st.columns(len(uploaded_files))
            for i, uf in enumerate(uploaded_files):
                try:
                    cols[i].image(uf, width=300, caption=f"Preview: {uf.name}")
                except Exception:
                    cols[i].caption(f"Preview not available for {uf.name}")
    
    # Simple tag input (fallback if streamlit-tags not available)
    image_tags_input = st.text_input("Image tags (comma-separated)", 
                                   placeholder="e.g., music, art, outdoors, food, travel",
                                   value=", ".join(st.session_state.user_profile.get("image_tags", [])))
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("← Back to Step 1"):
            st.session_state.current_step = 1
            # Persist step change and navigate immediately
            try:
                save_current_session(sid)
            except Exception:
                logger.exception("Failed to save session after back to step 1")
            st.rerun()
    
    with col2:
        if st.button("Add to Network →"):
            log(f"➕ Adding new participant: {st.session_state.user_profile['name']}")
            tags = [t.strip() for t in image_tags_input.split(",") if t.strip()]
            log(f"Manual tags: {tags}")
            
            pid = str(uuid.uuid4())[:8]
            images_list = []

            # Store image data and analyze with AI if available
            if uploaded_files:
                if len(uploaded_files) > 2:
                    st.error("Please upload 2 images or fewer.")
                else:
                    for uf in uploaded_files:
                        try:
                            log(f"Image uploaded: {uf.name}")
                            img_data = uf.getvalue()
                            img_name = uf.name
                            ai_analysis = None

                            # AI Analysis - check session state
                            if st.session_state.openai_api_key and st.session_state.get("use_ai", True):
                                with st.spinner(f"🤖 AI is analyzing {img_name}..."):
                                    ai_analysis = analyze_image_with_ai(img_data, st.session_state.openai_api_key)
                                    if ai_analysis.get("error"):
                                        st.error(f"❌ AI Analysis Failed for {img_name}")
                                    elif ai_analysis.get("themes"):
                                        st.success(f"✨ AI detected in {img_name}: {', '.join(ai_analysis['themes'])}")
                            else:
                                log("AI analysis skipped (disabled by user)")

                            images_list.append({
                                "name": img_name,
                                "data": img_data,
                                "ai": ai_analysis or {"themes": [], "description": "", "embedding": []}
                            })
                        except Exception as e:
                            log(f"Error processing uploaded file {uf.name}: {e}", "ERROR")
            
            # Generate semantic embedding for fun fact (so "I love labradors" ≈ "I love dogs")
            fun_fact_embedding = []
            if st.session_state.openai_api_key and st.session_state.get("use_ai", True):
                try:
                    log(f"Generating fun fact embedding for: '{st.session_state.user_profile['fun_fact']}'")
                    client = OpenAI(api_key=st.session_state.openai_api_key)
                    fun_fact_embedding = get_embedding(st.session_state.user_profile["fun_fact"], client)
                    if fun_fact_embedding:
                        log(f"✅ Fun fact embedding generated ({len(fun_fact_embedding)} dimensions)")
                except Exception as e:
                    log(f"⚠️ Fun fact embedding failed: {str(e)}", "WARNING")
            
            # Add to participants (with semantic embedding for smart matching)
            participant = {
                "id": pid,
                "name": st.session_state.user_profile["name"],
                "hobbies": st.session_state.user_profile["hobbies"],
                "music": st.session_state.user_profile["music"],
                "fun_fact": st.session_state.user_profile["fun_fact"],
                "images": images_list,
                "image_tags": tags,
                # For backward compatibility we collect ai_themes/embedding from first image if available
                "ai_themes": images_list[0]["ai"].get("themes", []) if images_list else [],
                "ai_description": images_list[0]["ai"].get("description", "") if images_list else "",
                "ai_embedding": images_list[0]["ai"].get("embedding", []) if images_list else [],
                "fun_fact_embedding": fun_fact_embedding  # Semantic vector for fun facts
            }
            
            log(f"✅ Participant created: {participant['name']}, AI themes: {participant['ai_themes']}, Has embedding: {len(participant['ai_embedding']) > 0}")
            
            st.session_state.participants.append(participant)
            st.session_state.user_completed = True
            st.session_state.current_step = 3
            log(f"Total participants now: {len(st.session_state.participants)}")
            # Persist participants so other users/sessions see them
            try:
                save_participants(st.session_state.participants)
            except Exception:
                logger.exception("Failed to persist participants after adding")

            # Save the user's session state (so refresh preserves their place)
            try:
                save_current_session(sid)
            except Exception:
                logger.exception("Failed to save session after adding participant")
            try:
                if st.session_state.get("student_username"):
                    save_user_session_for_current(st.session_state.get("student_username"))
            except Exception:
                logger.exception("Failed to save user session after adding participant")
            # Navigate to Step 3 immediately after adding
            st.rerun()

# STEP 3: View Network
elif st.session_state.current_step == 3:
    st.subheader("Step 3: Discover connections!")
    
    # Show user's info
    if st.session_state.user_completed:
        st.success(f"You're in the network as: **{st.session_state.user_profile['name']}** 🎉")
    
    # Controls
    col1, col2, col3 = st.columns(3)
    with col1:
        sim_threshold = st.slider(
            "Connection Threshold",
            0.0,
            1.0,
            0.20,
            0.05,
            help=(
                "Only draw a line when two students' total match is at least this number. "
                "The total mix is: hobbies (30%), images (30%), music (15%), tags (15%), fun fact (10%). "
                "Move left to see more lines; move right to show only strong matches. Try 0.20–0.30."
            ),
        )
        st.caption(f"Lines show when total match ≥ {sim_threshold:.0%}")
    with col2:
        if st.button("🔄 Refresh Network"):
            pass
    with col3:
        # Only admin can add arbitrary extra users; students can only add themselves once
        if st.session_state.is_admin:
            if st.button("➕ Add Another User (admin)"):
                st.session_state.current_step = 1
                st.session_state.user_profile = {}
                st.session_state.user_completed = False
        else:
            st.caption("Student accounts: you can add your profile only once. Ask the admin to add more participants.")
    
    # Debug: Show actual similarity scores
    if len(st.session_state.participants) >= 2:
        with st.expander("🔍 Debug: See Actual Match Scores", expanded=False):
            st.caption("This shows why people are or aren't connected:")
            
            # Check embedding status
            embeddings_count = sum(1 for p in st.session_state.participants if p.get("ai_embedding"))
            if embeddings_count > 0:
                st.info(f"✅ {embeddings_count}/{len(st.session_state.participants)} participants have semantic embeddings")
            else:
                st.warning(f"⚠️ No semantic embeddings found - using keyword matching only")
            
            for i in range(len(st.session_state.participants)):
                for j in range(i+1, len(st.session_state.participants)):
                    p1 = st.session_state.participants[i]
                    p2 = st.session_state.participants[j]
                    sim = similarity(p1, p2)
                    
                    # Debug: Show what data exists
                    st.write(f"**{p1['name']} vs {p2['name']}:**")
                    st.caption(f"  • {p1['name']} AI themes: {p1.get('ai_themes', [])}")
                    st.caption(f"  • {p2['name']} AI themes: {p2.get('ai_themes', [])}")
                    st.caption(f"  • {p1['name']} has embedding: {len(p1.get('ai_embedding', [])) > 0}")
                    st.caption(f"  • {p2['name']} has embedding: {len(p2.get('ai_embedding', [])) > 0}")
                    
                    if sim >= sim_threshold:
                        st.success(f"✅ {sim:.1%} match (CONNECTED)")
                    else:
                        st.error(f"❌ {sim:.1%} match (below {sim_threshold:.1%} threshold)")
                    
                    # Show what they have in common
                    shared_hobbies = set(p1['hobbies']) & set(p2['hobbies'])
                    same_music = p1['music'] == p2['music']
                    shared_tags = set(p1['image_tags']) & set(p2['image_tags'])
                    shared_ai = set(p1.get('ai_themes', [])) & set(p2.get('ai_themes', []))
                    
                    # Calculate semantic similarity for images
                    embedding1 = p1.get('ai_embedding', [])
                    embedding2 = p2.get('ai_embedding', [])
                    semantic_sim = cosine_similarity(embedding1, embedding2) if embedding1 and embedding2 else 0
                    
                    details = []
                    if shared_hobbies:
                        details.append(f"🎨 Shared hobbies: {', '.join(shared_hobbies)}")
                    if same_music:
                        details.append(f"🎵 Both like {p1['music']}")
                    if shared_tags:
                        details.append(f"🏷️ Shared tags: {', '.join(shared_tags)}")
                    if shared_ai:
                        details.append(f"🤖 AI keywords match: {', '.join(shared_ai)}")
                    
                    # Show semantic similarity (this catches "plant" ≈ "tree" type matches)
                    if semantic_sim > 0.7:
                        ai_themes1 = p1.get('ai_themes', [])
                        ai_themes2 = p2.get('ai_themes', [])
                        details.append(f"✨ AI semantic match: {semantic_sim:.0%} similarity")
                        details.append(f"   ({', '.join(ai_themes1[:3])} ≈ {', '.join(ai_themes2[:3])})")
                    
                    if details:
                        for detail in details:
                            st.caption(f"  • {detail}")
                    else:
                        st.caption(f"  • No obvious matches (might need lower threshold or more data)")
                    st.markdown("---")
    
    # Admin-only controls
    if st.session_state.is_admin:
        with st.expander("🔒 Admin controls", expanded=False):
            if embeddings_count == 0 and len(st.session_state.participants) > 0:
                st.warning("⚠️ Existing participants don't have semantic embeddings. Clear data and re-add them to enable semantic matching!")

            if st.button("🗑️ Clear All Data"):
                        # Clear in-memory and persisted participants
                        st.session_state.participants = []
                        save_participants([])
                        st.session_state.current_step = 1
                        st.session_state.user_profile = {}
                        st.session_state.user_completed = False
                        # Remove saved session for current sid as well
                        try:
                            if sid:
                                sessions = load_sessions()
                                if sid in sessions:
                                    sessions.pop(sid, None)
                                    save_sessions(sessions)
                        except Exception:
                            logger.exception("Failed to clear saved session for sid")
    
    # Network visualization and participant list
    col1, col2 = st.columns([2,1])
    
    with col1:
        st.subheader("Connection Network")
        # Tiny legend that doesn't overwhelm students
        st.caption("Tip: Thicker line = stronger match. Hover a line to see the match %.")

        # Add helpful explanation
        with st.expander("🔍 How to Read This Graph", expanded=False):
            st.markdown("""
            ### What you're looking at
            - Circles = each student
            - Lines = connections when two students have enough in common (above the slider)
            - Thicker lines = stronger overall match
            - Positions just help you see the lines — they don't change the score

            ### Why does it sometimes say 6/6 with only 4 students?
            With 4 students there are 6 possible pairs. The number shows
            connections made / all possible pairs. So "6/6" means everyone connects with everyone.

            ### What makes a connection
            - Hobbies you share (counts most)
            - What your images are about (if AI is on)
            - Same music choice
            - Tags you typed
            - Your fun facts

            Tip: Hover a line to see the match percent for that pair.
            """)
        
        if len(st.session_state.participants) < 2:
            st.info("Waiting for more participants to join to show connections...")
            st.caption(f"Current participants: {len(st.session_state.participants)}")
        else:
            # Calculate and show statistics
            log(f"🔨 Building graph with {len(st.session_state.participants)} participants, threshold={sim_threshold}")
            G = build_graph(st.session_state.participants, threshold=sim_threshold)
            
            total_possible = len(st.session_state.participants) * (len(st.session_state.participants) - 1) // 2
            total_connections = G.number_of_edges()
            
            log(f"Graph built: {total_connections}/{total_possible} connections above threshold")
            
            # Calculate similarities with debug mode
            for i in range(len(st.session_state.participants)):
                for j in range(i+1, len(st.session_state.participants)):
                    p1 = st.session_state.participants[i]
                    p2 = st.session_state.participants[j]
                    similarity(p1, p2, debug=True)
            
            # Find strongest connection
            strongest_edge = None
            max_similarity = 0
            for edge in G.edges(data=True):
                title = edge[2].get('title', '')
                if 'Similarity:' in title:
                    sim_value = float(title.split('Similarity:')[1].strip())
                    if sim_value > max_similarity:
                        max_similarity = sim_value
                        strongest_edge = (G.nodes[edge[0]]['label'], G.nodes[edge[1]]['label'])
            
            # Show insights
            col_a, col_b, col_c = st.columns(3)
            with col_a:
                st.metric("👥 Students", len(st.session_state.participants))
            with col_b:
                st.metric("🔗 Connections", f"{total_connections}/{total_possible}")
            with col_c:
                if strongest_edge:
                    st.metric("💪 Strongest Match", f"{max_similarity:.0%}")
                    st.caption(f"{strongest_edge[0]} ↔ {strongest_edge[1]}")
            
            render_pyvis(G)

    with col2:
        n_participants = len(st.session_state.participants)
        st.subheader(f"Participants ({n_participants})")

        tabs = st.tabs(["Connections", f"All Participants ({n_participants})"])

        # --- Tab 1: Connections (with focus + top-N controls) ---
        with tabs[0]:
            if n_participants < 2:
                st.caption("Waiting for more participants…")
            else:
                names = sorted([p['name'] for p in st.session_state.participants])
                focus = st.selectbox("Show connections for", ["Everyone"] + names, index=0)

                # Build the list of current edges (pairs) that meet the threshold
                pairs = []
                for i in range(n_participants):
                    for j in range(i+1, n_participants):
                        p1 = st.session_state.participants[i]
                        p2 = st.session_state.participants[j]
                        sim = similarity(p1, p2)
                        if sim >= sim_threshold:
                            pairs.append({"p1": p1, "p2": p2, "sim": sim})

                # Optional focus filter
                if focus != "Everyone":
                    pairs = [e for e in pairs if e["p1"]["name"] == focus or e["p2"]["name"] == focus]

                # Sort by similarity, highest first
                pairs.sort(key=lambda e: e["sim"], reverse=True)

                # Top-N control to avoid very long lists
                max_show = len(pairs) if pairs else 0
                if max_show > 0:
                    top_n = st.slider("How many to show", 3, max_show, min(10, max_show))
                    pairs = pairs[:top_n]
                else:
                    st.caption("No connections at this threshold")

                # Display the pairs with kid‑friendly reasons
                for e in pairs:
                    p1, p2, sim = e["p1"], e["p2"], e["sim"]
                    st.markdown(f"**{p1['name']} ↔ {p2['name']}** ({sim:.0%} match)")

                    shared_hobbies = set(p1['hobbies']) & set(p2['hobbies'])
                    same_music = p1['music'] == p2['music']
                    shared_tags = set(p1['image_tags']) & set(p2['image_tags'])
                    shared_ai = set(p1.get('ai_themes', [])) & set(p2.get('ai_themes', []))

                    embedding1 = p1.get('ai_embedding', [])
                    embedding2 = p2.get('ai_embedding', [])
                    semantic_sim = cosine_similarity(embedding1, embedding2) if embedding1 and embedding2 else 0

                    reasons = []
                    if shared_hobbies:
                        reasons.append(f"🎨 Hobbies you both like: {', '.join(shared_hobbies)}")
                    if same_music:
                        reasons.append(f"🎵 Both like {p1['music']} music")
                    if shared_tags:
                        reasons.append(f"🏷️ Similar tags: {', '.join(shared_tags)}")
                    if shared_ai:
                        reasons.append(f"🤖 Image keywords in common: {', '.join(sorted(shared_ai))}")
                    if semantic_sim > 0.7:
                        reasons.append(f"✨ Pictures feel similar: {semantic_sim:.0%}")

                    if reasons:
                        for r in reasons:
                            st.caption(f"  • {r}")
                    st.markdown("---")

        # --- Tab 2: All Participants ---
        with tabs[1]:
            if not st.session_state.participants:
                st.caption("No participants yet")
            else:
                for p in st.session_state.participants:
                    with st.expander(f"👤 {p['name']}"):
                        st.write(f"**Music:** {p['music']}")
                        st.write(f"**Hobbies:** {', '.join(p['hobbies'])}")
                        st.write(f"**Fun fact:** {p['fun_fact']}")
                        if p['image_tags']:
                            st.write(f"**Manual Tags:** {', '.join(p['image_tags'])}")

                        if p.get('ai_themes'):
                            st.write(f"**🤖 AI Detected:** {', '.join(p['ai_themes'])}")
                            if p.get('ai_description'):
                                st.caption(f"_{p['ai_description']}_")

                        if p.get("images"):
                            imgs = p.get("images", [])
                            for img in imgs:
                                try:
                                    st.image(img.get("data"), caption=img.get("name", "Uploaded image"))
                                except Exception:
                                    st.caption(f"📷 {img.get('name', 'uploaded image')} (display error)")
                        elif p.get("image_data"):
                            try:
                                st.image(p["image_data"], width='stretch', caption=p.get("image_name", "Uploaded image"))
                            except Exception:
                                st.caption("📷 Image uploaded (display error)")
                        elif p.get("image_path"):
                            try:
                                if os.path.exists(p["image_path"]):
                                    st.image(p["image_path"], width='stretch')
                                else:
                                    st.caption("📷 Image uploaded (file no longer available)")
                            except Exception:
                                st.caption("📷 Image uploaded (display error)")
