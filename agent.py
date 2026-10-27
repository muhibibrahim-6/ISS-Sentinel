"""ISS Cloud Security Agent - antivirus engine.

Protection layers:
  1. Signature scan      - byte signatures (EICAR + your own) over the whole file
  2. Cloud hash scan     - SHA-256 of every file against the ISS cloud threat list
                           (cached locally, so it also works offline)
  3. Heuristic engine    - score-based; a file is quarantined only at a high score,
                           a medium score shows a warning and leaves the file alone
        - executable disguised as a document/picture (MZ/ELF header, .pdf/.jpg name)
        - double extensions (report.pdf.exe) and right-to-left-override filenames
        - PE structure: packer sections, writable+executable code, high-entropy code
        - malicious script patterns (PowerShell/BAT/VBS/JS/HTA): encoded commands,
          download cradles, shadow-copy deletion, Defender tampering, ...
        - ransom notes, autorun.inf
  4. Archive scan        - ZIP contents (with zip-bomb limits)
  5. Real-time protection - watches your folders, rescans new files for 15 minutes
  6. Ransomware behavior - many existing files rewritten with random-looking data
                           (or renamed to ransomware extensions) in a short time
  7. Process scan        - running programs are scanned; detected ones are killed
                           (needs: pip install psutil - optional)
  8. USB / removable drives are scanned as soon as they are plugged in
  9. Quarantine          - files are made inert (encoded) and can be restored
 10. The portal's "Test" button runs the EICAR file through this same pipeline

Usage:
  python agent.py                  run protection (keep it running)
  python agent.py scan <folder|file>  scan a folder or a single file now
  python agent.py quick            quick scan of your watched folders
  python agent.py full             scan all fixed drives
  python agent.py list             list quarantined files
  python agent.py restore <name>   restore a quarantined file
"""
import hashlib
import json
import math
import os
import platform
import re
import shutil
import stat
import struct
import subprocess
import sys
import threading
import time
import uuid
import zipfile
from collections import Counter, deque, defaultdict

import requests

try:
    import psutil  # optional: enables process scanning and ransomware process stop
except ImportError:
    psutil = None

BASE_URL = "https://iss-antivirus.onrender.com"
CONFIG_FILE = "config.json"
QUARANTINE_DIR = "quarantine"
TEST_DIR = "iss_test"
LOG_FILE = "iss_agent.log"
THREAT_CACHE_FILE = "threats_cache.json"

CHUNK = 4 * 1024 * 1024
MAX_CONTENT_SCAN = 200 * 1024 * 1024     # signature-scan the first 200 MB of a file
MAX_HASH_BYTES = 2 * 1024 * 1024 * 1024  # files above this are skipped
ARCHIVE_MAX_ENTRIES = 500
ARCHIVE_MAX_ENTRY = 50 * 1024 * 1024
ARCHIVE_MAX_TOTAL = 500 * 1024 * 1024    # zip-bomb limit

WATCH_WINDOW = 15 * 60       # keep re-checking a new file for this long
RESCAN_INTERVAL = 30         # seconds between re-checks inside the watch window
RANSOM_WINDOW = 20           # seconds
RANSOM_THRESHOLD = 8         # suspicious file rewrites in that window in one folder
BLOCK_SCORE = 80             # heuristic score that quarantines a file
WARN_SCORE = 40              # heuristic score that only shows a warning

# ---------------------------------------------------------------- signatures
# Standard, harmless EICAR antivirus test string (split so this file is not flagged itself).
EICAR = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
SIGNATURES = {"EICAR-Test-File": EICAR.encode()}   # add more: "Name": b"bytes"

DOC_MEDIA_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
                  ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".mp3", ".mp4", ".wav",
                  ".avi", ".mkv", ".mov", ".zip", ".rar", ".7z", ".csv"}
DOUBLE_EXT_RE = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt|mp3|mp4|zip|rar|7z)"
    r"\.(exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|wsf|hta|lnk|ps1)$")

SCRIPT_EXTS = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".sh"}
NOTE_EXTS = {".txt", ".html", ".htm", ".hta", ".rtf"}

# (text to find, points, label) - searched in lower-cased script text
SCRIPT_RULES = [
    ("-encodedcommand", 30, "encoded PowerShell"), ("-enc ", 25, "encoded PowerShell"),
    ("frombase64string", 20, "base64 decode"), ("invoke-expression", 15, "dynamic execution"),
    ("iex(", 15, "dynamic execution"), ("iex (", 15, "dynamic execution"),
    ("downloadstring", 30, "download cradle"), ("downloadfile", 25, "file download"),
    ("net.webclient", 20, "web client"), ("invoke-webrequest", 15, "web request"),
    ("-executionpolicy bypass", 20, "policy bypass"), ("-ep bypass", 20, "policy bypass"),
    ("-windowstyle hidden", 20, "hidden window"), ("-w hidden", 20, "hidden window"),
    ("certutil -urlcache", 40, "certutil download"), ("certutil.exe -urlcache", 40, "certutil download"),
    ("bitsadmin /transfer", 35, "bitsadmin download"), ("mshta http", 45, "remote HTA"),
    ("regsvr32 /s /n /u /i:http", 50, "remote scriptlet"),
    ("vssadmin delete shadows", 60, "shadow copy deletion"),
    ("wmic shadowcopy delete", 60, "shadow copy deletion"),
    ("wbadmin delete catalog", 50, "backup deletion"),
    ("recoveryenabled no", 50, "recovery disabled"),
    ("set-mpreference -disablerealtimemonitoring", 60, "Defender disabled"),
    ("add-mppreference -exclusionpath", 35, "Defender exclusion"),
    ("amsiutils", 50, "AMSI bypass"), ("[reflection.assembly]::load", 30, "in-memory loader"),
    ("netsh advfirewall set allprofiles state off", 45, "firewall disabled"),
    ("schtasks /create", 15, "scheduled task"), ("currentversion\\run", 20, "startup persistence"),
    ("wscript.shell", 10, "shell object"), ("adodb.stream", 20, "binary dropper"),
    ("virtualalloc", 20, "memory allocation"),
]
NOTE_NAMES = ("readme_to_decrypt", "how_to_decrypt", "how_to_recover", "decrypt_instructions",
              "decrypt_files", "restore_my_files", "restore-my-files", "!!!read_me",
              "read_me_to_decrypt", "@please_read_me@", "help_decrypt", "your_files_are_encrypted")
NOTE_WORDS = ("your files", "encrypted", "decrypt", "bitcoin", "ransom", "private key",
              ".onion", "tor browser", "payment", "wallet")
RANSOM_EXTS = {".locked", ".encrypted", ".crypt", ".crypted", ".enc", ".lockbit", ".wncry",
               ".wnry", ".ryk", ".conti", ".akira", ".blackcat", ".hive", ".basta", ".royal",
               ".cerber", ".locky", ".zepto", ".djvu", ".stop", ".phobos", ".dharma"}
COMPRESSED_EXTS = {".zip", ".rar", ".7z", ".gz", ".bz2", ".xz", ".jpg", ".jpeg", ".png", ".gif",
                   ".webp", ".mp3", ".mp4", ".mkv", ".avi", ".mov", ".pdf", ".docx", ".xlsx",
                   ".pptx", ".apk", ".jar", ".msi", ".cab", ".iso"}
PACKER_SECTIONS = {"upx0", "upx1", "upx2", ".aspack", ".adata", ".themida", ".vmp0", ".vmp1",
                   ".petite", ".mpress1", ".mpress2", ".nsp0", ".nsp1", ".enigma1"}
PSEUDO_FS = {"/proc", "/sys", "/dev", "/run"}


def _protected_roots():
    if os.name == "nt":
        return [os.environ.get("SystemRoot", r"C:\Windows").lower() + os.sep]
    return ["/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/etc/", "/boot/", "/proc/",
            "/sys/", "/dev/", "/system/", "/library/", "/private/var/db/"]


PROTECTED = _protected_roots()

# ---------------------------------------------------------------- state
first_seen = {}                    # path -> time first noticed
last_scan = {}                     # path -> time of last scan
scan_cache = {}                    # path -> (mtime, size, db_version) of last clean scan
recent_writes = defaultdict(deque)  # folder -> (time, path) of suspicious rewrites
last_ransom_alert = {}
warned = set()
proc_cache = {}
stats = {"scanned": 0}

threat_hashes = set()
db_version = 0
last_command_id = 0


# ---------------------------------------------------------------- helpers
def load_config():
    try:
        with open(CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def device_id():
    raw = f"{uuid.getnode()}-{platform.node()}-{platform.system()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def call(path, extra=None):
    payload = {"license_key": load_config().get("license_key", ""), "device_id": device_id(),
               "device_name": platform.node() or "Unnamed PC"}
    payload.update(extra or {})
    try:
        return requests.post(BASE_URL + path, json=payload, timeout=15).json()
    except Exception:
        return {"status": "error", "message": "Server unreachable."}


def log(msg):
    line = time.strftime("%Y-%m-%d %H:%M:%S ") + msg
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def popup(title, msg):
    def run():
        print(f"[POPUP] {title}: {msg}")
        try:
            if os.name == "nt":
                import ctypes
                ctypes.windll.user32.MessageBoxW(0, msg, title, 0x30)
            elif sys.platform == "darwin":
                subprocess.run(["osascript", "-e", 'display notification "%s" with title "%s"' % (msg.replace('"', "'"), title)])
            else:
                subprocess.run(["notify-send", title, msg])
        except Exception:
            pass
    threading.Thread(target=run, daemon=True).start()


def entropy(data):
    if not data:
        return 0.0
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in Counter(data).values())


def _under(path, base):
    p, b = os.path.abspath(path).lower(), os.path.abspath(base).lower()
    return p == b or p.startswith(b.rstrip(os.sep) + os.sep)


def is_protected(path):
    p = os.path.abspath(path).lower()
    return any(p.startswith(r) for r in PROTECTED)


def excluded(path):
    return any(_under(path, e) for e in load_config().get("exclude", []))


def load_threat_cache():
    global db_version
    try:
        with open(THREAT_CACHE_FILE, "r") as f:
            threat_hashes.update(str(x).lower() for x in json.load(f))
            db_version += 1
    except Exception:
        pass


def refresh_threats():
    global db_version
    res = call("/api/agent/threats")
    if res.get("status") == "ok":
        new = {str(x).lower() for x in res.get("hashes", [])} - threat_hashes
        if new:
            threat_hashes.update(new)
            db_version += 1  # forces every file to be rescanned against the new list
            try:
                with open(THREAT_CACHE_FILE, "w") as f:
                    json.dump(sorted(threat_hashes), f)
            except OSError:
                pass


# ---------------------------------------------------------------- analysis
def analyze_pe(f, size):
    """Score a Windows executable from its structure. Returns (score, reasons)."""
    score, why = 0, []
    try:
        f.seek(0x3C)
        off = struct.unpack("<I", f.read(4))[0]
        if off < 64 or off + 24 > size:
            return 0, []
        f.seek(off)
        nt = f.read(24)
        if nt[:4] != b"PE\x00\x00":
            return 0, []
        nsec = struct.unpack_from("<H", nt, 6)[0]
        opt = struct.unpack_from("<H", nt, 20)[0]
        if nsec == 0 or nsec > 96:
            return 20, ["Malformed PE header"]
        f.seek(off + 24 + opt)
        table = f.read(40 * nsec)
        packers, rwx, hot = [], 0, 0
        for i in range(min(nsec, 10)):
            e = table[i * 40:(i + 1) * 40]
            if len(e) < 40:
                break
            name = e[:8].rstrip(b"\x00").decode("latin-1").lower()
            raw_size, raw_ptr = struct.unpack_from("<II", e, 16)
            chars = struct.unpack_from("<I", e, 36)[0]
            if name in PACKER_SECTIONS:
                packers.append(name)
            if chars & 0x20000000 and chars & 0x80000000:
                rwx += 1
            if (chars & 0x20 or chars & 0x20000000) and raw_size > 1024 and raw_ptr < size:
                f.seek(raw_ptr)
                if entropy(f.read(min(raw_size, 1 << 20))) > 7.2:
                    hot += 1
        if packers:
            score += 35
            why.append("Packed executable (" + packers[0] + ")")
        if hot:
            score += 25
            why.append("Encrypted/packed code section")
        if rwx:
            score += 10
            why.append("Writable+executable section")
    except (OSError, struct.error):
        pass
    return score, why


def analyze_script(head):
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        text = head.decode("utf-16", "ignore")
    else:
        text = head[:2 * 1024 * 1024].decode("latin-1")
    text = re.sub(r"\s+", " ", text.lower())
    score, hits = 0, []
    for needle, pts, label in SCRIPT_RULES:
        if needle in text:
            score += pts
            if label not in hits:
                hits.append(label)
    return score, (["Suspicious-Script (" + ", ".join(hits[:3]) + ")"] if hits else [])


def analyze_note(base, head):
    text = head.decode("latin-1").lower()
    s = 0
    if any(p in base for p in NOTE_NAMES):
        s += 50
    if sum(k in text for k in NOTE_WORDS) >= 3 and ("decrypt" in text or "encrypted" in text):
        s += 50
    return (s, ["Ransom-Note"]) if s else (0, [])


def scan_zip(path):
    try:
        with zipfile.ZipFile(path) as z:
            total = 0
            for i in z.infolist()[:ARCHIVE_MAX_ENTRIES]:
                total += i.file_size
                if total > ARCHIVE_MAX_TOTAL:
                    return "Suspicious-Archive (possible zip bomb)", 60
                if i.is_dir() or i.flag_bits & 1 or i.file_size > ARCHIVE_MAX_ENTRY:
                    continue
                n = i.filename.lower()
                if "\u202e" in n or DOUBLE_EXT_RE.search(os.path.basename(n)):
                    return f"Disguised-File-Extension (in archive: {i.filename})", 100
                data = z.read(i)
                for name, sig in SIGNATURES.items():
                    if sig in data:
                        return f"{name} (in archive: {i.filename})", 100
                if hashlib.sha256(data).hexdigest() in threat_hashes:
                    return f"Known-Malware-Hash (in archive: {i.filename})", 100
    except Exception:
        return None
    return None


def scan_file(path):
    """Return (threat_name, score) or None.
    score 100 = certain match, >= BLOCK_SCORE is quarantined, >= WARN_SCORE only warns.
    Raises OSError if the file cannot be read (locked / permission)."""
    base = os.path.basename(path).lower()
    if "\u202e" in path:
        return "Spoofed-Filename (right-to-left override)", 100
    if DOUBLE_EXT_RE.search(base):
        return "Disguised-File-Extension", 100
    size = os.path.getsize(path)
    if size > MAX_HASH_BYTES:
        return None
    ext = os.path.splitext(base)[1]
    heur = not is_protected(path)   # never guess on operating-system files
    overlap = max(len(s) for s in SIGNATURES.values()) - 1
    h = hashlib.sha256()
    head, tail, scanned = b"", b"", 0
    score, why = 0, []
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            if not head:
                head = chunk
            h.update(chunk)
            if scanned < MAX_CONTENT_SCAN:
                buf = tail + chunk
                for name, sig in SIGNATURES.items():
                    if sig in buf:
                        return name, 100
                tail = buf[-overlap:]
                scanned += len(chunk)
        if h.hexdigest() in threat_hashes:
            return "Known-Malware-Hash", 100
        if heur:
            is_pe = head[:2] == b"MZ"
            if (is_pe or head[:4] == b"\x7fELF") and ext in DOC_MEDIA_EXTS:
                score += 85
                why.append("Executable disguised as " + ext)
            if is_pe:
                s, w = analyze_pe(f, size)
                score += min(s, 60)
                why += w
    if ext == ".zip" and zipfile.is_zipfile(path):
        hit = scan_zip(path)
        if hit:
            return hit
    if heur:
        if ext in SCRIPT_EXTS:
            s, w = analyze_script(head)
            score += s
            why += w
        if ext in NOTE_EXTS and size < 65536:
            s, w = analyze_note(base, head)
            score += s
            why += w
        if base == "autorun.inf" and (b"open=" in head.lower() or b"shellexecute=" in head.lower()):
            score += 40
            why.append("Autorun entry")
    if score >= WARN_SCORE:
        return "Heuristic: " + "; ".join(why[:3]), min(score, 100)
    return None


# ---------------------------------------------------------------- ransomware behavior
def register_write(folder, path, rewritten):
    """Count a changed file if it looks like ransomware touched it. True = alert now."""
    ext = os.path.splitext(path)[1].lower()
    suspicious = ext in RANSOM_EXTS
    if not suspicious and rewritten and ext not in COMPRESSED_EXTS:
        try:
            if os.path.getsize(path) >= 4096:
                with open(path, "rb") as f:
                    suspicious = entropy(f.read(65536)) > 7.5   # looks like encrypted data
        except OSError:
            pass
    if not suspicious:
        return False
    now_t = time.time()
    dq = recent_writes[folder]
    dq.append((now_t, path))
    while dq and now_t - dq[0][0] > RANSOM_WINDOW:
        dq.popleft()
    if len({p for _, p in dq}) >= RANSOM_THRESHOLD and now_t - last_ransom_alert.get(folder, 0) > 60:
        last_ransom_alert[folder] = now_t
        return True
    return False


def stop_ransomware_suspects(folder):
    """Kill user-level programs that hold files open in the attacked folder (needs psutil)."""
    killed = []
    if not psutil:
        return killed
    home = os.path.expanduser("~")
    for p in psutil.process_iter(["pid", "exe"]):
        try:
            exe = p.info["exe"]
            if not exe or p.info["pid"] == os.getpid() or not _under(exe, home):
                continue
            if any(_under(of.path, folder) for of in p.open_files()):
                p.kill()
                killed.append(os.path.basename(exe))
        except Exception:
            continue
    return killed


def ransomware_alert(folder):
    killed = stop_ransomware_suspects(folder)
    detail = f"Ransomware-Pattern: {RANSOM_THRESHOLD}+ files rewritten in {RANSOM_WINDOW}s in {folder}"
    if killed:
        detail += " | stopped: " + ", ".join(killed)
    log("[RANSOMWARE] " + detail)
    popup("ISS Security - Ransomware behavior detected", detail)
    call("/api/agent/event", {"type": "ransomware_pattern_blocked", "command_id": 0, "detail": detail})


# ---------------------------------------------------------------- quarantine
_XOR = bytes(i ^ 0x5A for i in range(256))   # makes quarantined files non-executable


def _xor_copy(src, dst):
    with open(src, "rb") as a, open(dst, "wb") as b:
        for chunk in iter(lambda: a.read(1024 * 1024), b""):
            b.write(chunk.translate(_XOR))


def quarantine(path, threat=""):
    os.makedirs(QUARANTINE_DIR, exist_ok=True)
    dest = os.path.join(QUARANTINE_DIR, f"{int(time.time() * 1000)}_{os.path.basename(path)}.iss")
    _xor_copy(path, dest)
    try:
        try:
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        except OSError:
            pass
        os.remove(path)
    except Exception:
        os.remove(dest)
        raise
    with open(dest + ".json", "w") as f:
        json.dump({"original": os.path.abspath(path), "threat": threat,
                   "time": time.strftime("%Y-%m-%d %H:%M:%S")}, f)
    return dest


def restore(name):
    src = os.path.join(QUARANTINE_DIR, name)
    if not os.path.exists(src) and os.path.exists(src + ".iss"):
        src += ".iss"
    try:
        with open(src + ".json") as f:
            dest = json.load(f)["original"]
        if os.path.exists(dest):
            dest += ".restored"
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        _xor_copy(src, dest)
        os.remove(src)
        os.remove(src + ".json")
        print(f"[+] Restored to {dest}")
    except Exception as e:
        print(f"[Error] {e}")


def list_quarantine():
    if not os.path.isdir(QUARANTINE_DIR):
        print("[+] Quarantine is empty.")
        return
    count = 0
    for n in sorted(os.listdir(QUARANTINE_DIR)):
        if n.endswith(".iss"):
            try:
                with open(os.path.join(QUARANTINE_DIR, n) + ".json") as f:
                    m = json.load(f)
                print(f"{n}  |  {m.get('threat', '')}  |  {m.get('original', '')}  |  {m.get('time', '')}")
            except Exception:
                print(n)
            count += 1
    print(f"[+] {count} file(s) in quarantine.")


# ---------------------------------------------------------------- pipeline
def handle_file(path, command_id=0, is_test=False):
    """One pipeline for every file: detect, quarantine, warn, report.
    Used identically for the EICAR test file and for anything found during real-time
    or on-demand scanning, so a test genuinely exercises the real detection path."""
    try:
        result = scan_file(path)
    except OSError:
        return False
    if not result:
        return False
    name, score = result
    if score < BLOCK_SCORE:
        if path not in warned:
            warned.add(path)
            log(f"[WARN] {name} (score {score}): {path}")
            popup("ISS Security - Suspicious file", f"{name}\n{os.path.basename(path)}\n(not removed - please check it)")
        return False
    try:
        quarantine(path, name)
    except Exception as e:
        print(f"[!] Could not quarantine {path}: {e}")
        if is_test:
            call("/api/agent/event", {"type": "test_missed", "command_id": command_id, "detail": "could not quarantine"})
        return False
    log(f"[BLOCKED] {name}: {path}")
    popup("ISS Security - Threat blocked", f"{name} was blocked and quarantined:\n{os.path.basename(path)}")
    etype = "test_blocked" if is_test else "threat_blocked"
    call("/api/agent/event", {"type": etype, "command_id": command_id, "detail": f"{name}: {os.path.basename(path)}"})
    return True


def run_test(command_id):
    os.makedirs(TEST_DIR, exist_ok=True)
    path = os.path.join(TEST_DIR, f"eicar_test_{int(time.time())}.com")
    with open(path, "w") as f:
        f.write(EICAR)
    handle_file(path, command_id, is_test=True)
    if os.path.exists(path):  # still there = protection failed
        call("/api/agent/event", {"type": "test_missed", "command_id": command_id, "detail": "test file was not blocked"})


def scan_processes():
    """Scan the program file of every running process; stop and quarantine detected ones."""
    if not psutil:
        return
    for p in psutil.process_iter(["pid", "exe"]):
        try:
            exe = p.info["exe"]
            if not exe or p.info["pid"] in (0, 4, os.getpid()) or is_protected(exe):
                continue
            st = os.stat(exe)
            key = (st.st_mtime, st.st_size, db_version)
            if proc_cache.get(exe) == key:
                continue
            proc_cache[exe] = key
            res = scan_file(exe)
            if res and res[1] >= BLOCK_SCORE:
                p.kill()
                try:
                    p.wait(3)
                except Exception:
                    pass
                time.sleep(0.5)
                handle_file(exe)
        except Exception:
            continue


# ---------------------------------------------------------------- folders & drives
def _win_drives(kind):
    import ctypes
    k = ctypes.windll.kernel32
    mask = k.GetLogicalDrives()
    return [f"{chr(65 + i)}:\\" for i in range(26)
            if mask >> i & 1 and k.GetDriveTypeW(f"{chr(65 + i)}:\\") == kind]


def removable_drives():
    out = []
    try:
        if os.name == "nt":
            return _win_drives(2)
        for base, levels in (("/media", 2), ("/run/media", 2), ("/Volumes", 1)):
            if not os.path.isdir(base):
                continue
            level = [base]
            for _ in range(levels):
                level = [os.path.join(d, n) for d in level for n in os.listdir(d)
                         if os.path.isdir(os.path.join(d, n))]
            out += [d for d in level if os.path.realpath(d) != "/"]
    except Exception:
        pass
    return out


def fixed_drives():
    try:
        return _win_drives(3) if os.name == "nt" else ["/"]
    except Exception:
        return ["/"]


def watch_folders():
    cfg = load_config()
    home = os.path.expanduser("~")
    folders = cfg.get("watch") or [os.path.join(home, "Downloads"), os.path.join(home, "Desktop"), TEST_DIR]
    folders = [os.path.abspath(p) for p in folders if os.path.isdir(p)]
    return folders + [d for d in removable_drives() if d not in folders]


def iter_files(folder, depth):
    base = folder.rstrip(os.sep).count(os.sep)
    for root, dirs, files in os.walk(folder):
        if _under(root, QUARANTINE_DIR) or excluded(root):
            dirs[:] = []
            continue
        if root.count(os.sep) - base >= depth:
            dirs[:] = []
        else:
            dirs[:] = [d for d in dirs if os.path.join(root, d) not in PSEUDO_FS]
        for n in files:
            p = os.path.join(root, n)
            if not os.path.islink(p):
                yield root, p


def baseline(folder, seen, depth=2):
    """Remember existing files so only new or changed ones count as activity."""
    for _, p in iter_files(folder, depth):
        try:
            st = os.stat(p)
            seen[p] = (st.st_mtime, st.st_size)
        except OSError:
            pass


def scan_folder(folder, seen=None, depth=2):
    """On-demand (seen=None): scans every file.
    Real-time (seen given): a changed file is always rescanned; a file not scanned with
    the current threat list is scanned; and any file is re-checked every 30 seconds for
    its first 15 minutes, so malware that waits before acting is still caught."""
    found, now_t = 0, time.time()
    for root, p in iter_files(folder, depth):
        try:
            st = os.stat(p)
        except OSError:
            continue
        sig = (st.st_mtime, st.st_size)
        if seen is not None:
            first_seen.setdefault(p, now_t)
            changed = seen.get(p) != sig
            rewritten = changed and p in seen
            if changed:
                seen[p] = sig
            stale = scan_cache.get(p) != sig + (db_version,)
            watching = now_t - first_seen[p] < WATCH_WINDOW and now_t - last_scan.get(p, 0) >= RESCAN_INTERVAL
            if not (changed or stale or watching):
                continue
            if changed and register_write(root, p, rewritten):
                ransomware_alert(root)
        stats["scanned"] += 1
        last_scan[p] = now_t
        if handle_file(p):
            found += 1
            if seen is not None:
                for d in (seen, scan_cache, first_seen, last_scan):
                    d.pop(p, None)
        elif seen is not None:
            scan_cache[p] = sig + (db_version,)
    return found


# ---------------------------------------------------------------- main loop
def protect():
    global last_command_id
    if not load_config().get("license_key"):
        print("[Error] config.json with your license_key was not found. Download it from the Client Portal.")
        return
    res = call("/api/activate")
    if res.get("status") != "active":
        print(f"[Denied] {res.get('message', 'Activation failed')}")
        return
    print(f"[Active] {res['plan']} | devices {res['devices_used']} of {res['devices_max']} | expires {res['expiry']}")
    load_threat_cache()
    refresh_threats()
    seen, tick = {}, 0
    for f in watch_folders():
        baseline(f, seen)
    known_drives = set(removable_drives())
    print("[+] Real-time protection is running. Watching:", ", ".join(watch_folders()) or "nothing")
    if not psutil:
        print("[i] Optional: pip install psutil  (enables running-program scanning)")
    while True:
        for d in set(removable_drives()) - known_drives:   # USB just plugged in
            known_drives.add(d)
            log(f"[USB] New drive detected, scanning: {d}")
            scan_folder(d, depth=6)
            baseline(d, seen)
        known_drives &= set(removable_drives())
        for f in watch_folders():
            scan_folder(f, seen)
        if tick % 6 == 0:
            scan_processes()
            res = call("/api/agent/poll", {"since_id": last_command_id})
            if res.get("status") == "ok":
                for cmd in res.get("commands", []):
                    if cmd["type"] == "eicar_test":
                        run_test(cmd["id"])
                last_command_id = max(last_command_id, res.get("last_id", 0))
            elif res.get("status") == "denied":
                print(f"[Denied] {res.get('message')}")
        if tick % 120 == 0 and tick:
            refresh_threats()
            for d in (first_seen, last_scan, scan_cache):   # forget deleted files
                for k in [k for k in d if k not in seen]:
                    del d[k]
        tick += 1
        time.sleep(5)


def report_scan(label, found):
    print(f"[+] {label}: files scanned {stats['scanned']} | threats blocked {found}")


if __name__ == "__main__":
    args = sys.argv[1:]
    cmd = args[0] if args else ""
    if cmd == "scan" and len(args) > 1:
        load_threat_cache()
        refresh_threats()
        if os.path.isfile(args[1]):
            stats["scanned"] = 1
            report_scan("Scan", 1 if handle_file(args[1]) else 0)
        else:
            report_scan("Scan", scan_folder(args[1], depth=10))
    elif cmd == "quick":
        load_threat_cache()
        refresh_threats()
        report_scan("Quick scan", sum(scan_folder(f, depth=6) for f in watch_folders()))
    elif cmd == "full":
        load_threat_cache()
        refresh_threats()
        report_scan("Full scan", sum(scan_folder(d, depth=64) for d in fixed_drives()))
    elif cmd == "list":
        list_quarantine()
    elif cmd == "restore" and len(args) > 1:
        restore(args[1])
    else:
        try:
            protect()
        except KeyboardInterrupt:
            print("\n[+] Agent stopped.")
