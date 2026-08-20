"""
db.py
-----
SQLite baza za Floraminder. Uporablja vgrajen `sqlite3` modul -
ni potreben noben dodaten `pip install`.

Shema vključuje uporabnike, rastline, zgodovino nege, opomnike in
varnostne zapise:

  users            - uporabniški računi in nastavitve obveščanja
  plants           - rastline, vezane na lastnika
  watering_log     - zgodovina zalivanja
  reminders        - nastavitve opomnikov, vezane na rastlino
  care_log         - dnevnik drugih aktivnosti nege
  notification_log - zgodovina poslanih obvestil

Podatkovna baza uporablja referenčno integriteto in posamezne, ciljno
usmerjene poizvedbe. SQLite skrbi za zaklepanje pri sočasnih zahtevah.
"""

import sqlite3
import os

PROJECT_DIR = os.path.dirname(os.path.abspath(__file__))
# Relativna pot je na WSGI/cron gostovanjih nevarna, ker je delovni direktorij
# lahko drugačen ob vsakem zagonu. V produkciji zato nastavi DATABASE_PATH na
# absolutno pot izven public_html; lokalno pa se baza ohrani ob projektu.
DB_PATH = os.path.abspath(os.environ.get('DATABASE_PATH', os.path.join(PROJECT_DIR, 'floraminder.db')))


def get_connection():
    """Vrne novo povezavo do baze. Kliči za vsako operacijo posebej
    (ali uporabi 'with get_connection() as conn:')."""
    conn = sqlite3.connect(DB_PATH, timeout=30)
    conn.row_factory = sqlite3.Row  # omogoča dostop do stolpcev po imenu (vrstica['ime'])
    conn.execute('PRAGMA foreign_keys = ON')  # SQLite privzeto NE uveljavlja FK, treba vklopiti ročno
    conn.execute('PRAGMA busy_timeout = 5000')
    conn.execute('PRAGMA journal_mode = WAL')
    return conn


SHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT,
    notify_email INTEGER NOT NULL DEFAULT 1,
    push_subscription TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS plants (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    species TEXT,
    description TEXT,
    interval_days INTEGER NOT NULL,
    last_watered_date TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS watering_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plant_id INTEGER NOT NULL REFERENCES plants(id) ON DELETE CASCADE,
    watered_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS reminders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plant_id INTEGER NOT NULL UNIQUE REFERENCES plants(id) ON DELETE CASCADE,
    cas_opomnika TEXT NOT NULL DEFAULT '1_dan',
    kanali TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS care_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plant_id INTEGER NOT NULL REFERENCES plants(id) ON DELETE CASCADE,
    care_type TEXT NOT NULL,
    note TEXT,
    performed_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS notification_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    plant_id INTEGER NOT NULL REFERENCES plants(id) ON DELETE CASCADE,
    channel TEXT NOT NULL,
    scheduled_for TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE(plant_id, channel, scheduled_for)
);

CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at TEXT
);

CREATE TABLE IF NOT EXISTS notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    note_date TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_plants_owner ON plants(owner_id);
CREATE INDEX IF NOT EXISTS idx_watering_log_plant ON watering_log(plant_id);
CREATE INDEX IF NOT EXISTS idx_notes_owner_date ON notes(owner_id, note_date);
CREATE INDEX IF NOT EXISTS idx_care_log_plant_date ON care_log(plant_id, performed_at);
CREATE INDEX IF NOT EXISTS idx_notification_log_scheduled ON notification_log(plant_id, scheduled_for);
"""


def init_db():
    """Ustvari tabele, če še ne obstajajo. Varno klicati ob vsakem zagonu.
    Poleg tega poskrbi za majhne migracije sheme (dodajanje novih stolpcev
    v obstoječo bazo), da ti ni treba ročno spreminjati floraminder.db."""
    conn = get_connection()
    conn.executescript(SHEMA)
    conn.commit()

    # Migracija: če je baza narejena pred dodajanjem stolpca 'description', ga dodaj zdaj.
    obstojeci_stolpci = [vrstica['name'] for vrstica in conn.execute('PRAGMA table_info(plants)').fetchall()]
    if 'description' not in obstojeci_stolpci:
        conn.execute('ALTER TABLE plants ADD COLUMN description TEXT')
        conn.commit()
        print("Migracija: dodan stolpec 'description' v tabelo plants.")

    opomnik_stolpci = [vrstica['name'] for vrstica in conn.execute('PRAGMA table_info(reminders)').fetchall()]
    if 'reminder_time' not in opomnik_stolpci:
        conn.execute("ALTER TABLE reminders ADD COLUMN reminder_time TEXT NOT NULL DEFAULT '09:00'")
    if 'repeat_overdue' not in opomnik_stolpci:
        conn.execute('ALTER TABLE reminders ADD COLUMN repeat_overdue INTEGER NOT NULL DEFAULT 1')
    if 'snoozed_until' not in opomnik_stolpci:
        conn.execute('ALTER TABLE reminders ADD COLUMN snoozed_until TEXT')

    # E-poštni naslov je identiteta za obnovitev gesla in obvestila, zato ga
    # en račun lahko uporablja le enkrat (neodvisno od velikosti črk).
    podvojeni_emaili = conn.execute(
        '''SELECT lower(trim(email)) FROM users WHERE trim(coalesce(email, '')) != ''
           GROUP BY lower(trim(email)) HAVING COUNT(*) > 1'''
    ).fetchall()
    if not podvojeni_emaili:
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email_unique ON users(lower(trim(email))) WHERE trim(email) != ''")
    else:
        print('OPOZORILO: podvojeni e-poštni naslovi preprečujejo unikaten indeks; uredi jih v profilih.')
    conn.commit()

    conn.close()
    print(f"Baza pripravljena: {os.path.abspath(DB_PATH)}")


if __name__ == '__main__':
    init_db()
