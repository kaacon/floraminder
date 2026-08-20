"""
notifications.py
-----------------
Vse, kar je povezano s pošiljanjem obvestil (email + push), na enem mestu.

NASTAVITEV (environment spremenljivke):

  Email (SMTP):
    MAIL_SERVER      npr. smtp.gmail.com
    MAIL_PORT        npr. 587
    MAIL_USERNAME    tvoj email naslov
    MAIL_PASSWORD    geslo za aplikacijo (App Password, ne navadno geslo!)

  Push (Web Push / VAPID):
    VAPID_PUBLIC_KEY
    VAPID_PRIVATE_KEY
    VAPID_CLAIM_EMAIL   npr. mailto:tvoj@email.com

  VAPID ključe generiraš enkrat, npr.:
    pip install py-vapid --break-system-packages
    vapid --gen

  Če spremenljivke niso nastavljene, funkciji spodaj samo zabeležita
  v log, da pošiljanje ni konfigurirano, in se ne zrušita.
"""

import os
import json
import smtplib
import logging
from email.mime.text import MIMEText

logger = logging.getLogger("floraminder.notifications")
logging.basicConfig(level=logging.INFO)

# ---------------------------------
# EMAIL
# ---------------------------------

def posli_email(prejemnik, zadeva, vsebina):
    """Pošlje email preko SMTP. Vrne True/False glede na uspeh."""
    strežnik = os.environ.get("MAIL_SERVER")
    vrata = os.environ.get("MAIL_PORT")
    uporabnik = os.environ.get("MAIL_USERNAME")
    geslo = os.environ.get("MAIL_PASSWORD")

    if not all([strežnik, vrata, uporabnik, geslo]):
        logger.warning("Email ni konfiguriran (manjkajo MAIL_* env spremenljivke) - preskačem pošiljanje na %s", prejemnik)
        return False

    if not prejemnik:
        return False

    sporocilo = MIMEText(vsebina)
    sporocilo["Subject"] = zadeva
    sporocilo["From"] = uporabnik
    sporocilo["To"] = prejemnik

    try:
        with smtplib.SMTP(strežnik, int(vrata), timeout=10) as smtp:
            smtp.starttls()
            smtp.login(uporabnik, geslo)
            smtp.sendmail(uporabnik, [prejemnik], sporocilo.as_string())
        logger.info("Email uspešno poslan na %s", prejemnik)
        return True
    except Exception as e:
        logger.error("Napaka pri pošiljanju emaila na %s: %s", prejemnik, e)
        return False


# ---------------------------------
# WEB PUSH (obvestila v brskalniku na PC)
# ---------------------------------

def pridobi_vapid_javni_kljuc():
    return os.environ.get("VAPID_PUBLIC_KEY", "")


def posli_push(subscription_info, naslov, vsebina, ciljna_pot='/dashboard'):
    """Pošlje push obvestilo na eno naročnino (subscription). Vrne True/False.
    Če subscription ni več veljaven (uporabnik je zaprl/preklical), vrne 'expired'."""
    try:
        from pywebpush import webpush, WebPushException
    except ImportError:
        logger.warning("Paket 'pywebpush' ni nameščen (pip install pywebpush) - preskačem push.")
        return False

    zasebni_kljuc = os.environ.get("VAPID_PRIVATE_KEY")
    claim_email = os.environ.get("VAPID_CLAIM_EMAIL") or "mailto:admin@floraminder.local"

    # VAPID zahteva, da je 'sub' oblike "mailto:..." ali "https://..." -
    # če je uporabnik v .env vpisal samo golo e-pošto brez predpone, jo dodamo sami.
    if not claim_email.startswith(("mailto:", "https:")):
        claim_email = "mailto:" + claim_email

    if not zasebni_kljuc:
        logger.warning("VAPID_PRIVATE_KEY ni nastavljen - preskačem pošiljanje push obvestila.")
        return False

    try:
        webpush(
            subscription_info=subscription_info,
            data=json.dumps({"title": naslov, "body": vsebina, "url": ciljna_pot}),
            vapid_private_key=zasebni_kljuc,
            vapid_claims={"sub": claim_email},
        )
        logger.info("Push obvestilo uspešno poslano.")
        return True
    except WebPushException as e:
        # 404/410 pomeni, da je naročnina potekla ali jo je uporabnik preklical
        status = getattr(e.response, "status_code", None)
        if status in (404, 410):
            logger.info("Push naročnina ni več veljavna (status %s).", status)
            return "expired"
        logger.error("Napaka pri pošiljanju push obvestila: %s", e)
        return False


# ---------------------------------
# SHRANJEVANJE NASTAVITEV OPOMNIKOV (SQLite, tabela `reminders`)
# ---------------------------------
# Vsaka rastlina ima zdaj pravi ID (glej db.py), zato so opomniki vezani
# nanj neposredno - ni več potrebe po ročnem iskanju po (lastnik, ime).

import db as _db

def preberi_opomnik_za_rastlino(plant_id, privzeti_cas="1_dan"):
    conn = _db.get_connection()
    vrstica = conn.execute(
        'SELECT cas_opomnika, kanali, reminder_time, repeat_overdue, snoozed_until FROM reminders WHERE plant_id = ?', (plant_id,)
    ).fetchone()
    conn.close()

    if not vrstica:
        return {"cas": privzeti_cas, "kanali": [], "ura": "09:00", "ponavljaj_zamudo": True, "prelozeno_do": None}

    return {
        "cas": vrstica['cas_opomnika'],
        "kanali": [k for k in vrstica['kanali'].split(';') if k],
        "ura": vrstica['reminder_time'] or "09:00",
        "ponavljaj_zamudo": bool(vrstica['repeat_overdue']),
        "prelozeno_do": vrstica['snoozed_until'],
    }


def shrani_opomnik_nastavitve(plant_id, cas_opomnika, kanali, ura="09:00", ponavljaj_zamudo=True):
    """Posodobi (ali doda) nastavitev opomnika za eno rastlino (po ID-ju)."""
    conn = _db.get_connection()
    conn.execute(
        """INSERT INTO reminders (plant_id, cas_opomnika, kanali, reminder_time, repeat_overdue)
           VALUES (?, ?, ?, ?, ?)
           ON CONFLICT(plant_id) DO UPDATE SET cas_opomnika = excluded.cas_opomnika,
                                                kanali = excluded.kanali,
                                                reminder_time = excluded.reminder_time,
                                                repeat_overdue = excluded.repeat_overdue""",
        (plant_id, cas_opomnika, ';'.join(kanali), ura, 1 if ponavljaj_zamudo else 0)
    )
    conn.commit()
    conn.close()


def prelozi_opomnik(plant_id, do_datuma):
    """Začasno zadrži pošiljanje opomnika do navedenega datuma."""
    conn = _db.get_connection()
    conn.execute(
        """INSERT INTO reminders (plant_id, cas_opomnika, kanali, reminder_time, repeat_overdue, snoozed_until)
           VALUES (?, '1_dan', '', '09:00', 1, ?)
           ON CONFLICT(plant_id) DO UPDATE SET snoozed_until = excluded.snoozed_until""",
        (plant_id, do_datuma)
    )
    conn.commit()
    conn.close()


# Koliko dni vnaprej posamezna nastavitev pomeni obvestilo.
# Scheduler preverja opomnike vsakih pet minut, zato so minute in ure uporabne.
CAS_V_DNEH = {
    "ob_casu": 0,
    "15_min": 0,
    "1_ura": 0,
    "1_dan": 1,
    "1_teden": 7,
}
