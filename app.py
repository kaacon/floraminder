from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
import os
import json
import random
import sqlite3
import hashlib
import secrets
from datetime import datetime, timedelta
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash

# Naloži spremenljivke iz .env datoteke (če obstaja in je paket nameščen).
# Če python-dotenv ni nameščen, se aplikacija še vedno zažene normalno -
# takrat moraš env spremenljivke nastaviti ročno (glej NOTIFIKACIJE_SETUP.md).
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

import db
import notifications
from calendar_service import zgradi_koledar
from validators import (MAX_DESCRIPTION, MAX_NOTE, MAX_PLANT_NAME, MAX_SPECIES,
                        MAX_USERNAME, clean_text, valid_date, valid_email)

db.init_db()

app = Flask(__name__)
scheduler = None  # prepreči, da bi bil BackgroundScheduler odstranjen iz pomnilnika

# SECRET_KEY zdaj bere iz .env (glej .env.example). Če ni nastavljen,
# se izpiše opozorilo in uporabi začasen ključ SAMO za lokalni razvoj -
# v produkciji MORA biti nastavljen, sicer se seje izničijo ob vsakem restartu
# in nihče ne more ostati prijavljen.
_secret = os.environ.get('SECRET_KEY')
if not _secret:
    import secrets
    _secret = secrets.token_hex(32)
    print("OPOZORILO: SECRET_KEY ni nastavljen v .env - uporabljam začasen "
          "naključen ključ (seje se bodo izničile ob vsakem restartu strežnika). "
          "Dodaj SECRET_KEY=... v svojo .env datoteko.")
app.secret_key = _secret


def _veljaven_datum(vrednost):
    """Vrne datetime za veljaven ISO datum ali None."""
    return valid_date(vrednost)


def _hash_reset_zetona(zeton):
    return hashlib.sha256(zeton.encode('utf-8')).hexdigest()

# --- CSRF zaščita (Flask-WTF) ---
try:
    from flask_wtf import CSRFProtect
    CSRFProtect(app)  # samodejno doda 'csrf_token()' v vse Jinja predloge
    print("CSRF zaščita aktivna.")
except ImportError:
    print("OPOZORILO: paket 'flask-wtf' ni nameščen (pip install flask-wtf) - "
          "CSRF zaščita NI aktivna! Obrazci so ranljivi za CSRF napade.")
    app.jinja_env.globals.setdefault('csrf_token', lambda: '')

# --- Rate limiting na prijavo (Flask-Limiter) - proti brute-force napadom ---
try:
    from flask_limiter import Limiter
    from flask_limiter.util import get_remote_address
    limiter = Limiter(get_remote_address, app=app, default_limits=[])
    limit_prijave = limiter.limit("5 per minute")
    print("Rate limiting na /login aktiven (5 poskusov/minuto).")
except ImportError:
    print("OPOZORILO: paket 'flask-limiter' ni nameščen (pip install flask-limiter) - "
          "rate limiting na /login NI aktiven! Nič ne preprečuje brute-force poskusov gesel.")
    def limit_prijave(f):
        return f

# Varnejše nastavitve piškotka seje
app.config['SESSION_COOKIE_HTTPONLY'] = True   # JavaScript ne more brati piškotka (zaščita pred XSS krajo seje)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'  # ščiti pred nekaterimi CSRF napadi
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', '0') == '1'
app.config['SESSION_COOKIE_NAME'] = 'floraminder_session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=14)


def prijava_obvezna(f):
    """Enotna zaščita poti, ki zahtevajo prijavljen račun."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        if 'user' not in session:
            flash('Za to dejanje se moraš prijaviti.', 'error')
            return redirect(url_for('domov'))
        return f(*args, **kwargs)
    return wrapper


def ustvari_novo_sejo(username):
    """Ob prijavi odstrani vse stare podatke seje (zaščita pred fixation)."""
    session.clear()
    session['user'] = username
    session.permanent = True

# ---------------------------------
# POMOŽNE FUNKCIJE - SQLite
# ---------------------------------

def preberi_rastline(trenutni_uporabnik):
    """Vrne seznam rastlin prijavljenega uporabnika z njihovimi identifikatorji."""
    seznam_rastlin = []
    danasnji_datum = datetime.now()

    conn = db.get_connection()
    vrstice = conn.execute(
        """SELECT plants.id, plants.name, plants.species, plants.interval_days, plants.last_watered_date, plants.description
           FROM plants
           JOIN users ON plants.owner_id = users.id
           WHERE users.username = ?""",
        (trenutni_uporabnik,)
    ).fetchall()
    conn.close()

    for vrstica in vrstice:
        try:
            datum_zalivanja = datetime.strptime(vrstica['last_watered_date'], '%Y-%m-%d')
        except (ValueError, TypeError):
            datum_zalivanja = danasnji_datum

        dni_od_zalivanja = (danasnji_datum - datum_zalivanja).days

        seznam_rastlin.append({
            'id': vrstica['id'],
            'name': vrstica['name'],
            'species': vrstica['species'],
            'interval_days': vrstica['interval_days'],
            'days_since_watered': dni_od_zalivanja,
            'raw_date': vrstica['last_watered_date'],
            'description': vrstica['description'],
        })

    seznam_rastlin.sort(key=lambda r: r['days_since_watered'] - r['interval_days'], reverse=True)
    return seznam_rastlin

def preveri_uporabnika(username, password):
    """Preveri uporabniško ime in geslo. Podpira tudi stara gesla v čistem
    besedilu (iz prejšnje CSV verzije) - če se ujemajo, jih ob uspešni
    prijavi samodejno nadgradi v varen hash."""
    conn = db.get_connection()
    vrstica = conn.execute(
        'SELECT id, password_hash FROM users WHERE username = ?', (username,)
    ).fetchone()

    if not vrstica:
        conn.close()
        return False

    shranjeno_geslo = vrstica['password_hash']

    if shranjeno_geslo.startswith(('pbkdf2:', 'scrypt:')):
        conn.close()
        return check_password_hash(shranjeno_geslo, password)

    # Staro geslo v čistem besedilu
    if shranjeno_geslo == password:
        conn.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (generate_password_hash(password), vrstica['id'])
        )
        conn.commit()
        conn.close()
        return True

    conn.close()
    return False

def preberi_uporabnika_podatke(username):
    """Vrne celoten zapis uporabnika (email, notify_email, push_subscription) ali None."""
    conn = db.get_connection()
    vrstica = conn.execute(
        'SELECT * FROM users WHERE username = ?', (username,)
    ).fetchone()
    conn.close()
    return dict(vrstica) if vrstica else None

def dodaj_uporabnika(username, password, email='', notify_email=True):
    conn = db.get_connection()
    obstaja = conn.execute(
        'SELECT id FROM users WHERE username = ? OR lower(email) = lower(?)',
        (username, email)
    ).fetchone()
    if obstaja:
        conn.close()
        return False

    try:
        conn.execute(
            """INSERT INTO users (username, password_hash, email, notify_email, push_subscription)
               VALUES (?, ?, ?, ?, ?)""",
            (username, generate_password_hash(password), email, 1 if notify_email else 0, '')
        )
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return False
    conn.close()
    return True

def posodobi_push_subscription(username, subscription_json):
    """Shrani/posodobi push naročnino (JSON niz) za uporabnika."""
    conn = db.get_connection()
    conn.execute(
        'UPDATE users SET push_subscription = ? WHERE username = ?',
        (subscription_json, username)
    )
    conn.commit()
    conn.close()
    return True


# ---------------------------------
# POTI (Routes)
# ---------------------------------

@app.route('/')
def domov():
    if 'user' in session:
        return redirect(url_for('nadzorna_plosca'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user' in session:
        return redirect(url_for('nadzorna_plosca'))

    if request.method == 'POST':
        uporabnik = request.form.get('username', '').strip()
        geslo = request.form.get('password', '')
        potrdi_geslo = request.form.get('confirm_password', '')
        email = valid_email(request.form.get('email', ''))
        notify_email = request.form.get('notify_email') is not None

        # --- Osnovna validacija vnosov ---
        if len(uporabnik) < 3 or len(uporabnik) > MAX_USERNAME:
            flash('Uporabniško ime mora imeti od 3 do 40 znakov.', 'error')
            return redirect(url_for('register'))

        if len(geslo) < 8 or len(geslo) > 128:
            flash('Geslo mora imeti od 8 do 128 znakov.', 'error')
            return redirect(url_for('register'))

        if geslo != potrdi_geslo:
            flash('Gesli se ne ujemata!', 'error')
            return redirect(url_for('register'))

        if not email:
            flash('Vnesi veljaven e-poštni naslov.', 'error')
            return redirect(url_for('register'))

        if dodaj_uporabnika(uporabnik, geslo, email, notify_email):
            ustvari_novo_sejo(uporabnik)
            flash('Registracija uspešna! Dobrodošel v Floraminder.', 'success')
            return redirect(url_for('nadzorna_plosca'))
        else:
            flash('Uporabniško ime ali e-poštni naslov je že v uporabi.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['POST'])
@limit_prijave
def login():
    uporabnik = request.form.get('username')
    geslo = request.form.get('password')
    
    if preveri_uporabnika(uporabnik, geslo):
        ustvari_novo_sejo(uporabnik)
        flash(f'Pozdravljen nazaj, {uporabnik}! Prijava je bila uspešna.', 'success')
        return redirect(url_for('nadzorna_plosca'))
    else:
        flash('Napačno uporabniško ime ali geslo!', 'error')
        return redirect(url_for('domov'))


@app.route('/pozabljeno-geslo', methods=['GET', 'POST'])
def pozabljeno_geslo():
    """Ustvari enkraten, eno uro veljaven žeton za ponastavitev gesla."""
    if request.method == 'POST':
        email = valid_email(request.form.get('email', '')) or ''
        conn = db.get_connection()
        uporabnik = conn.execute('SELECT id, username, email FROM users WHERE lower(email) = ?', (email,)).fetchone()
        if uporabnik:
            conn.execute('DELETE FROM password_reset_tokens WHERE user_id = ? OR expires_at < ?',
                         (uporabnik['id'], datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            zeton = secrets.token_urlsafe(32)
            conn.execute('INSERT INTO password_reset_tokens (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
                         (uporabnik['id'], _hash_reset_zetona(zeton),
                          (datetime.now() + timedelta(hours=1)).strftime('%Y-%m-%d %H:%M:%S')))
            conn.commit()
            povezava = url_for('ponastavi_geslo', zeton=zeton, _external=True)
            notifications.posli_email(
                uporabnik['email'], 'Floraminder – ponastavitev gesla',
                f'Živjo, {uporabnik["username"]}!\n\nGeslo lahko ponastaviš na tej povezavi (velja 1 uro):\n{povezava}'
            )
        conn.close()
        # Enak odgovor za vse naslove prepreči ugibanje, kateri računi obstajajo.
        flash('Če račun s tem e-poštnim naslovom obstaja, smo poslali povezavo za ponastavitev gesla.', 'success')
        return redirect(url_for('domov'))
    return render_template('pozabljeno_geslo.html')


@app.route('/ponastavi-geslo/<zeton>', methods=['GET', 'POST'])
def ponastavi_geslo(zeton):
    conn = db.get_connection()
    zapis = conn.execute(
        """SELECT password_reset_tokens.id, password_reset_tokens.user_id
           FROM password_reset_tokens
           WHERE token_hash = ? AND used_at IS NULL AND expires_at >= ?""",
        (_hash_reset_zetona(zeton), datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    ).fetchone()
    if not zapis:
        conn.close()
        flash('Povezava za ponastavitev gesla je neveljavna ali je potekla.', 'error')
        return redirect(url_for('pozabljeno_geslo'))
    if request.method == 'POST':
        geslo = request.form.get('password', '')
        potrditev = request.form.get('confirm_password', '')
        if len(geslo) < 8 or len(geslo) > 128 or geslo != potrditev:
            conn.close()
            flash('Geslo mora imeti od 8 do 128 znakov in se mora ujemati s potrditvijo.', 'error')
            return redirect(url_for('ponastavi_geslo', zeton=zeton))
        conn.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                     (generate_password_hash(geslo), zapis['user_id']))
        conn.execute('UPDATE password_reset_tokens SET used_at = ? WHERE id = ?',
                     (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), zapis['id']))
        conn.commit()
        conn.close()
        flash('Geslo je uspešno spremenjeno. Zdaj se lahko prijaviš.', 'success')
        return redirect(url_for('domov'))
    conn.close()
    return render_template('ponastavi_geslo.html', zeton=zeton)

@app.route('/logout', methods=['POST'])
def logout():
    session.clear() 
    flash('Uspešno si se odjavil(a). Se vidimo kmalu!', 'success')
    return redirect(url_for('domov'))


@app.route('/profil', methods=['GET', 'POST'])
def profil():
    if 'user' not in session:
        return redirect(url_for('domov'))
    conn = db.get_connection()
    uporabnik = conn.execute('SELECT id, username, email, notify_email FROM users WHERE username = ?',
                             (session['user'],)).fetchone()
    if not uporabnik:
        conn.close()
        session.clear()
        return redirect(url_for('domov'))
    if request.method == 'POST':
        email = valid_email(request.form.get('email', ''))
        trenutno_geslo = request.form.get('current_password', '')
        novo_geslo = request.form.get('new_password', '')
        potrditev = request.form.get('confirm_password', '')
        if not email:
            flash('Vnesi veljaven e-poštni naslov.', 'error')
        elif conn.execute('SELECT id FROM users WHERE lower(email) = lower(?) AND id != ?',
                          (email, uporabnik['id'])).fetchone():
            flash('Ta e-poštni naslov je že povezan z drugim profilom.', 'error')
        elif novo_geslo and (len(novo_geslo) < 8 or len(novo_geslo) > 128 or novo_geslo != potrditev):
            flash('Novo geslo mora imeti od 8 do 128 znakov in se mora ujemati s potrditvijo.', 'error')
        elif novo_geslo:
            shranjeno_geslo = conn.execute('SELECT password_hash FROM users WHERE id = ?', (uporabnik['id'],)).fetchone()['password_hash']
            geslo_ustrezno = (check_password_hash(shranjeno_geslo, trenutno_geslo)
                               if shranjeno_geslo.startswith(('pbkdf2:', 'scrypt:')) else shranjeno_geslo == trenutno_geslo)
            if not geslo_ustrezno:
                flash('Trenutno geslo ni pravilno.', 'error')
            else:
                conn.execute('UPDATE users SET email = ?, password_hash = ? WHERE id = ?',
                             (email, generate_password_hash(novo_geslo), uporabnik['id']))
                conn.commit()
                conn.close()
                flash('Profil je shranjen.', 'success')
                return redirect(url_for('profil'))
        else:
            conn.execute('UPDATE users SET email = ? WHERE id = ?', (email, uporabnik['id']))
            if novo_geslo:
                conn.execute('UPDATE users SET password_hash = ? WHERE id = ?',
                             (generate_password_hash(novo_geslo), uporabnik['id']))
            conn.commit()
            conn.close()
            flash('Profil je shranjen.', 'success')
            return redirect(url_for('profil'))
        uporabnik = dict(uporabnik)
        uporabnik['email'] = email
    conn.close()
    return render_template('profil.html', uporabnik=uporabnik)

# ---------------------------------
# TESTNI POTI (za preverjanje nastavitev - lahko kasneje odstraniš)
# ---------------------------------

@app.route('/test-email')
def test_email():
    """Pošlje testni email na naslov, ki si ga vpisala ob registraciji.
    Obišči /test-email v brskalniku, ko si prijavljena, da preveriš nastavitve."""
    if 'user' not in session:
        flash('Za to se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))

    podatki = preberi_uporabnika_podatke(session['user'])
    email = podatki.get('email') if podatki else None

    if not email:
        flash('Tvoj račun nima shranjenega e-poštnega naslova. Dodaj ga v svojem profilu.', 'error')
        return redirect(url_for('nadzorna_plosca'))

    uspeh = notifications.posli_email(
        email,
        'Floraminder - testno sporočilo',
        'Če vidiš to sporočilo, je email konfiguracija pravilna! 🌿'
    )

    if uspeh:
        flash(f'Testni email poslan na {email}! Preveri nabiralnik (tudi vsiljeno pošto).', 'success')
    else:
        flash('Pošiljanje NI uspelo - preveri terminal (konzolo), kjer teče "python app.py", tam bo izpisan razlog.', 'error')

    return redirect(url_for('nadzorna_plosca'))

@app.route('/test-push')
def test_push():
    """Pošlje testno push obvestilo na napravo, na kateri si kliknila
    'Omogoči push obvestila'. Obišči /test-push v brskalniku, ko si prijavljena."""
    if 'user' not in session:
        flash('Za to se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))

    podatki = preberi_uporabnika_podatke(session['user'])
    subscription_raw = podatki.get('push_subscription') if podatki else None

    if not subscription_raw:
        flash('Nimaš še omogočenih push obvestil - najprej klikni "🔔 Omogoči push obvestila" na dashboardu.', 'error')
        return redirect(url_for('nadzorna_plosca'))

    try:
        subscription = json.loads(subscription_raw)
    except (json.JSONDecodeError, TypeError):
        flash('Napaka pri branju shranjene push naročnine.', 'error')
        return redirect(url_for('nadzorna_plosca'))

    rezultat = notifications.posli_push(
        subscription,
        'Floraminder - testno obvestilo',
        'Če vidiš to obvestilo, push deluje! 🌿'
    )

    if rezultat is True:
        flash('Testno push obvestilo poslano! Preveri sistemska obvestila na svojem računalniku.', 'success')
    elif rezultat == 'expired':
        flash('Push naročnina ni več veljavna - ponovno klikni "Omogoči push obvestila" na dashboardu.', 'error')
    else:
        flash('Pošiljanje NI uspelo - preveri terminal (konzolo), kjer teče "python app.py", tam bo izpisan razlog.', 'error')

    return redirect(url_for('nadzorna_plosca'))

@app.route('/test-opomniki')
def test_opomniki():
    """Ročno sproži preverjanje opomnikov (namesto čakanja na 8:00 scheduler)."""
    if 'user' not in session:
        flash('Za to se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))

    preveri_in_posli_dnevne_opomnike()
    flash('Preverjanje opomnikov je bilo sproženo ročno - če je katera rastlina danes na vrsti in imaš nastavljen kanal, bi moral email/push priti.', 'success')
    return redirect(url_for('opomniki'))

# ---------------------------------
# PUSH NOTIFIKACIJE (Web Push)
# ---------------------------------

@app.route('/push/public-key')
def push_public_key():
    """Frontend JS pokliče to pot, da dobi VAPID javni ključ za naročnino."""
    return jsonify({'publicKey': notifications.pridobi_vapid_javni_kljuc()})

@app.route('/push/subscribe', methods=['POST'])
def push_subscribe():
    """Frontend pošlje sem PushSubscription objekt (iz service workerja),
    ko uporabnik dovoli obvestila. Shranimo ga k trenutnemu uporabniku."""
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    subscription = request.get_json(silent=True)
    if not subscription:
        return jsonify({'error': 'missing subscription'}), 400

    posodobi_push_subscription(session['user'], json.dumps(subscription))
    return jsonify({'status': 'ok'})

@app.route('/dashboard')
def nadzorna_plosca():
    if 'user' not in session:
        flash('Za dostop do nadzorne plošče se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))
        
    vse_rastline = preberi_rastline(session['user'])
    
    # Preštejemo žejne in zdrave rastline v Pythonu
    zejne_count = sum(1 for r in vse_rastline if r['days_since_watered'] >= r['interval_days'])
    zdrave_count = len(vse_rastline) - zejne_count

    # Prihajajoči dogodki
    prihajajoci_dogodki = []
    danasnji_datum = datetime.now()

    for r in vse_rastline:
        zadnji_vodeni = datetime.strptime(r['raw_date'], "%Y-%m-%d")
        naslednje_zalivanje = zadnji_vodeni + timedelta(days=r['interval_days'])
        razlika_dni = (naslednje_zalivanje.date() - danasnji_datum.date()).days
        
        if razlika_dni < 0:
            status = "Zamuda!"
        elif razlika_dni == 0:
            status = "Danes"
        elif razlika_dni == 1:
            status = "Jutri"
        else:
            status = f"Čez {razlika_dni} dni"
            
        prihajajoci_dogodki.append({
            'name': r['name'],
            'datum': naslednje_zalivanje.strftime("%d. %m. %Y"),
            'status': status,
            'razlika': razlika_dni
        })
            
    prihajajoci_dogodki = sorted(prihajajoci_dogodki, key=lambda x: x['razlika'])[:5]

    koledar_podatki = zgradi_koledar(vse_rastline, danasnji_datum)

    return render_template('dashboard.html', 
                           rastline=vse_rastline, 
                           uporabnik=session['user'], 
                           prihajajoci_dogodki=prihajajoci_dogodki,
                           zejne_count=zejne_count,
                           zdrave_count=zdrave_count,
                           koledar=koledar_podatki)


@app.route('/dodaj', methods=['GET', 'POST'])
def dodaj_rastlino():
    if 'user' not in session:
        flash('Za dodajanje rastlin se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))

    if request.method == 'POST':
        ime = clean_text(request.form.get('ime'), MAX_PLANT_NAME)
        vrsta = clean_text(request.form.get('vrsta'), MAX_SPECIES)
        interval = request.form.get('interval')
        zadnje_zalivanje = valid_date(request.form.get('zadnje_zalivanje'))
        opis = clean_text(request.form.get('opis'), MAX_DESCRIPTION) or None
        trenutni_uporabnik = session['user']

        if not ime or not vrsta or not zadnje_zalivanje:
            flash('Izpolni ime, vrsto in veljaven datum zadnjega zalivanja.', 'error')
            return redirect(url_for('dodaj_rastlino'))

        zadnje_zalivanje = zadnje_zalivanje.strftime('%Y-%m-%d')
        conn = db.get_connection()
        lastnik = conn.execute('SELECT id FROM users WHERE username = ?', (trenutni_uporabnik,)).fetchone()
        if not lastnik:
            conn.close()
            flash('Napaka: uporabnik ni najden.', 'error')
            return redirect(url_for('domov'))

        try:
            interval_int = int(interval)
            if interval_int < 1 or interval_int > 3650:
                raise ValueError
        except (ValueError, TypeError):
            conn.close()
            flash('Interval zalivanja mora biti pozitivno število.', 'error')
            return redirect(url_for('dodaj_rastlino'))

        cur = conn.execute(
            """INSERT INTO plants (owner_id, name, species, interval_days, last_watered_date, description)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (lastnik['id'], ime, vrsta, interval_int, zadnje_zalivanje, opis)
        )
        conn.execute(
            'INSERT INTO watering_log (plant_id, watered_at) VALUES (?, ?)',
            (cur.lastrowid, zadnje_zalivanje)
        )
        conn.execute(
            "INSERT INTO care_log (plant_id, care_type, note, performed_at) VALUES (?, 'zalivanje', ?, ?)",
            (cur.lastrowid, 'Začetni vnos rastline', zadnje_zalivanje)
        )
        conn.commit()
        conn.close()

        flash(f'Rastlina "{ime}" je bila uspešno dodana!', 'success')
        return redirect(url_for('nadzorna_plosca'))

    return render_template('dodaj.html')

@app.route('/zalij', methods=['POST'])
def zalij_rastlino():
    if 'user' not in session:
        flash('Za to dejanje se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))

    plant_id = request.form.get('plant_id')
    trenutni_uporabnik = session['user']
    danes = datetime.now().strftime('%Y-%m-%d')

    conn = db.get_connection()
    # Preverimo lastništvo, preden karkoli spremenimo
    rastlina = conn.execute(
        """SELECT plants.id, plants.name, plants.interval_days FROM plants
           JOIN users ON plants.owner_id = users.id
           WHERE plants.id = ? AND users.username = ?""",
        (plant_id, trenutni_uporabnik)
    ).fetchone()

    if not rastlina:
        conn.close()
        flash('Rastline ni mogoče najti ali nimaš pravic zanjo.', 'error')
        return redirect(url_for('nadzorna_plosca'))

    conn.execute('UPDATE plants SET last_watered_date = ? WHERE id = ?', (danes, plant_id))
    conn.execute('INSERT INTO watering_log (plant_id, watered_at) VALUES (?, ?)', (plant_id, danes))
    conn.execute("INSERT INTO care_log (plant_id, care_type, performed_at) VALUES (?, 'zalivanje', ?)", (plant_id, danes))
    conn.commit()
    conn.close()
    naslednji = (datetime.now().date() + timedelta(days=rastlina['interval_days'])).strftime('%d. %m. %Y')
    flash(f"{rastlina['name']} je označena kot zalita. Naslednje zalivanje: {naslednji}.", 'success')
    return redirect(request.referrer or url_for('nadzorna_plosca'))

@app.route('/zalij-vec', methods=['POST'])
def zalij_vec_rastlin():
    """Množično zalivanje - uporablja se z 'Moje rastline' strani, ko uporabnik
    z checkboxi izbere več rastlin naenkrat."""
    if 'user' not in session:
        flash('Za to dejanje se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))

    plant_ids = request.form.getlist('plant_ids')
    if not plant_ids:
        flash('Nobena rastlina ni bila izbrana.', 'error')
        return redirect(url_for('my_plants'))

    trenutni_uporabnik = session['user']
    danes = datetime.now().strftime('%Y-%m-%d')

    conn = db.get_connection()
    stevilo_zalitih = 0
    for plant_id in plant_ids:
        rastlina = conn.execute(
            """SELECT plants.id FROM plants
               JOIN users ON plants.owner_id = users.id
               WHERE plants.id = ? AND users.username = ?""",
            (plant_id, trenutni_uporabnik)
        ).fetchone()
        if not rastlina:
            continue
        conn.execute('UPDATE plants SET last_watered_date = ? WHERE id = ?', (danes, plant_id))
        conn.execute('INSERT INTO watering_log (plant_id, watered_at) VALUES (?, ?)', (plant_id, danes))
        conn.execute("INSERT INTO care_log (plant_id, care_type, performed_at) VALUES (?, 'zalivanje', ?)", (plant_id, danes))
        stevilo_zalitih += 1
    conn.commit()
    conn.close()

    flash(f'Zalitih {stevilo_zalitih} rastlin! 💧', 'success')
    return redirect(url_for('my_plants'))

@app.route('/odstrani', methods=['POST'])
def odstrani_rastlino():
    if 'user' not in session:
        flash('Za to dejanje se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))

    plant_id = request.form.get('plant_id')
    trenutni_uporabnik = session['user']

    conn = db.get_connection()
    rastlina = conn.execute(
        """SELECT plants.id FROM plants
           JOIN users ON plants.owner_id = users.id
           WHERE plants.id = ? AND users.username = ?""",
        (plant_id, trenutni_uporabnik)
    ).fetchone()

    if not rastlina:
        conn.close()
        flash('Rastline ni mogoče najti ali nimaš pravic zanjo.', 'error')
        return redirect(url_for('nadzorna_plosca'))

    # ON DELETE CASCADE v shemi poskrbi, da se izbrišejo tudi watering_log in reminders zapisi
    conn.execute('DELETE FROM plants WHERE id = ?', (plant_id,))
    conn.commit()
    conn.close()

    return redirect(url_for('nadzorna_plosca'))

@app.route('/uredi/<int:plant_id>', methods=['GET', 'POST'])
def uredi_rastlino(plant_id):
    if 'user' not in session:
        flash('Za urejanje rastlin se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))

    trenutni_uporabnik = session['user']
    conn = db.get_connection()

    vrstica = conn.execute(
        """SELECT plants.* FROM plants
           JOIN users ON plants.owner_id = users.id
           WHERE plants.id = ? AND users.username = ?""",
        (plant_id, trenutni_uporabnik)
    ).fetchone()

    if not vrstica:
        conn.close()
        flash('Rastline ni mogoče najti ali pa nimate pravic za urejanje.', 'error')
        return redirect(url_for('nadzorna_plosca'))

    if request.method == 'POST':
        novo_ime = clean_text(request.form.get('ime'), MAX_PLANT_NAME)
        nova_vrsta = clean_text(request.form.get('vrsta'), MAX_SPECIES)
        nov_interval = request.form.get('interval')
        novo_zalivanje = valid_date(request.form.get('zadnje_zalivanje'))
        nov_opis = clean_text(request.form.get('opis'), MAX_DESCRIPTION) or None

        if not novo_ime or not nova_vrsta or not novo_zalivanje:
            conn.close()
            flash('Izpolni ime, vrsto in veljaven datum zadnjega zalivanja.', 'error')
            return redirect(url_for('uredi_rastlino', plant_id=plant_id))

        try:
            nov_interval_int = int(nov_interval)
            if nov_interval_int < 1 or nov_interval_int > 3650:
                raise ValueError
        except (ValueError, TypeError):
            conn.close()
            flash('Interval zalivanja mora biti pozitivno število.', 'error')
            return redirect(url_for('uredi_rastlino', plant_id=plant_id))

        novo_zalivanje = novo_zalivanje.strftime('%Y-%m-%d')
        conn.execute(
            """UPDATE plants SET name = ?, species = ?, interval_days = ?, last_watered_date = ?, description = ?
               WHERE id = ?""",
            (novo_ime, nova_vrsta, nov_interval_int, novo_zalivanje, nov_opis, plant_id)
        )
        conn.commit()
        conn.close()

        flash(f'Rastlina "{novo_ime}" je bila uspešno posodobljena.', 'success')
        return redirect(url_for('nadzorna_plosca'))

    izbrana_rastlina = {
        'id': vrstica['id'],
        'ime': vrstica['name'],
        'vrsta': vrstica['species'],
        'interval': vrstica['interval_days'],
        'zadnje_zalivanje': vrstica['last_watered_date'],
        'opis': vrstica['description'] or '',
    }
    conn.close()
    return render_template('uredi.html', rastlina=izbrana_rastlina)

@app.route('/rastlina/<int:plant_id>')
def podrobnosti_rastline(plant_id):
    """Prikaže zgodovino zalivanja (pravočasno / zamuda) in projekcijo
    prihodnjih predvidenih datumov zalivanja za eno rastlino."""
    if 'user' not in session:
        flash('Za ogled podrobnosti se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))

    trenutni_uporabnik = session['user']
    conn = db.get_connection()

    rastlina = conn.execute(
        """SELECT plants.* FROM plants
           JOIN users ON plants.owner_id = users.id
           WHERE plants.id = ? AND users.username = ?""",
        (plant_id, trenutni_uporabnik)
    ).fetchone()

    if not rastlina:
        conn.close()
        flash('Rastline ni mogoče najti ali nimaš pravic zanjo.', 'error')
        return redirect(url_for('my_plants'))

    zapisi_zalivanja = conn.execute(
        'SELECT watered_at FROM watering_log WHERE plant_id = ? ORDER BY watered_at ASC', (plant_id,)
    ).fetchall()
    nega_zapisi = conn.execute(
        'SELECT id, care_type, note, performed_at FROM care_log WHERE plant_id = ? ORDER BY performed_at DESC, id DESC LIMIT 30',
        (plant_id,)
    ).fetchall()
    conn.close()

    interval = rastlina['interval_days']

    # --- Zgodovina: za vsak zapis primerjaj razmik s prejšnjim proti intervalu ---
    zgodovina = []
    prejsnji_datum = None
    for vrstica in zapisi_zalivanja:
        try:
            trenutni_datum = datetime.strptime(vrstica['watered_at'], '%Y-%m-%d')
        except (ValueError, TypeError):
            continue

        if prejsnji_datum is None:
            status = 'Prvi zabeleženi zapis'
            razred = 'nevtralno'
        else:
            dni_vmes = (trenutni_datum - prejsnji_datum).days
            if dni_vmes <= interval:
                status = 'Pravočasno'
                razred = 'pravocasno'
            else:
                status = f'Zamuda za {dni_vmes - interval} {"dan" if dni_vmes - interval == 1 else "dni"}'
                razred = 'zamuda'

        zgodovina.append({
            'datum': trenutni_datum.strftime('%d. %m. %Y'),
            'status': status,
            'razred': razred,
        })
        prejsnji_datum = trenutni_datum

    zgodovina.reverse()  # najnovejše na vrhu

    # --- Projekcija: naslednjih 6 predvidenih datumov zalivanja naprej ---
    projekcija = []
    if prejsnji_datum is not None:
        naslednji = prejsnji_datum
        for _ in range(6):
            naslednji = naslednji + timedelta(days=interval)
            projekcija.append(naslednji.strftime('%d. %m. %Y (%A)'))

    # Slovenski nazivi dni namesto angleških (ker strftime %A vrne angleško ime)
    ANG_V_SLO_DAN = {
        'Monday': 'ponedeljek', 'Tuesday': 'torek', 'Wednesday': 'sreda',
        'Thursday': 'četrtek', 'Friday': 'petek', 'Saturday': 'sobota', 'Sunday': 'nedelja'
    }
    for ang, slo in ANG_V_SLO_DAN.items():
        projekcija = [p.replace(ang, slo) for p in projekcija]

    rastlina_info = {
        'id': rastlina['id'],
        'ime': rastlina['name'],
        'vrsta': rastlina['species'],
        'interval': interval,
        'opis': rastlina['description'],
    }

    return render_template(
        'rastlina_podrobnosti.html',
        uporabnik=trenutni_uporabnik,
        rastlina=rastlina_info,
        zgodovina=zgodovina,
        projekcija=projekcija,
        nega_zapisi=nega_zapisi,
        danes=datetime.now().strftime('%Y-%m-%d'),
    )


@app.route('/rastlina/<int:plant_id>/nega', methods=['POST'])
def dodaj_nego(plant_id):
    if 'user' not in session:
        return redirect(url_for('domov'))
    tip = request.form.get('care_type', '')
    opomba = clean_text(request.form.get('note'), MAX_NOTE)
    datum = _veljaven_datum(request.form.get('performed_at'))
    dovoljeni_tipi = {'gnojenje', 'presajanje', 'obrezovanje', 'pregled', 'skodljivci'}
    if tip not in dovoljeni_tipi or not datum:
        flash('Izberi veljaven tip nege in datum.', 'error')
        return redirect(url_for('podrobnosti_rastline', plant_id=plant_id))
    conn = db.get_connection()
    rastlina = conn.execute(
        '''SELECT plants.id FROM plants JOIN users ON plants.owner_id = users.id
           WHERE plants.id = ? AND users.username = ?''', (plant_id, session['user'])
    ).fetchone()
    if rastlina:
        conn.execute('INSERT INTO care_log (plant_id, care_type, note, performed_at) VALUES (?, ?, ?, ?)',
                     (plant_id, tip, opomba or None, datum.strftime('%Y-%m-%d')))
        conn.commit()
        flash('Dogodek nege je dodan v dnevnik.', 'success')
    else:
        flash('Rastline ni mogoče najti.', 'error')
    conn.close()
    return redirect(url_for('podrobnosti_rastline', plant_id=plant_id))

@app.route('/my-plants')
def my_plants():
    if 'user' not in session:
        return redirect(url_for('domov'))
    
    uporabnikove_rastline = preberi_rastline(session['user'])
    return render_template('my_plants.html', uporabnik=session['user'], rastline=uporabnikove_rastline)

@app.route('/calendar')
def calendar():
    if 'user' not in session:
        return redirect(url_for('domov'))
        
    trenutni_uporabnik = session['user']
    uporabnikove_rastline = preberi_rastline(trenutni_uporabnik)
    
    urnik_zalivanja = []
    danes = datetime.now()
    leto = request.args.get('year', type=int, default=danes.year)
    mesec = request.args.get('month', type=int, default=danes.month)
    if mesec < 1 or mesec > 12 or leto < 2000 or leto > 2100:
        leto, mesec = danes.year, danes.month
    izbran_mesec = datetime(leto, mesec, 1)

    for r in uporabnikove_rastline:
        zadnji_vodeni = datetime.strptime(r['raw_date'], "%Y-%m-%d")
        naslednje_zalivanje = zadnji_vodeni + timedelta(days=r['interval_days'])
        
        razlika_dni = (naslednje_zalivanje.date() - danes.date()).days
        
        if razlika_dni < 0:
            status = "Zamuda!"
        elif razlika_dni == 0:
            status = "Danes"
        elif razlika_dni == 1:
            status = "Jutri"
        else:
            status = f"Čez {razlika_dni} dni"
            
        urnik_zalivanja.append({
            'name': r['name'],
            'datum': naslednje_zalivanje.strftime("%d. %m. %Y"),
            'status': status,
            'razlika': razlika_dni
        })
            
    urnik_zalivanja = sorted(urnik_zalivanja, key=lambda x: x['razlika'])
    koledar_podatki = zgradi_koledar(uporabnikove_rastline, izbran_mesec)
    _oznaci_dneve_z_zapiski(koledar_podatki, trenutni_uporabnik, izbran_mesec)
    prejsnji = (izbran_mesec - timedelta(days=1)).replace(day=1)
    naslednji = (izbran_mesec.replace(day=28) + timedelta(days=4)).replace(day=1)
    return render_template('calendar.html', uporabnik=trenutni_uporabnik, urnik=urnik_zalivanja,
                           koledar=koledar_podatki, prejsnji=prejsnji, naslednji=naslednji,
                           je_trenutni_mesec=(leto == danes.year and mesec == danes.month))


def _oznaci_dneve_z_zapiski(koledar_podatki, username, danasnji_datum):
    """Doda 'has_note': True/False vsakemu dnevu v koledarju, glede na to,
    ali ima uporabnik za ta dan shranjen kakšen osebni zapisek."""
    conn = db.get_connection()
    owner_id = _pridobi_id_uporabnika(conn, username)

    vzorec = f"{danasnji_datum.year:04d}-{danasnji_datum.month:02d}-%"
    vrstice = conn.execute(
        'SELECT DISTINCT note_date FROM notes WHERE owner_id = ? AND note_date LIKE ?',
        (owner_id, vzorec)
    ).fetchall()
    conn.close()

    dnevi_z_zapiski = set()
    for vrstica in vrstice:
        try:
            dnevi_z_zapiski.add(int(vrstica['note_date'].split('-')[2]))
        except (ValueError, IndexError):
            continue

    for teden in koledar_podatki['tedni']:
        for dan in teden:
            if dan.get('day'):
                dan['has_note'] = dan['day'] in dnevi_z_zapiski


# ---------------------------------
# API ZA OSEBNE ZAPISKE V KOLEDARJU
# ---------------------------------
# Ločeno od avtomatskih opomnikov za zalivanje - uporabnik lahko na kateri
# koli dan v koledarju doda poljubno besedilno opombo (npr. "gnojila sem
# vse rastline", "presadila Monstero" ...).

def _pridobi_id_uporabnika(conn, username):
    vrstica = conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone()
    return vrstica['id'] if vrstica else None

@app.route('/api/dnevni-zapiski/<datum>')
def api_pridobi_zapiske(datum):
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    conn = db.get_connection()
    owner_id = _pridobi_id_uporabnika(conn, session['user'])
    zapiski = conn.execute(
        'SELECT id, content FROM notes WHERE owner_id = ? AND note_date = ? ORDER BY id ASC',
        (owner_id, datum)
    ).fetchall()
    conn.close()

    return jsonify({'notes': [{'id': z['id'], 'text': z['content']} for z in zapiski]})

@app.route('/api/dnevni-zapiski', methods=['POST'])
def api_dodaj_zapisek():
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    podatki = request.get_json(silent=True) or {}
    datum = podatki.get('datum')
    besedilo = (podatki.get('text') or '').strip()

    if not datum or not besedilo:
        return jsonify({'error': 'manjkajo podatki'}), 400
    besedilo = besedilo[:500]  # varnostna omejitev dolžine

    conn = db.get_connection()
    owner_id = _pridobi_id_uporabnika(conn, session['user'])
    conn.execute(
        'INSERT INTO notes (owner_id, note_date, content) VALUES (?, ?, ?)',
        (owner_id, datum, besedilo)
    )
    conn.commit()

    zapiski = conn.execute(
        'SELECT id, content FROM notes WHERE owner_id = ? AND note_date = ? ORDER BY id ASC',
        (owner_id, datum)
    ).fetchall()
    conn.close()

    return jsonify({'notes': [{'id': z['id'], 'text': z['content']} for z in zapiski]})

@app.route('/api/dnevni-zapiski/<int:zapisek_id>', methods=['DELETE'])
def api_izbrisi_zapisek(zapisek_id):
    if 'user' not in session:
        return jsonify({'error': 'unauthorized'}), 401

    conn = db.get_connection()
    zapisek = conn.execute(
        """SELECT notes.id FROM notes
           JOIN users ON notes.owner_id = users.id
           WHERE notes.id = ? AND users.username = ?""",
        (zapisek_id, session['user'])
    ).fetchone()

    if not zapisek:
        conn.close()
        return jsonify({'error': 'not found'}), 404

    conn.execute('DELETE FROM notes WHERE id = ?', (zapisek_id,))
    conn.commit()
    conn.close()

    return jsonify({'status': 'ok'})

@app.route('/statistics')
def statistics():
    if 'user' not in session:
        return redirect(url_for('domov'))
        
    trenutni_uporabnik = session['user']
    uporabnikove_rastline = preberi_rastline(trenutni_uporabnik)
    
    skupaj = len(uporabnikove_rastline)
    potrebujejo_vodo = 0
    
    for r in uporabnikove_rastline:
        if r['days_since_watered'] >= r['interval_days']:
            potrebujejo_vodo += 1
                
    zelene = skupaj - potrebujejo_vodo
    odstotek_hidracije = 100 if skupaj == 0 else int((zelene / skupaj) * 100)
    
    stats = {
        'skupaj': skupaj,
        'potrebujejo_vodo': potrebujejo_vodo,
        'zelene': zelene,
        'odstotek_hidracije': odstotek_hidracije
    }

    # Zadnjih 30 dni zalivanja za enostaven pregled navad.
    zacetek = (datetime.now() - timedelta(days=29)).strftime('%Y-%m-%d')
    conn = db.get_connection()
    vrstice = conn.execute(
        '''SELECT watering_log.watered_at, COUNT(*) AS stevilo
           FROM watering_log JOIN plants ON watering_log.plant_id = plants.id
           JOIN users ON plants.owner_id = users.id
           WHERE users.username = ? AND watering_log.watered_at >= ?
           GROUP BY watering_log.watered_at ORDER BY watering_log.watered_at''',
        (trenutni_uporabnik, zacetek)
    ).fetchall()
    conn.close()
    po_dnevih = {v['watered_at']: v['stevilo'] for v in vrstice}
    dnevi = [datetime.now().date() - timedelta(days=i) for i in range(29, -1, -1)]
    graf_oznake = [d.strftime('%d.%m.') for d in dnevi]
    graf_vrednosti = [po_dnevih.get(d.strftime('%Y-%m-%d'), 0) for d in dnevi]

    return render_template('statistics.html', uporabnik=trenutni_uporabnik, stats=stats,
                           graf_oznake=graf_oznake, graf_vrednosti=graf_vrednosti)


# ---------------------------------
# OPOMNIKI - povezani z dejanskimi rastlinami prijavljenega uporabnika
# ---------------------------------

def izracunaj_dogodke_za_opomnike(uporabnikove_rastline, danasnji_datum=None):
    """Za vsako rastlino izračuna naslednji datum zalivanja + status,
    enako kot na dashboardu/koledarju, in doda shranjeno nastavitev opomnika."""
    if danasnji_datum is None:
        danasnji_datum = datetime.now()

    dogodki = []
    for r in uporabnikove_rastline:
        try:
            zadnji_vodeni = datetime.strptime(r['raw_date'], "%Y-%m-%d")
        except (ValueError, TypeError, KeyError):
            continue
        naslednje_zalivanje = zadnji_vodeni + timedelta(days=r['interval_days'])
        razlika_dni = (naslednje_zalivanje.date() - danasnji_datum.date()).days

        if razlika_dni < 0:
            status = "Zamuda!"
        elif razlika_dni == 0:
            status = "Danes"
        elif razlika_dni == 1:
            status = "Jutri"
        else:
            status = f"Čez {razlika_dni} dni"

        nastavitev = notifications.preberi_opomnik_za_rastlino(r['id'])
        try:
            ura_opomnika = datetime.strptime(nastavitev['ura'], '%H:%M').time()
        except (TypeError, ValueError):
            ura_opomnika = datetime.strptime('09:00', '%H:%M').time()
        minute_prej = {'ob_casu': 0, '15_min': 15, '1_ura': 60, '1_dan': 1440, '1_teden': 10080}.get(nastavitev['cas'], 1440)
        naslednji_opomnik = datetime.combine(naslednje_zalivanje.date(), ura_opomnika) - timedelta(minutes=minute_prej)

        dogodki.append({
            'plant_id': r['id'],
            'naziv': f"Zalivanje: {r['name']}",
            'datum_opravila': f"{naslednje_zalivanje.strftime('%d. %m. %Y')} ({status})",
            'nujno': razlika_dni <= 0,
            'cas': nastavitev['cas'],
            'kanali': nastavitev['kanali'],
            'ura': nastavitev['ura'],
            'ponavljaj_zamudo': nastavitev['ponavljaj_zamudo'],
            'naslednji_opomnik': naslednji_opomnik.strftime('%d. %m. %Y ob %H:%M'),
            'prelozeno_do': nastavitev['prelozeno_do'],
        })

    dogodki.sort(key=lambda d: d['nujno'], reverse=True)
    return dogodki

@app.route('/opomniki')
def opomniki():
    if 'user' not in session:
        flash('Za dostop do opomnikov se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))

    trenutni_uporabnik = session['user']
    uporabnikove_rastline = preberi_rastline(trenutni_uporabnik)

    opomniki_seznam = izracunaj_dogodke_za_opomnike(uporabnikove_rastline)
    podatki_uporabnika = preberi_uporabnika_podatke(trenutni_uporabnik)
    email_obvescanje_vklopljeno = bool(podatki_uporabnika['notify_email']) if podatki_uporabnika else True
    ima_push_narocnino = bool(podatki_uporabnika.get('push_subscription')) if podatki_uporabnika else False
    conn = db.get_connection()
    zgodovina_obvestil = conn.execute(
        '''SELECT notification_log.channel, notification_log.created_at, plants.name
           FROM notification_log JOIN plants ON plants.id = notification_log.plant_id
           JOIN users ON users.id = plants.owner_id
           WHERE users.username = ? ORDER BY notification_log.created_at DESC LIMIT 8''',
        (trenutni_uporabnik,)
    ).fetchall()
    conn.close()

    return render_template(
        'opomniki.html',
        opomniki_seznam=opomniki_seznam,
        uporabnik=trenutni_uporabnik,
        email_obvescanje_vklopljeno=email_obvescanje_vklopljeno,
        ima_push_narocnino=ima_push_narocnino,
        zgodovina_obvestil=zgodovina_obvestil,
    )

@app.route('/nastavitve/email-obvescanje', methods=['POST'])
def preklopi_email_obvescanje():
    if 'user' not in session:
        flash('Za to dejanje se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))

    zeleno_stanje = request.form.get('vklopljeno') == '1'

    conn = db.get_connection()
    conn.execute(
        'UPDATE users SET notify_email = ? WHERE username = ?',
        (1 if zeleno_stanje else 0, session['user'])
    )
    conn.commit()
    conn.close()

    if zeleno_stanje:
        flash('Email obveščanje je vklopljeno.', 'success')
    else:
        flash('Email obveščanje je izklopljeno - opomnikov na email ne boš več prejemala.', 'success')

    return redirect(url_for('opomniki'))

@app.route('/nastavitve/preklici-push', methods=['POST'])
def preklici_push():
    if 'user' not in session:
        flash('Za to dejanje se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))

    conn = db.get_connection()
    conn.execute(
        "UPDATE users SET push_subscription = '' WHERE username = ?",
        (session['user'],)
    )
    conn.commit()
    conn.close()

    flash('Push obvestila so preklicana na tej napravi. Za ponoven vklop klikni gumb na nadzorni plošči.', 'success')
    return redirect(url_for('opomniki'))

@app.route('/shrani-opomnik/<int:plant_id>', methods=['POST'])
def shrani_opomnik(plant_id):
    if 'user' not in session:
        flash('Za to dejanje se moraš prijaviti!', 'error')
        return redirect(url_for('domov'))

    # Preverimo lastništvo rastline, preden shranimo nastavitev
    conn = db.get_connection()
    rastlina = conn.execute(
        """SELECT plants.name FROM plants
           JOIN users ON plants.owner_id = users.id
           WHERE plants.id = ? AND users.username = ?""",
        (plant_id, session['user'])
    ).fetchone()
    conn.close()

    if not rastlina:
        flash('Rastline ni mogoče najti ali nimaš pravic zanjo.', 'error')
        return redirect(url_for('opomniki'))

    cas_opomnika = request.form.get('cas_opomnika', '1_dan')
    izbrani_kanali = request.form.getlist('kanali')
    ura = request.form.get('reminder_time', '09:00')
    try:
        datetime.strptime(ura, '%H:%M')
    except ValueError:
        ura = '09:00'
    ponavljaj_zamudo = request.form.get('repeat_overdue') == '1'

    notifications.shrani_opomnik_nastavitve(plant_id, cas_opomnika, izbrani_kanali, ura, ponavljaj_zamudo)
    flash(f"Nastavitve za '{rastlina['name']}' uspešno shranjene!", "success")
    return redirect(url_for('opomniki'))


@app.route('/opomnik/<int:plant_id>/prelozi', methods=['POST'])
def prelozi_opomnik(plant_id):
    """Uporabnik lahko opomnik za izbrano rastlino preloži na jutri."""
    if 'user' not in session:
        return redirect(url_for('domov'))
    conn = db.get_connection()
    rastlina = conn.execute(
        '''SELECT plants.name FROM plants JOIN users ON plants.owner_id = users.id
           WHERE plants.id = ? AND users.username = ?''',
        (plant_id, session['user'])
    ).fetchone()
    conn.close()
    if not rastlina:
        flash('Rastline ni mogoče najti.', 'error')
        return redirect(url_for('opomniki'))
    jutri = (datetime.now().date() + timedelta(days=1)).isoformat()
    notifications.prelozi_opomnik(plant_id, jutri)
    flash(f"Opomnik za '{rastlina['name']}' je preložen na jutri.", 'success')
    return redirect(url_for('opomniki'))


@app.route('/shrani-vse-opomnike', methods=['POST'])
def shrani_vse_opomnike():
    """Uporabi enake nastavitve opomnikov za vse rastline prijavljenega uporabnika."""
    if 'user' not in session:
        return redirect(url_for('domov'))

    cas_opomnika = request.form.get('cas_opomnika', '1_dan')
    dovoljeni_casi = {'ob_casu', '15_min', '1_ura', '1_dan', '1_teden'}
    if cas_opomnika not in dovoljeni_casi:
        cas_opomnika = '1_dan'
    ura = request.form.get('reminder_time', '09:00')
    try:
        datetime.strptime(ura, '%H:%M')
    except (ValueError, TypeError):
        ura = '09:00'
    kanali = [kanal for kanal in request.form.getlist('kanali') if kanal in {'email', 'push'}]
    ponavljaj_zamudo = request.form.get('repeat_overdue') == '1'

    conn = db.get_connection()
    rastline = conn.execute(
        '''SELECT plants.id FROM plants JOIN users ON plants.owner_id = users.id
           WHERE users.username = ?''', (session['user'],)
    ).fetchall()
    conn.close()
    for rastlina in rastline:
        notifications.shrani_opomnik_nastavitve(rastlina['id'], cas_opomnika, kanali, ura, ponavljaj_zamudo)

    flash(f'Nastavitve opomnikov so shranjene za vseh {len(rastline)} rastlin.', 'success')
    return redirect(url_for('opomniki'))


# ---------------------------------
# DNEVNI SCHEDULER - preveri žejne rastline in pošlje obvestila
# ---------------------------------

def sestavi_igrivo_sporocilo(ime_rastline, datum_zalivanja, je_v_zamudi):
    """Sestavi prijazno/igrivo sporočilo za email in push obvestilo.
    Naključno izbere eno od nekaj variant, da ni vsak dan popolnoma enako."""
    datum_str = datum_zalivanja.strftime('%d. %m. %Y')

    if je_v_zamudi:
        zadeve = [
            f"🥵 {ime_rastline} je že precej žejna!",
            f"🚨 SOS od {ime_rastline}!",
            f"😰 {ime_rastline} te pogreša (in vodo)",
        ]
        besedila = [
            f"Ojoj, {ime_rastline} bi morala biti zalita že {datum_str}. Čas je za malo vode! 💧",
            f"{ime_rastline} šteje minute in upa, da prideš mimo s kanglico. Zamujeno zalivanje: {datum_str}. 🌿",
            f"Psst... {ime_rastline} je malo suhotna. Predviden datum zalivanja ({datum_str}) je že mimo!",
        ]
    else:
        zadeve = [
            f"🌿 {ime_rastline} te kliče!",
            f"💧 Čas za {ime_rastline}",
            f"🌱 {ime_rastline} bi rada malo pozornosti",
        ]
        besedila = [
            f"Pssst... {ime_rastline} je danes na vrsti za zalivanje ({datum_str}). Ne pusti je čakati! 💦",
            f"{ime_rastline} si želi malo vode danes ({datum_str}) - par kapljic naredi čudeže. 🌿",
            f"Danes ({datum_str}) je pravi dan, da postrežeš {ime_rastline} z osvežilnim požirkom vode. 🚿",
        ]

    return random.choice(zadeve), random.choice(besedila)

def preveri_in_posli_dnevne_opomnike():
    """Pošlje pravočasen opomnik ter, če je izbrano, en opomnik na dan ob zamudi.
    Tabela notification_log prepreči podvajanje obvestil po restartu schedulerja."""
    danasnji_datum = datetime.now()

    conn = db.get_connection()
    uporabniki = conn.execute('SELECT * FROM users').fetchall()

    for uporabnik_vrstica in uporabniki:
        username = uporabnik_vrstica['username']

        rastline = conn.execute(
            'SELECT * FROM plants WHERE owner_id = ?', (uporabnik_vrstica['id'],)
        ).fetchall()

        for r in rastline:
            try:
                zadnji_vodeni = datetime.strptime(r['last_watered_date'], "%Y-%m-%d")
            except (ValueError, TypeError):
                continue
            naslednje_zalivanje = zadnji_vodeni + timedelta(days=r['interval_days'])
            nastavitev = notifications.preberi_opomnik_za_rastlino(r['id'])
            kanali = nastavitev['kanali']
            if not kanali:
                continue

            if nastavitev['prelozeno_do']:
                try:
                    if danasnji_datum.date() < datetime.strptime(nastavitev['prelozeno_do'], '%Y-%m-%d').date():
                        continue
                except (TypeError, ValueError):
                    pass

            try:
                ura = datetime.strptime(nastavitev['ura'], '%H:%M').time()
            except (ValueError, TypeError):
                ura = datetime.strptime('09:00', '%H:%M').time()
            minute_prej = {'ob_casu': 0, '15_min': 15, '1_ura': 60, '1_dan': 1440, '1_teden': 10080}.get(nastavitev['cas'], 1440)
            planirani_cas = datetime.combine(naslednje_zalivanje.date(), ura) - timedelta(minutes=minute_prej)
            je_v_zamudi = danasnji_datum.date() > naslednje_zalivanje.date()
            if je_v_zamudi:
                if not nastavitev['ponavljaj_zamudo']:
                    continue
                planirani_cas = datetime.combine(danasnji_datum.date(), ura)
            if danasnji_datum < planirani_cas:
                continue

            oznaka_termina = planirani_cas.strftime('%Y-%m-%d %H:%M')
            zadeva, besedilo = sestavi_igrivo_sporocilo(r['name'], naslednje_zalivanje, je_v_zamudi)

            if 'email' in kanali and uporabnik_vrstica['notify_email']:
                email_naslov = uporabnik_vrstica['email']
                ze_poslano = conn.execute('SELECT 1 FROM notification_log WHERE plant_id = ? AND channel = ? AND scheduled_for = ?',
                                           (r['id'], 'email', oznaka_termina)).fetchone()
                if email_naslov and not ze_poslano and notifications.posli_email(email_naslov, zadeva, besedilo):
                    conn.execute('INSERT OR IGNORE INTO notification_log (plant_id, channel, scheduled_for) VALUES (?, ?, ?)',
                                 (r['id'], 'email', oznaka_termina))

            if 'push' in kanali:
                subscription_raw = uporabnik_vrstica['push_subscription']
                ze_poslano = conn.execute('SELECT 1 FROM notification_log WHERE plant_id = ? AND channel = ? AND scheduled_for = ?',
                                           (r['id'], 'push', oznaka_termina)).fetchone()
                if subscription_raw and not ze_poslano:
                    try:
                        subscription = json.loads(subscription_raw)
                        rezultat = notifications.posli_push(
                            subscription, zadeva, besedilo,
                            url_for('podrobnosti_rastline', plant_id=r['id'])
                        )
                        if rezultat is True:
                            conn.execute('INSERT OR IGNORE INTO notification_log (plant_id, channel, scheduled_for) VALUES (?, ?, ?)',
                                         (r['id'], 'push', oznaka_termina))
                    except (json.JSONDecodeError, TypeError):
                        pass

    conn.commit()
    conn.close()


def zazeni_scheduler():
    """Zažene APScheduler, ki enkrat na dan (ob 8:00) pokliče
    preveri_in_posli_dnevne_opomnike(). Klic je zaščiten, da se v Flask
    debug načinu (ki podvoji proces zaradi reloaderja) ne zažene dvakrat."""
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true' and app.debug:
        # V debug načinu se ta modul naloži dvakrat (glavni proces + reloader).
        # Scheduler zaženemo samo v procesu, ki dejansko streže zahteve.
        return
    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        print("OPOZORILO: paket 'apscheduler' ni nameščen (pip install apscheduler) - "
              "dnevna obvestila NE bodo poslana samodejno.")
        return

    global scheduler
    if scheduler is not None:
        return
    scheduler = BackgroundScheduler()
    scheduler.add_job(preveri_in_posli_dnevne_opomnike, 'interval', minutes=5, id='opomniki', replace_existing=True)
    scheduler.start()
    print("Scheduler za opomnike zagnan (preverjanje vsakih 5 minut).")

if __name__ == '__main__':
    # DEBUG naj bo vklopljen samo lokalno med razvojem! V produkciji nastavi
    # FLASK_DEBUG=0 v .env (privzeto je tukaj vklopljen zaradi lažjega razvoja).
    debug_nacin = os.environ.get('FLASK_DEBUG', '0') == '1'
    app.debug = debug_nacin
    if debug_nacin:
        print("OPOZORILO: aplikacija teče v DEBUG načinu - to je NAMENJENO SAMO "
              "lokalnemu razvoju. Pred objavo na spletu nastavi FLASK_DEBUG=0 v .env, "
              "sicer je javno dostopen Werkzeug debugger, kar je resno varnostno tveganje.")
    # Na produkcijskem WSGI gostovanju opomnike zažene ločen cron_opomniki.py.
    # Lokalni zagon z "python app.py" ohrani samodejne opomnike za razvoj.
    if os.environ.get('RUN_INTERNAL_SCHEDULER', '1') == '1':
        zazeni_scheduler()
    app.run(debug=debug_nacin)
