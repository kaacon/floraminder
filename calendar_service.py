"""Priprava podatkov za interaktivni koledar; brez Flask odvisnosti."""

import calendar as calendar_lib
from datetime import datetime, timedelta

IMENA_MESECEV = [
    "Januar", "Februar", "Marec", "April", "Maj", "Junij",
    "Julij", "Avgust", "September", "Oktober", "November", "December"
]


def zgradi_koledar(uporabnikove_rastline, danasnji_datum=None):
    if danasnji_datum is None:
        danasnji_datum = datetime.now()
    dogodki_po_dnevih = {}
    for rastlina in uporabnikove_rastline:
        try:
            zadnje = datetime.strptime(rastlina['raw_date'], '%Y-%m-%d')
        except (ValueError, TypeError, KeyError):
            continue
        naslednje = zadnje + timedelta(days=rastlina['interval_days'])
        if (naslednje.year, naslednje.month) == (danasnji_datum.year, danasnji_datum.month):
            dogodki_po_dnevih.setdefault(naslednje.day, []).append(rastlina['name'])

    pravi_danes = datetime.now()
    cal = calendar_lib.Calendar(firstweekday=0)
    tedni = []
    for teden in cal.monthdayscalendar(danasnji_datum.year, danasnji_datum.month):
        tedni.append([{
            'day': dan or '',
            'is_today': bool(dan and dan == pravi_danes.day and danasnji_datum.month == pravi_danes.month
                             and danasnji_datum.year == pravi_danes.year),
            'has_event': bool(dogodki_po_dnevih.get(dan, [])),
            'events': dogodki_po_dnevih.get(dan, [])
        } for dan in teden])
    return {'tedni': tedni, 'ime_meseca': IMENA_MESECEV[danasnji_datum.month - 1],
            'mesec_st': danasnji_datum.month, 'leto': danasnji_datum.year}
