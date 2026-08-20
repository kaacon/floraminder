"""Centralizirana validacija uporabniških vnosov."""

from datetime import datetime
import re

MAX_USERNAME = 40
MAX_PLANT_NAME = 80
MAX_SPECIES = 100
MAX_DESCRIPTION = 1000
MAX_NOTE = 500


def valid_email(email):
    email = (email or '').strip().lower()
    return email if re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email) and len(email) <= 254 else None


def valid_date(value):
    try:
        return datetime.strptime(value or '', '%Y-%m-%d')
    except (ValueError, TypeError):
        return None


def clean_text(value, maximum):
    return (value or '').strip()[:maximum]
