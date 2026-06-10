# ============================================================
#  geoip_helper.py — Géolocalisation des adresses IP
#  Utilise une base GeoLite2 locale (hors-ligne).
#  Dégrade proprement si la base est absente ou l'IP privée.
# ============================================================

import os
import ipaddress

# Emplacement attendu de la base GeoLite2 (City ou Country)
_DB_CANDIDATES = [
    os.path.join(os.path.dirname(__file__), "geoip", "GeoLite2-Country.mmdb"),
    os.path.join(os.path.dirname(__file__), "geoip", "GeoLite2-City.mmdb"),
    "/usr/share/GeoIP/GeoLite2-Country.mmdb",
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
]

_reader = None
_db_path = None

def _init_reader():
    """Charge la base GeoLite2 une seule fois (lazy)."""
    global _reader, _db_path
    if _reader is not None:
        return _reader
    try:
        import geoip2.database
    except ImportError:
        return None
    for path in _DB_CANDIDATES:
        if os.path.exists(path):
            try:
                _reader = geoip2.database.Reader(path)
                _db_path = path
                return _reader
            except Exception:
                continue
    return None


def _is_public(ip):
    """Vrai si l'IP est publique (donc géolocalisable)."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or
                    addr.is_link_local or addr.is_reserved)
    except ValueError:
        return False


def lookup_country(ip):
    """
    Retourne (code_pays, nom_pays) pour une IP.
    Exemple : ("FR", "France"). Renvoie ("", "") si indéterminable.
    """
    if not ip or not _is_public(ip):
        return ("", "")
    reader = _init_reader()
    if reader is None:
        return ("", "")
    try:
        # Fonctionne pour GeoLite2-Country comme City
        try:
            resp = reader.country(ip)
        except AttributeError:
            resp = reader.city(ip)
        code = resp.country.iso_code or ""
        name = resp.country.name or ""
        return (code, name)
    except Exception:
        return ("", "")


def country_flag(code):
    """Convertit un code pays ISO (FR) en emoji drapeau. Vide si inconnu."""
    if not code or len(code) != 2:
        return ""
    try:
        return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code.upper())
    except Exception:
        return ""


def db_available():
    """Indique si la base de géolocalisation est disponible."""
    return _init_reader() is not None
