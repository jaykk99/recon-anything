"""Geocoding + POI lookup for Bank/ATM source types.

Jay picks [Bank] or [ATM] on the scan form, types a location, and the app
finds every bank/ATM there via OpenStreetMap, then assesses each one.

- Geocoding: Nominatim (free, no key, needs a real User-Agent)
- POI lookup: Overpass API (free, no key)
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from . import net

NOMINATIM_URL = "https://nominatim.openstreetmap.org/search"
OVERPASS_URL = "https://overpass-api.de/api/interpreter"
# Fallback Overpass mirrors if the primary is down.
OVERPASS_MIRRORS = [
    "https://overpass-api.de/api/interpreter",
    "https://overpass.kumi.systems/api/interpreter",
]

UA = {"User-Agent": "ReconAnything/1.0 (security assessment tool)"}

# source_type -> Overpass amenity tag
POI_AMENITY = {
    "bank": "bank",
    "atm": "atm",
}


def parse_coords(s: str) -> Optional[Tuple[float, float]]:
    """Parse 'lat,lon' or 'lat lon' directly. Returns None if not coords."""
    s = (s or "").strip()
    m = re.match(r"^\s*(-?\d{1,3}(?:\.\d+)?)\s*[,;\s]\s*(-?\d{1,3}(?:\.\d+)?)\s*$", s)
    if not m:
        return None
    try:
        lat, lon = float(m.group(1)), float(m.group(2))
    except ValueError:
        return None
    if -90 <= lat <= 90 and -180 <= lon <= 180:
        return (lat, lon)
    return None


async def geocode(location: str) -> Optional[Dict]:
    """Address/city -> {lat, lon, display_name}. None on failure."""
    coords = parse_coords(location)
    if coords:
        return {"lat": coords[0], "lon": coords[1],
                "display_name": f"{coords[0]},{coords[1]}"}
    try:
        async with net.async_client(timeout=15) as client:
            resp = await client.get(
                NOMINATIM_URL,
                params={"q": location, "format": "json", "limit": 1},
                headers=UA,
            )
            if resp.status_code != 200:
                return None
            data = resp.json()
            if not data:
                return None
            first = data[0]
            return {
                "lat": float(first["lat"]),
                "lon": float(first["lon"]),
                "display_name": first.get("display_name", location),
            }
    except Exception:
        return None


async def find_pois(lat: float, lon: float, poi_type: str,
                    radius_m: int = 5000) -> List[Dict]:
    """Find banks or ATMs near a point.

    Uses Nominatim amenity search (simple, reliable) with an Overpass
    fallback for denser results. Returns list of
    {name, lat, lon, address, tags}.
    """
    # Primary: Nominatim amenity search near the point.
    try:
        async with net.async_client(timeout=20) as client:
            resp = await client.get(
                NOMINATIM_URL,
                params={
                    "q": f"{poi_type} near {lat},{lon}",
                    "format": "json",
                    "limit": 50,
                },
                headers=UA,
            )
            if resp.status_code == 200:
                data = resp.json()
                out = _parse_nominatim(data, poi_type, lat, lon, radius_m)
                if out:
                    return out
    except Exception:
        pass
    # Fallback: Overpass API for denser coverage.
    return await _find_pois_overpass(lat, lon, poi_type, radius_m)


def _parse_nominatim(data: List[Dict], poi_type: str,
                     lat: float, lon: float, radius_m: int) -> List[Dict]:
    import math
    out = []
    for el in data or []:
        if el.get("class") != "amenity" or el.get("type") != poi_type:
            continue
        try:
            plat, plon = float(el["lat"]), float(el["lon"])
        except (KeyError, ValueError, TypeError):
            continue
        # Rough distance filter (haversine).
        dlat = math.radians(plat - lat)
        dlon = math.radians(plon - lon)
        a = (math.sin(dlat / 2) ** 2 +
             math.cos(math.radians(lat)) * math.cos(math.radians(plat)) *
             math.sin(dlon / 2) ** 2)
        dist_m = 6371000 * 2 * math.asin(math.sqrt(a))
        if dist_m > radius_m:
            continue
        out.append({
            "name": el.get("name") or f"Unnamed {poi_type.upper()}",
            "lat": plat,
            "lon": plon,
            "address": el.get("display_name", ""),
            "operator": "",
            "website": "",
            "phone": "",
            "opening_hours": "",
        })
    return out


async def _find_pois_overpass(lat: float, lon: float, poi_type: str,
                              radius_m: int = 5000) -> List[Dict]:
    amenity = POI_AMENITY.get(poi_type)
    if not amenity:
        return []
    query = (
        f"[out:json][timeout:25];"
        f"("
        f"node[\"amenity\"=\"{amenity}\"](around:{radius_m},{lat},{lon});"
        f"way[\"amenity\"=\"{amenity}\"](around:{radius_m},{lat},{lon});"
        f");"
        f"out center 50;"
    )
    for url in OVERPASS_MIRRORS:
        try:
            async with net.async_client(timeout=30) as client:
                resp = await client.post(url, data={"data": query},
                                         headers=UA)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                return _parse_overpass(data, poi_type)
        except Exception:
            continue
    return []


async def find_bank_atm_pois(lat: float, lon: float,
                             radius_m: int = 5000,
                             cap: int = 25) -> List[Dict]:
    """Banks AND ATMs near a point, in one Overpass query.

    Unlike find_pois (single amenity, Nominatim-first, tags dropped),
    this keeps the full OSM tag set - brand, operator, website - because
    Bank/ATM mode resolves each operator to a domain. Returns dicts with
    an extra "poi_type" ("bank"|"atm") per element, deduped, capped.
    """
    query = (
        f"[out:json][timeout:25];"
        f"("
        f"node[\"amenity\"~\"^(bank|atm)$\"](around:{radius_m},{lat},{lon});"
        f"way[\"amenity\"~\"^(bank|atm)$\"](around:{radius_m},{lat},{lon});"
        f");"
        f"out center 60;"
    )
    for url in OVERPASS_MIRRORS:
        try:
            async with net.async_client(timeout=30) as client:
                resp = await client.post(url, data={"data": query},
                                         headers=UA)
                if resp.status_code != 200:
                    continue
                return parse_bank_atm_elements(resp.json(), cap)
        except Exception:
            continue
    return []


def parse_bank_atm_elements(data: Dict, cap: int = 25) -> List[Dict]:
    """Parse an Overpass response for amenity=bank|atm into POI dicts.

    Pure function (fixture-testable). Dedupes on (type, name, rounded
    coords) and stops at cap.
    """
    out: List[Dict] = []
    seen = set()
    for el in (data or {}).get("elements", []):
        tags = el.get("tags", {}) or {}
        amenity = (tags.get("amenity") or "").strip().lower()
        if amenity not in ("bank", "atm"):
            continue
        lat = el.get("lat") or (el.get("center") or {}).get("lat")
        lon = el.get("lon") or (el.get("center") or {}).get("lon")
        if lat is None or lon is None:
            continue
        lat, lon = float(lat), float(lon)
        operator = tags.get("operator", "") or ""
        brand = tags.get("brand", "") or ""
        name = (tags.get("name") or brand or operator
                or f"Unnamed {amenity.upper()}")
        key = (amenity, name.lower(), round(lat, 4), round(lon, 4))
        if key in seen:
            continue
        seen.add(key)
        addr_parts = [
            tags.get("addr:housenumber", ""),
            tags.get("addr:street", ""),
            tags.get("addr:city", ""),
            tags.get("addr:postcode", ""),
        ]
        address = " ".join(p for p in addr_parts if p).strip()
        if not address:
            address = tags.get("addr:full", "") or ""
        out.append({
            "name": name,
            "lat": lat,
            "lon": lon,
            "address": address,
            "operator": operator,
            "brand": brand,
            "website": tags.get("website", "")
                       or tags.get("contact:website", ""),
            "phone": tags.get("phone", "") or tags.get("contact:phone", ""),
            "opening_hours": tags.get("opening_hours", ""),
            "poi_type": amenity,
        })
        if len(out) >= cap:
            break
    return out


def _parse_overpass(data: Dict, poi_type: str) -> List[Dict]:
    out = []
    for el in data.get("elements", []):
        tags = el.get("tags", {}) or {}
        lat = el.get("lat") or (el.get("center") or {}).get("lat")
        lon = el.get("lon") or (el.get("center") or {}).get("lon")
        if lat is None or lon is None:
            continue
        name = tags.get("name") or tags.get("operator") or f"Unnamed {poi_type.upper()}"
        addr_parts = [
            tags.get("addr:housenumber", ""),
            tags.get("addr:street", ""),
            tags.get("addr:city", ""),
        ]
        address = " ".join(p for p in addr_parts if p).strip()
        out.append({
            "name": name,
            "lat": float(lat),
            "lon": float(lon),
            "address": address,
            "operator": tags.get("operator", ""),
            "website": tags.get("website", ""),
            "phone": tags.get("phone", ""),
            "opening_hours": tags.get("opening_hours", ""),
        })
    return out
