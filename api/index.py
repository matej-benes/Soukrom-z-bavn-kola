"""Vercel serverless funkce - preposila vsechny /api/* a /web/* na app.Handler.
Stateless HMAC tokeny + Supabase, zadna sdilena pamet. HTTPS certifikat resi Vercel automaticky.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import Handler  # noqa: E402


class handler(Handler):
    pass
