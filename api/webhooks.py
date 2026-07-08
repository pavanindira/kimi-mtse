"""
webhooks.py — shared helpers for webhook payload signing.

Split out from tasks.py so the signing logic has exactly one implementation,
used by both:
  - tasks.py::_dispatch_webhook   (Celery worker, fires on real scan completion)
  - routers/engagements.py's webhook-test endpoint (FastAPI process, fires
    on-demand so someone configuring a receiver can verify it works before
    waiting for a real scan to finish)

Two call sites computing "the same" HMAC independently is exactly the kind
of thing that quietly drifts — a signature that a test ping validates but
a real delivery doesn't (or vice versa) would be a confusing, hard-to-spot
bug for whoever's implementing the receiving end.
"""

import hashlib
import hmac
import json
from datetime import datetime, timezone


def sign_payload(secret: str, raw_body: str) -> dict[str, str]:
    """
    Build the X-MSTE-Signature / X-MSTE-Timestamp headers for a webhook body.

    Follows the Stripe/GitHub convention of signing "{timestamp}.{body}"
    rather than just the body, so a captured request can't be replayed
    indefinitely — receivers should reject deliveries with a stale
    timestamp (5+ minutes old is a reasonable cutoff).
    """
    timestamp = str(int(datetime.now(timezone.utc).timestamp()))
    signed_content = f'{timestamp}.{raw_body}'
    signature = hmac.new(secret.encode(), signed_content.encode(), hashlib.sha256).hexdigest()
    return {
        'X-MSTE-Signature': f'sha256={signature}',
        'X-MSTE-Timestamp': timestamp,
    }


def serialize_payload(payload: dict) -> str:
    """
    Stable JSON serialisation used for both the actual HTTP body and the
    signing input — sort_keys so the signature is reproducible, and this is
    what's sent (not requests'/httpx's own serialisation), so the signature
    always matches what the receiver reads off the wire.
    """
    return json.dumps(payload, sort_keys=True, separators=(',', ':'))
