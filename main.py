import os
import json
import requests
import stripe
from fastapi import FastAPI, Request, HTTPException
from supabase import create_client

app = FastAPI()

# -----------------------------
# ENV
# -----------------------------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

# A) Additional env vars
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")
WEBHOOK_BASE_URL = os.getenv("WEBHOOK_BASE_URL", "").rstrip("/")
PRICE_STARTER = os.getenv("STRIPE_PRICE_STARTER", "")
PRICE_PRO = os.getenv("STRIPE_PRICE_PRO", "")

if STRIPE_SECRET_KEY:
    stripe.api_key = STRIPE_SECRET_KEY

supabase = None
if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)


# -----------------------------
# Helpers
# -----------------------------
def plan_from_price_id(price_id: str | None) -> str | None:
    """
    Map Stripe price IDs -> your internal plan names.
    IMPORTANT: replace these with your real price IDs (you already have them).
    """
    if not price_id:
        return None

    if PRICE_STARTER and price_id == PRICE_STARTER:
        return "starter"
    if PRICE_PRO and price_id == PRICE_PRO:
        return "pro"

    return None


# B) Map plan name -> Stripe price ID
def price_id_from_plan(plan: str) -> str | None:
    plan = (plan or "").strip().lower()
    if plan == "starter":
        return PRICE_STARTER or None
    if plan == "pro":
        return PRICE_PRO or None
    return None


def upsert_user_plan(user_email: str, plan: str, is_active: bool = True):
    if not supabase:
        raise RuntimeError("Supabase not configured (missing SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).")

    user_email = (user_email or "").strip().lower()
    plan = (plan or "").strip().lower()

    if not user_email:
        raise ValueError("Missing user_email.")
    if plan not in ("starter", "pro", "enterprise"):
        raise ValueError(f"Invalid plan: {plan}")

    # Upsert into user_plans table
    # Expecting columns: user_email (unique), plan, is_active
    res = (
        supabase.table("user_plans")
        .upsert({"user_email": user_email, "plan": plan, "is_active": is_active}, on_conflict="user_email")
        .execute()
    )
    return res


# -----------------------------
# Routes
# -----------------------------
@app.get("/")
def health():
    return {"ok": True}


# C) Create Stripe Checkout Session
@app.post("/create-checkout-session")
async def create_checkout_session(request: Request):
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="STRIPE_SECRET_KEY not set.")
    if not APP_BASE_URL:
        raise HTTPException(status_code=500, detail="APP_BASE_URL not set.")
    if not (PRICE_STARTER and PRICE_PRO):
        raise HTTPException(status_code=500, detail="Missing STRIPE_PRICE_STARTER / STRIPE_PRICE_PRO.")

    auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <token> header.")
    access_token = auth.split(" ", 1)[1].strip()

    body = await request.json()
    plan = (body.get("plan") or "").strip().lower()
    if plan not in ("starter", "pro"):
        raise HTTPException(status_code=400, detail="plan must be 'starter' or 'pro'.")

    # Verify token + get email (service role key is required for this to work reliably)
    if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
        raise HTTPException(status_code=500, detail="Supabase not configured for auth verify.")

    r = requests.get(
        f"{SUPABASE_URL}/auth/v1/user",
        headers={
            "Authorization": f"Bearer {access_token}",
            "apikey": SUPABASE_SERVICE_ROLE_KEY,
        },
        timeout=15,
    )
    if not r.ok:
        raise HTTPException(status_code=401, detail=f"Invalid token: {r.text}")

    u = r.json() or {}
    email = (u.get("email") or u.get("user_metadata", {}).get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=401, detail="Token valid but email missing.")

    price_id = price_id_from_plan(plan)
    if not price_id:
        raise HTTPException(status_code=500, detail=f"No price_id found for plan: {plan}")

    success_url = f"{APP_BASE_URL}/?checkout=success&session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{APP_BASE_URL}/?checkout=cancel"

    session = stripe.checkout.Session.create(
        mode="subscription",
        line_items=[{"price": price_id, "quantity": 1}],
        success_url=success_url,
        cancel_url=cancel_url,
        customer_email=email,
        client_reference_id=email,
        metadata={"plan": plan, "user_email": email},
        allow_promotion_codes=True,
    )
    return {"url": session.url}


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="STRIPE_WEBHOOK_SECRET not set.")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature")

    try:
        event = stripe.Webhook.construct_event(
            payload=payload,
            sig_header=sig_header,
            secret=STRIPE_WEBHOOK_SECRET,
        )
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Webhook error: {e}")

    event_type = event.get("type")
    obj = event.get("data", {}).get("object", {})

    # -----------------------------
    # 1) checkout.session.completed (best first hook)
    # -----------------------------
    if event_type == "checkout.session.completed":
        # You pass metadata in create_checkout_session():
        # metadata={"plan": plan, "user_email": user_email}
        metadata = obj.get("metadata") or {}
        user_email = (metadata.get("user_email") or obj.get("customer_email") or "").strip().lower()
        plan = (metadata.get("plan") or "").strip().lower()

        # Optional: If metadata missing, derive from line items
        if not plan:
            try:
                session_id = obj.get("id")
                items = stripe.checkout.Session.list_line_items(session_id, limit=1)
                price_id = items.data[0].price.id if items and items.data else None
                plan = plan_from_price_id(price_id) or ""
            except Exception:
                plan = ""

        if user_email and plan:
            try:
                upsert_user_plan(user_email, plan, is_active=True)
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Supabase update failed: {e}")

    # -----------------------------
    # 2) invoice.payment_succeeded (keeps plan active on renewals)
    # -----------------------------
    elif event_type == "invoice.payment_succeeded":
        customer_email = (obj.get("customer_email") or "").strip().lower()
        if customer_email:
            try:
                # Keep whatever plan already exists, just ensure active
                supabase.table("user_plans").update({"is_active": True}).eq("user_email", customer_email).execute()
            except Exception:
                pass

    # -----------------------------
    # 3) customer.subscription.deleted (mark inactive)
    # -----------------------------
    elif event_type == "customer.subscription.deleted":
        # Usually no email; you'd map customer->user in DB for perfect handling.
        # For now: do nothing unless you store customer_id somewhere.
        pass

    return {"received": True, "type": event_type}
