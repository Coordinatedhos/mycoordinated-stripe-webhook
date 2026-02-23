import os
import json
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

    PRICE_STARTER = os.getenv("STRIPE_PRICE_STARTER", "")
    PRICE_PRO = os.getenv("STRIPE_PRICE_PRO", "")

    if PRICE_STARTER and price_id == PRICE_STARTER:
        return "starter"
    if PRICE_PRO and price_id == PRICE_PRO:
        return "pro"

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
        # invoices have customer_email sometimes, often not.
        # We'll try metadata via subscription -> checkout metadata not always present here.
        customer_email = (obj.get("customer_email") or "").strip().lower()
        if customer_email:
            # If you want renewals to just keep "is_active=True" without changing plan:
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