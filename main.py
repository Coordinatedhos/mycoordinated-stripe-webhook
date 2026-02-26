import os
import json
import stripe
import requests
import logging
from datetime import datetime, timezone
from fastapi import FastAPI, Request, HTTPException
from supabase import create_client

app = FastAPI()

logger = logging.getLogger("mycoordinated_stripe")
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))

# -----------------------------
# ENV
# -----------------------------
STRIPE_SECRET_KEY = os.getenv("STRIPE_SECRET_KEY", "")
STRIPE_WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")

SUPABASE_URL = os.getenv("SUPABASE_URL", "")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")

# Used by /create-checkout-session
APP_BASE_URL = os.getenv("APP_BASE_URL", "").rstrip("/")  # e.g. https://app.mycoordinated.com
WEBHOOK_BASE_URL = os.getenv("WEBHOOK_BASE_URL", "").rstrip("/")  # e.g. https://mycoordinated-stripe-webhook.onrender.com

# Stripe price IDs (recommended to keep in env for test/prod separation)
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
    """Map Stripe price IDs -> your internal plan names."""
    if not price_id:
        return None

    if PRICE_STARTER and price_id == PRICE_STARTER:
        return "starter"
    if PRICE_PRO and price_id == PRICE_PRO:
        return "pro"

    return None


def price_id_from_plan(plan: str) -> str | None:
    plan = (plan or "").strip().lower()
    if plan == "starter":
        return PRICE_STARTER or None
    if plan == "pro":
        return PRICE_PRO or None
    return None


def upsert_user_plan(
    user_email: str,
    plan: str,
    is_active: bool = True,
    status: str | None = None,
    cancel_at_period_end: bool | None = None,
    current_period_end: int | None = None,
    stripe_customer_id: str | None = None,
    stripe_subscription_id: str | None = None,
):
    """Upsert subscription state into `user_plans`.

    Notes:
    - `current_period_end` is a Stripe unix timestamp (seconds).
    - Keep the table flexible: only write optional fields when provided.
    """
    if not supabase:
        raise RuntimeError(
            "Supabase not configured (missing SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)."
        )

    user_email = (user_email or "").strip().lower()
    plan = (plan or "").strip().lower()

    if not user_email:
        raise ValueError("Missing user_email.")
    if plan not in ("starter", "pro", "enterprise"):
        raise ValueError(f"Invalid plan: {plan}")

    payload: dict = {
        "user_email": user_email,
        "plan": plan,
        "is_active": bool(is_active),
    }

    if status is not None:
        payload["status"] = status
    if cancel_at_period_end is not None:
        payload["cancel_at_period_end"] = bool(cancel_at_period_end)
    if current_period_end is not None:
        # Store as timestamptz (ISO-8601) to match Supabase column type
        payload["current_period_end"] = _to_timestamptz(current_period_end)
    if stripe_customer_id is not None:
        payload["stripe_customer_id"] = stripe_customer_id
    if stripe_subscription_id is not None:
        payload["stripe_subscription_id"] = stripe_subscription_id

    try:
        res = (
            supabase.table("user_plans")
            .upsert(payload, on_conflict="user_email")
            .execute()
        )
        return res
    except Exception as e:
        logger.exception("Supabase upsert failed", extra={"payload": payload})
        raise


def _verify_supabase_jwt(access_token: str) -> dict:
    """
    Verify user is logged in by calling Supabase Auth /user endpoint.
    Returns the user json (must contain email).
    """
    if not SUPABASE_URL:
        raise HTTPException(status_code=500, detail="SUPABASE_URL not set.")

    r = requests.get(
        f"{SUPABASE_URL}/auth/v1/user",
        headers={"Authorization": f"Bearer {access_token}", "apikey": SUPABASE_SERVICE_ROLE_KEY or ""},
        timeout=15,
    )
    if not r.ok:
        raise HTTPException(status_code=401, detail=f"Invalid token: {r.text}")

    u = r.json() or {}
    email = (u.get("email") or u.get("user_metadata", {}).get("email") or "").strip().lower()
    if not email:
        raise HTTPException(status_code=401, detail="Token valid but email missing.")
    return u


def _session_belongs_to_email(sess: dict, email: str) -> bool:
    """
    Extra safety: ensure the session we are about to trust belongs to the user.
    """
    email = (email or "").strip().lower()
    if not email:
        return False

    # Stripe may set customer_email on the session; metadata also has it (we set it)
    sess_email = (sess.get("customer_email") or "").strip().lower()
    meta = sess.get("metadata") or {}
    meta_email = (meta.get("user_email") or "").strip().lower()

    if sess_email and sess_email == email:
        return True
    if meta_email and meta_email == email:
        return True
    return False


def _email_from_customer_id(customer_id: str | None) -> str:
    if not customer_id:
        return ""
    try:
        cust = stripe.Customer.retrieve(customer_id)
        email = (getattr(cust, "email", None) or (cust.get("email") if isinstance(cust, dict) else "") or "").strip().lower()
        return email
    except Exception:
        return ""


def _email_from_invoice(obj: dict) -> str:
    # Invoice often has `customer` but not `customer_email` (that field is mostly for legacy invoicing)
    email = (obj.get("customer_email") or "").strip().lower()
    if email:
        return email
    customer_id = obj.get("customer")
    return _email_from_customer_id(customer_id)


# -----------------------------
# -----------------------------
# Helpers
# -----------------------------
def _to_timestamptz(value: int | str | None) -> str | None:
    """Convert a Stripe unix timestamp (seconds) to an ISO-8601 timestamptz string.

    Your Supabase `user_plans.current_period_end` column appears to be a date/timestamp type.
    Stripe provides `current_period_end` as unix seconds (e.g. 1774547316).
    Sending that integer directly causes Postgres to try parsing it as a date string.
    """
    if value is None:
        return None

    # Sometimes Stripe/lib returns ints; sometimes strings.
    if isinstance(value, str):
        v = value.strip()
        if not v:
            return None
        if v.isdigit():
            value_int = int(v)
        else:
            # Already an ISO timestamp or some other string — pass through.
            return v
    else:
        value_int = int(value)

    # Stripe timestamps are seconds since epoch.
    return datetime.fromtimestamp(value_int, tz=timezone.utc).isoformat()

# -----------------------------
# Routes
# -----------------------------
@app.get("/")
def health():
    return {"ok": True}


@app.post("/create-checkout-session")
async def create_checkout_session(request: Request):
    """
    Creates a Stripe Checkout Session for the signed-in user.

    Streamlit should call this endpoint with:
      Authorization: Bearer <SUPABASE_ACCESS_TOKEN>
      JSON body: { "plan": "starter" | "pro" }

    Returns: { "url": "<stripe_checkout_url>" }
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="STRIPE_SECRET_KEY not set.")
    if not APP_BASE_URL:
        raise HTTPException(status_code=500, detail="APP_BASE_URL not set.")
    if not WEBHOOK_BASE_URL:
        raise HTTPException(status_code=500, detail="WEBHOOK_BASE_URL not set.")
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

    # Verify Supabase user
    u = _verify_supabase_jwt(access_token)
    email = (u.get("email") or u.get("user_metadata", {}).get("email") or "").strip().lower()

    price_id = price_id_from_plan(plan)
    if not price_id:
        raise HTTPException(status_code=500, detail=f"No price_id found for plan: {plan}")

    success_url = f"{APP_BASE_URL}/?checkout=success&session_id={{CHECKOUT_SESSION_ID}}"
    cancel_url = f"{APP_BASE_URL}/?checkout=cancel"


    try:
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stripe error creating checkout session: {e}")


# -----------------------------
# Cancel Subscription Route and Helper
# -----------------------------

def _get_user_plan_row(user_email: str) -> dict | None:
    """Fetch the current user_plans row for an email (service role)."""
    if not supabase:
        return None
    user_email = (user_email or "").strip().lower()
    if not user_email:
        return None

    try:
        res = (
            supabase.table("user_plans")
            .select(
                "user_email,plan,status,is_active,cancel_at_period_end,current_period_end,stripe_customer_id,stripe_subscription_id"
            )
            .eq("user_email", user_email)
            .limit(1)
            .execute()
        )
        data = getattr(res, "data", None) or (res.get("data") if isinstance(res, dict) else None) or []
        return data[0] if data else None
    except Exception:
        logger.exception("Failed to fetch user_plans row", extra={"user_email": user_email})
        return None


@app.post("/cancel-subscription")
async def cancel_subscription(request: Request):
    """
    Cancel a user's subscription.

    Streamlit should call this endpoint with:
      Authorization: Bearer <SUPABASE_ACCESS_TOKEN>
      JSON body: { "mode": "period_end" | "immediate" }

    - period_end: sets Stripe `cancel_at_period_end=True` (recommended)
    - immediate: cancels immediately in Stripe

    IMPORTANT: Stripe is the source of truth. Supabase is updated via webhook events.
    """
    if not STRIPE_SECRET_KEY:
        raise HTTPException(status_code=500, detail="STRIPE_SECRET_KEY not set.")
    if not supabase:
        raise HTTPException(status_code=500, detail="Supabase not configured.")

    auth = request.headers.get("authorization") or request.headers.get("Authorization") or ""
    if not auth.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization: Bearer <token> header.")
    access_token = auth.split(" ", 1)[1].strip()

    body = await request.json()
    mode = (body.get("mode") or "period_end").strip().lower()
    if mode not in ("period_end", "immediate"):
        raise HTTPException(status_code=400, detail="mode must be 'period_end' or 'immediate'.")

    # Verify Supabase user
    u = _verify_supabase_jwt(access_token)
    user_email = (u.get("email") or u.get("user_metadata", {}).get("email") or "").strip().lower()
    if not user_email:
        raise HTTPException(status_code=401, detail="Authenticated user email missing.")

    # Find subscription id (prefer DB; fallback to Stripe customer lookup)
    row = _get_user_plan_row(user_email)
    sub_id = (row or {}).get("stripe_subscription_id")
    cust_id = (row or {}).get("stripe_customer_id")

    if not sub_id and cust_id:
        try:
            subs = stripe.Subscription.list(customer=cust_id, status="all", limit=10)
            # pick latest non-canceled subscription if present
            for s in subs.data:
                s_status = (s.get("status") if isinstance(s, dict) else getattr(s, "status", "")) or ""
                if s_status not in ("canceled",):
                    sub_id = s.get("id") if isinstance(s, dict) else getattr(s, "id", None)
                    break
            if not sub_id and subs.data:
                s0 = subs.data[0]
                sub_id = s0.get("id") if isinstance(s0, dict) else getattr(s0, "id", None)
        except Exception:
            logger.exception("Failed to list subscriptions for customer", extra={"user_email": user_email, "customer_id": cust_id})

    if not sub_id:
        raise HTTPException(status_code=404, detail="No Stripe subscription found for this user.")

    try:
        if mode == "period_end":
            stripe.Subscription.modify(sub_id, cancel_at_period_end=True)
        else:
            # Cancel immediately
            stripe.Subscription.delete(sub_id)

        # Do NOT force-update Supabase here. Webhook events will mirror Stripe state.
        return {"ok": True, "mode": mode, "subscription_id": sub_id}

    except Exception as e:
        logger.exception("Stripe cancellation failed", extra={"user_email": user_email, "subscription_id": sub_id, "mode": mode})
        raise HTTPException(status_code=500, detail=f"Stripe cancellation failed: {e}")


@app.post("/stripe/webhook")
async def stripe_webhook(request: Request):
    if not STRIPE_WEBHOOK_SECRET:
        raise HTTPException(status_code=500, detail="STRIPE_WEBHOOK_SECRET not set.")

    payload = await request.body()
    sig_header = request.headers.get("stripe-signature") or request.headers.get("Stripe-Signature")

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
    logger.info("stripe_webhook received", extra={"type": event_type})

    def _plan_from_invoice(invoice_obj: dict) -> str:
        """Derive plan from an Invoice object's line items (price id)."""
        try:
            lines = (invoice_obj.get("lines") or {}).get("data") or []
            if not lines:
                return ""
            price = (lines[0].get("price") or {})
            price_id = price.get("id")
            return plan_from_price_id(price_id) or ""
        except Exception:
            return ""

    def _email_from_invoice_obj(invoice_obj: dict) -> str:
        """Best-effort email extraction from an Invoice object."""
        email = (invoice_obj.get("customer_email") or "").strip().lower()
        if email:
            return email
        customer_id = invoice_obj.get("customer")
        return _email_from_customer_id(customer_id)

    # -----------------------------
    # 1) checkout.session.completed (best first hook)
    # -----------------------------
    if event_type == "checkout.session.completed":
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

        # Pull subscription state from Stripe (preferred)
        sub_id = obj.get("subscription")
        customer_id = obj.get("customer")
        sub_status = None
        cancel_at_period_end = None
        current_period_end = None

        if sub_id:
            try:
                sub = stripe.Subscription.retrieve(sub_id)
                # Stripe subscription fields
                sub_status = (sub.get("status") if isinstance(sub, dict) else getattr(sub, "status", None))
                cancel_at_period_end = (
                    sub.get("cancel_at_period_end") if isinstance(sub, dict) else getattr(sub, "cancel_at_period_end", None)
                )
                current_period_end = (
                    sub.get("current_period_end") if isinstance(sub, dict) else getattr(sub, "current_period_end", None)
                )
                # If email wasn't present on session, try customer lookup
                if not user_email and customer_id:
                    user_email = _email_from_customer_id(customer_id)
            except Exception:
                pass

        if user_email and plan:
            try:
                upsert_user_plan(
                    user_email,
                    plan,
                    is_active=True,
                    status=sub_status or "active",
                    cancel_at_period_end=False,
                    current_period_end=current_period_end,
                    stripe_customer_id=customer_id,
                    stripe_subscription_id=sub_id,
                )
                logger.info(
                    "user_plan updated from checkout.session.completed",
                    extra={
                        "user_email": user_email,
                        "plan": plan,
                        "status": sub_status or "active",
                        "customer_id": customer_id,
                        "subscription_id": sub_id,
                    },
                )
            except Exception as e:
                # IMPORTANT: don't 500 the webhook; log and allow other events (invoice/subscription.updated)
                # to reconcile state.
                logger.exception(
                    "Supabase update failed in checkout.session.completed",
                    extra={
                        "user_email": user_email,
                        "plan": plan,
                        "customer_id": customer_id,
                        "subscription_id": sub_id,
                        "error": str(e),
                    },
                )
        else:
            logger.warning(
                "checkout.session.completed missing user_email or plan",
                extra={
                    "user_email": user_email,
                    "plan": plan,
                    "customer_id": customer_id,
                    "subscription_id": sub_id,
                },
            )

    # -----------------------------
    # 2) invoice.paid / invoice.payment_succeeded / invoice_payment.paid
    # -----------------------------
    elif event_type in ("invoice.paid", "invoice.payment_succeeded", "invoice_payment.paid"):
        # Stripe sometimes emits `invoice_payment.paid` with object type `invoice_payment`.
        # That object contains an `invoice` id; we then fetch the full Invoice to derive plan + subscription.

        invoice_obj = None
        if event_type == "invoice_payment.paid":
            invoice_id = obj.get("invoice")
            if invoice_id:
                try:
                    invoice_obj = stripe.Invoice.retrieve(invoice_id)
                    if not isinstance(invoice_obj, dict):
                        invoice_obj = dict(invoice_obj)
                except Exception:
                    invoice_obj = None
        else:
            # `invoice.paid` / `invoice.payment_succeeded` usually provide the full invoice object
            invoice_obj = obj

        if not invoice_obj:
            return {"received": True, "type": event_type}

        # Identify the user + plan
        user_email = _email_from_invoice_obj(invoice_obj)
        customer_id = invoice_obj.get("customer")
        sub_id = invoice_obj.get("subscription")

        plan = (invoice_obj.get("metadata") or {}).get("plan")
        plan = (plan or "").strip().lower()
        if not plan:
            plan = _plan_from_invoice(invoice_obj)

        # Pull subscription state from Stripe (preferred)
        sub_status = None
        cancel_at_period_end = None
        current_period_end = None

        if sub_id:
            try:
                sub = stripe.Subscription.retrieve(sub_id)
                sub_status = (sub.get("status") if isinstance(sub, dict) else getattr(sub, "status", None))
                cancel_at_period_end = (
                    sub.get("cancel_at_period_end") if isinstance(sub, dict) else getattr(sub, "cancel_at_period_end", None)
                )
                current_period_end = (
                    sub.get("current_period_end") if isinstance(sub, dict) else getattr(sub, "current_period_end", None)
                )
            except Exception:
                pass

        if user_email and plan:
            try:
                upsert_user_plan(
                    user_email=user_email,
                    plan=plan,
                    is_active=True,
                    status=sub_status or "active",
                    cancel_at_period_end=False if cancel_at_period_end is None else bool(cancel_at_period_end),
                    current_period_end=current_period_end,
                    stripe_customer_id=customer_id,
                    stripe_subscription_id=sub_id,
                )
                logger.info(
                    "user_plan updated from invoice handler",
                    extra={
                        "user_email": user_email,
                        "plan": plan,
                        "status": sub_status or "active",
                        "customer_id": customer_id,
                        "subscription_id": sub_id,
                    },
                )
            except Exception as e:
                logger.exception(
                    "Supabase update failed in invoice handler",
                    extra={"user_email": user_email, "plan": plan, "subscription_id": sub_id, "error": str(e)},
                )

    # -----------------------------
    # 3) customer.subscription.updated / deleted (mark inactive)
    # -----------------------------
    elif event_type in ("customer.subscription.updated", "customer.subscription.deleted"):
        # Keep DB aligned with Stripe subscription state changes.
        customer_id = obj.get("customer")
        user_email = _email_from_customer_id(customer_id)

        sub_status = (obj.get("status") or "").strip()
        cancel_at_period_end = obj.get("cancel_at_period_end")
        current_period_end = obj.get("current_period_end")
        sub_id = obj.get("id")

        # If subscription is deleted, it is not active.
        is_active = False if event_type == "customer.subscription.deleted" else (sub_status == "active")

        if user_email and supabase:
            try:
                update_payload: dict = {
                    "is_active": bool(is_active),
                    "status": sub_status or (
                        "canceled" if event_type == "customer.subscription.deleted" else ""
                    ),
                    "cancel_at_period_end": bool(cancel_at_period_end)
                    if cancel_at_period_end is not None
                    else False,
                }

                # IMPORTANT:
                # `user_plans.current_period_end` is a timestamptz column in Supabase.
                # Stripe provides `current_period_end` as unix seconds.
                # Sending the raw integer causes Postgres to error: date/time field out of range.
                if current_period_end is not None:
                    update_payload["current_period_end"] = _to_timestamptz(current_period_end)

                if customer_id:
                    update_payload["stripe_customer_id"] = customer_id
                if sub_id:
                    update_payload["stripe_subscription_id"] = sub_id

                supabase.table("user_plans").update(update_payload).eq(
                    "user_email", user_email
                ).execute()
            except Exception as e:
                logger.exception(
                    "Supabase update failed in subscription handler",
                    extra={"user_email": user_email, "subscription_id": sub_id, "error": str(e)},
                )

    return {"received": True, "type": event_type}
