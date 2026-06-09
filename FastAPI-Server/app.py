from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime
from typing import List, Optional
import random

app = FastAPI(
    title="Advanced Test API",
    description="Expanded API with 50+ endpoints for testing and research",
    version="3.0.0",
)

# ============================================================
# Models
# ============================================================

class User(BaseModel):
    id: int
    name: str
    email: str
    role: str

class Product(BaseModel):
    id: int
    name: str
    price: float
    in_stock: bool

class Order(BaseModel):
    order_id: str
    user_id: int
    total: float

# ============================================================
# Mock Data
# ============================================================

users = [
    User(id=i, name=f"User{i}", email=f"user{i}@test.com", role="user")
    for i in range(1, 11)
]

products = [
    Product(id=i, name=f"Product{i}", price=random.randint(10, 500), in_stock=bool(i % 2))
    for i in range(100, 120)
]

orders = [
    Order(order_id=f"ORD-{i}", user_id=random.randint(1, 10), total=random.randint(50, 2000))
    for i in range(1, 30)
]

logs = [{"id": i, "level": random.choice(["INFO","WARN","ERROR"]), "msg": f"log {i}"} for i in range(50)]
files = [{"id": i, "name": f"file{i}.txt", "size": random.randint(100,10000)} for i in range(20)]

# ============================================================
# System Endpoints
# ============================================================

@app.get("/health")
def health():
    return {"status": "ok", "time": datetime.utcnow()}

@app.get("/uptime")
def uptime():
    return {"uptime": f"{random.randint(1,100)} hours"}

@app.get("/metrics")
def metrics():
    return {"cpu": random.random(), "memory": random.random()}

@app.get("/version")
def version():
    return {"version": "3.0.0"}

@app.get("/config")
def config():
    return {"env": "dev", "debug": True}

# ============================================================
# User Endpoints
# ============================================================

@app.get("/users")
def get_users():
    return users

@app.get("/users/{user_id}")
def get_user(user_id: int):
    for u in users:
        if u.id == user_id:
            return u
    raise HTTPException(404)

@app.get("/users/search")
def search_users(name: Optional[str] = None):
    return [u for u in users if name is None or name.lower() in u.name.lower()]

@app.get("/users/{user_id}/orders")
def user_orders(user_id: int):
    return [o for o in orders if o.user_id == user_id]

@app.get("/users/{user_id}/stats")
def user_stats(user_id: int):
    user_orders_list = [o.total for o in orders if o.user_id == user_id]
    return {"count": len(user_orders_list), "total": sum(user_orders_list)}

# ============================================================
# Product Endpoints
# ============================================================

@app.get("/products")
def get_products():
    return products

@app.get("/products/search")
def search_products(min_price: float = 0, max_price: float = 10000):
    return [p for p in products if min_price <= p.price <= max_price]

@app.get("/products/{product_id}")
def get_product(product_id: int):
    for p in products:
        if p.id == product_id:
            return p
    raise HTTPException(404)

@app.get("/products/top")
def top_products():
    return sorted(products, key=lambda x: x.price, reverse=True)[:5]

@app.get("/products/out-of-stock")
def out_of_stock():
    return [p for p in products if not p.in_stock]

# ============================================================
# Orders
# ============================================================

@app.get("/orders")
def get_orders():
    return orders

@app.get("/orders/{order_id}")
def get_order(order_id: str):
    for o in orders:
        if o.order_id == order_id:
            return o
    raise HTTPException(404)

@app.get("/orders/user/{user_id}")
def get_orders_by_user(user_id: int):
    return [o for o in orders if o.user_id == user_id]

@app.get("/orders/high-value")
def high_value_orders(threshold: float = 1000):
    return [o for o in orders if o.total > threshold]

@app.get("/orders/stats")
def order_stats():
    totals = [o.total for o in orders]
    return {"count": len(totals), "sum": sum(totals), "avg": sum(totals)/len(totals)}

# ============================================================
# Logs & Monitoring
# ============================================================

@app.get("/logs")
def get_logs():
    return logs

@app.get("/logs/errors")
def error_logs():
    return [l for l in logs if l["level"] == "ERROR"]

@app.get("/logs/recent")
def recent_logs(limit: int = 10):
    return logs[-limit:]

@app.get("/logs/{log_id}")
def get_log(log_id: int):
    return logs[log_id]

# ============================================================
# Files
# ============================================================

@app.get("/files")
def get_files():
    return files

@app.get("/files/{file_id}")
def get_file(file_id: int):
    for f in files:
        if f["id"] == file_id:
            return f
    raise HTTPException(404)

@app.get("/files/large")
def large_files(size: int = 5000):
    return [f for f in files if f["size"] > size]

# ============================================================
# Analytics
# ============================================================

@app.get("/analytics/revenue")
def revenue():
    return {"total": sum(o.total for o in orders)}

@app.get("/analytics/users")
def user_count():
    return {"total_users": len(users)}

@app.get("/analytics/products")
def product_count():
    return {"total_products": len(products)}

# ============================================================
# Auth (Mock)
# ============================================================

@app.post("/auth/login")
def login(username: str, password: str):
    return {"token": f"fake-token-{username}"}

@app.post("/auth/logout")
def logout():
    return {"message": "logged out"}

@app.get("/auth/audit-logs")
def audit_logs():
    return [{"event": "login", "time": str(datetime.utcnow())}]

# ============================================================
# Notifications
# ============================================================

@app.get("/notifications")
def get_notifications():
    return [{"id": i, "msg": f"Notification {i}"} for i in range(5)]

@app.post("/notifications/send")
def send_notification(msg: str):
    return {"status": "sent", "msg": msg}

# ============================================================
# Debug / Testing
# ============================================================

@app.get("/debug/echo")
def echo(msg: str):
    return {"echo": msg}

@app.get("/debug/random")
def random_data():
    return {"number": random.randint(1, 1000)}

@app.get("/debug/time")
def debug_time():
    return {"time": datetime.utcnow()}

@app.get("/debug/headers")
def headers():
    return {"agent": "test-client"}

@app.get("/debug/status")
def debug_status(code: int = Query(200)):
    return {"status": code}

# ============================================================
# ☠️ ZOMBIE ENDPOINTS (UNLINKED + UNDOCUMENTED)
# ============================================================

# NOTE: These endpoints are intentionally:
# - NOT referenced anywhere
# - NOT included in OpenAPI schema
# - Designed to look forgotten / legacy / internal


@app.get("/internal/users_dump", include_in_schema=False)
def zombie_users_dump():
    return {
        "exported_at": str(datetime.utcnow()),
        "data": [u.dict() for u in users]
    }


@app.get("/internal/orders_raw", include_in_schema=False)
def zombie_orders_raw():
    return [o.dict() for o in orders]


@app.get("/debug-old/system_info", include_in_schema=False)
def zombie_system_info():
    return {
        "hostname": "legacy-server-01",
        "env": "staging",
        "debug": True,
        "uptime": "243 days"
    }


@app.get("/v1/_hidden/metrics_full", include_in_schema=False)
def zombie_full_metrics():
    return {
        "cpu": random.random(),
        "memory": random.random(),
        "disk": random.random(),
        "threads": random.randint(50, 300)
    }


@app.get("/private/cards", include_in_schema=False)
def zombie_cards():
    # Intentionally UNMASKED (great for PII detection testing)
    return [c.__dict__ for c in credit_cards]


@app.get("/_internal/logs/all", include_in_schema=False)
def zombie_all_logs():
    return logs


@app.get("/legacy/getUserData", include_in_schema=False)
def zombie_legacy_user(user_id: int):
    for u in users:
        if u.id == user_id:
            return {"user": u, "legacy": True}
    raise HTTPException(404)


@app.get("/test/debug_dump", include_in_schema=False)
def zombie_debug_dump():
    return {
        "users": len(users),
        "orders": len(orders),
        "products": len(products),
        "timestamp": str(datetime.utcnow())
    }


@app.get("/backup/orders_2022", include_in_schema=False)
def zombie_backup_orders():
    # fake "old dataset"
    return [{"order_id": f"OLD-{i}", "total": random.randint(10, 500)} for i in range(10)]


@app.get("/admin/export/all", include_in_schema=False)
def zombie_admin_export():
    return {
        "users": users,
        "orders": orders,
        "products": products
    }


@app.get("/shadow/api_keys", include_in_schema=False)
def zombie_api_keys():
    return [
        {"service": "payment", "key": "sk_test_123456"},
        {"service": "email", "key": "mailgun_test_abcdef"}
    ]


@app.get("/ghost/endpoint", include_in_schema=False)
def zombie_ghost():
    return {"message": "You found a ghost endpoint 👻"}


@app.get("/tmp/session_dump", include_in_schema=False)
def zombie_sessions():
    return [{"session_id": f"sess_{i}", "user": random.randint(1,10)} for i in range(5)]


@app.get("/v2/internal/no-docs", include_in_schema=False)
def zombie_v2_internal():
    return {"status": "hidden", "version": 2}


@app.get("/forgotten/analytics/raw", include_in_schema=False)
def zombie_raw_analytics():
    return {
        "clicks": random.randint(1000, 5000),
        "sessions": random.randint(500, 2000),
        "bounce_rate": random.random()
    }
