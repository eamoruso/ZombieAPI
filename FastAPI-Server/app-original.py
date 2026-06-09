from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from datetime import datetime
from typing import List

app = FastAPI(
    title="Temporary Test API",
    description="Local API backend with browser-friendly front page",
    version="2.0.0",
)

# ============================================================
# Helper Functions
# ============================================================

def mask_card(card):
    return {
        "user_id": card.user_id,
        "last4": card.number[-4:],
        "expire": card.expire,
    }

# ============================================================
# Data Models
# ============================================================

class User(BaseModel):
    id: int
    name: str
    email: str
    role: str

class UserAddress(BaseModel):
    user_id: int
    street: str
    city: str
    state: str
    zip_code: str
    country: str

class UserShoppingPreferences(BaseModel):
    user_id: int
    preferred_categories: List[str]
    email_notifications: bool
    sms_notifications: bool

class Product(BaseModel):
    id: int
    name: str
    price: float
    in_stock: bool

class ProductInventory(BaseModel):
    product_id: int
    warehouse: str
    quantity: int
    restock_threshold: int

class Order(BaseModel):
    order_id: str
    user_id: int
    total: float

class CreditCard(BaseModel):
    user_id: int
    number: str
    expire: str

# ============================================================
# In-Memory Storage
# ============================================================

users = [
    User(id=1, name="Alice Smith", email="alice@example.com", role="admin"),
    User(id=2, name="Bob Johnson", email="bob@example.com", role="user"),
    User(id=3, name="Cindy Johnson", email="cindy@example.com", role="user"),
    User(id=4, name="Trudy Doe", email="trudy@example.com", role="user"),
    User(id=5, name="John Doe", email="john@example.com", role="user"),
]

user_addresses = [
    UserAddress(user_id=1, street="123 Main St", city="Orlando", state="FL", zip_code="32801", country="USA"),
    UserAddress(user_id=2, street="456 Oak Ave", city="Tampa", state="FL", zip_code="33602", country="USA"),
    UserAddress(user_id=3, street="456 Oak Ave", city="Tampa", state="FL", zip_code="33602", country="USA"),
]

user_preferences = [
    UserShoppingPreferences(user_id=1, preferred_categories=["electronics", "gaming"], email_notifications=True, sms_notifications=False),
    UserShoppingPreferences(user_id=2, preferred_categories=["office", "home"], email_notifications=True, sms_notifications=True),
]

products = [
    Product(id=100, name="Laptop", price=1299.99, in_stock=True),
    Product(id=101, name="Keyboard", price=99.99, in_stock=False),
    Product(id=102, name="Gaming Mouse", price=199.99, in_stock=True),
    Product(id=103, name="Gaming Console", price=1299.99, in_stock=True),
]

product_inventory = [
    ProductInventory(product_id=100, warehouse="WH-A", quantity=25, restock_threshold=5),
    ProductInventory(product_id=101, warehouse="WH-B", quantity=3, restock_threshold=10),
]

orders = [
    Order(order_id="ORD-001", user_id=1, total=1499.98),
    Order(order_id="ORD-002", user_id=2, total=99.99),
    Order(order_id="ORD-003", user_id=3, total=199.99),
    Order(order_id="ORD-004", user_id=4, total=2499.98),
    Order(order_id="ORD-005", user_id=4, total=399.99),
    Order(order_id="ORD-006", user_id=5, total=599.99),
]

credit_cards = [
    CreditCard(user_id=1, number="378282246310005", expire="12/29"),
    CreditCard(user_id=2, number="378284630112115", expire="10/26"),
    CreditCard(user_id=3, number="378263009110322", expire="01/27"),
    CreditCard(user_id=4, number="378282246313305", expire="11/29"),
    CreditCard(user_id=5, number="378256746310407", expire="09/30"),
]

# ============================================================
# Shared HTML helpers
# ============================================================

NAV = """
<nav>
  <a href="/">🏠 Home</a>
  <a href="/help">❓ Help</a>
  <a href="/about">🏢 About Us</a>
  <a href="/faq">💬 FAQ</a>
  <a href="/docs">📘 API Docs</a>
</nav>
"""

BASE_STYLE = """
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: system-ui, sans-serif; background: #0f172a; color: #e5e7eb; padding: 40px 20px; max-width: 900px; margin: auto; }
  h1 { font-size: 2rem; margin-bottom: 8px; }
  h2 { font-size: 1.3rem; color: #93c5fd; margin: 24px 0 8px; }
  p  { line-height: 1.7; color: #cbd5e1; margin-bottom: 12px; }
  .card { background: #1e293b; padding: 24px; border-radius: 12px; margin-bottom: 20px; }
  .tag { display: inline-block; background: #0ea5e9; color: #fff; font-size: 0.75rem; padding: 2px 8px; border-radius: 99px; margin-bottom: 12px; }
  nav { display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 32px; }
  nav a { color: #60a5fa; text-decoration: none; font-weight: 600; }
  nav a:hover { text-decoration: underline; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; }
  .stat { font-size: 2rem; font-weight: 700; color: #38bdf8; }
  ul { list-style: none; padding: 0; }
  ul li { padding: 6px 0; border-bottom: 1px solid #334155; color: #cbd5e1; }
  ul li:last-child { border: none; }
  details { margin-bottom: 12px; }
  summary { cursor: pointer; font-weight: 600; color: #93c5fd; padding: 10px 0; }
  summary:hover { color: #60a5fa; }
  details[open] summary { color: #38bdf8; }
  details p { margin-top: 8px; padding-left: 12px; border-left: 3px solid #334155; }
</style>
"""

# ============================================================
# Front Page
# ============================================================

@app.get("/", response_class=HTMLResponse)
def home():
    return f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Test API Dashboard</title>{BASE_STYLE}</head>
<body>
{NAV}
<h1>🚀 Test API Dashboard</h1>
<p>Welcome to the local test API server. Use the links above to explore the documentation or browse live data below.</p>

<div class="card">
  <span class="tag">STATUS</span>
  <div style="font-size:1.1rem;">API Status: ✅ Running</div>
</div>

<div class="card grid" id="stats-grid">
  <div><div style="color:#94a3b8;font-size:.85rem;">USERS</div><div class="stat" id="u">-</div></div>
  <div><div style="color:#94a3b8;font-size:.85rem;">PRODUCTS</div><div class="stat" id="p">-</div></div>
  <div><div style="color:#94a3b8;font-size:.85rem;">ORDERS</div><div class="stat" id="o">-</div></div>
  <div><div style="color:#94a3b8;font-size:.85rem;">CREDIT CARDS</div><div class="stat" id="c">-</div></div>
</div>

<div class="card grid">
  <a href="/users">👤 Users</a>
  <a href="/products">📦 Products</a>
  <a href="/orders">🧾 Orders</a>
  <a href="/docs">📘 Swagger Docs</a>
</div>

<script>
fetch("/stats").then(r=>r.json()).then(d=>{{
  document.getElementById("u").innerText = d.total_users;
  document.getElementById("p").innerText = d.total_products;
  document.getElementById("o").innerText = d.total_orders;
  document.getElementById("c").innerText = d.total_credit_cards;
}});
</script>
</body>
</html>
"""

# ============================================================
# Help Page
# ============================================================

@app.get("/help", response_class=HTMLResponse)
def help_page():
    return f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Help — Test API</title>{BASE_STYLE}</head>
<body>
{NAV}
<h1>❓ Help Center</h1>
<p>This page covers how to run, configure, and interact with the Test API server.</p>

<div class="card">
  <h2>⚡ Quick Start</h2>
  <p>Make sure you have Python 3.9+ and the required dependencies installed, then run:</p>
  <pre style="background:#0f172a;padding:12px;border-radius:8px;overflow-x:auto;color:#7dd3fc;">pip install fastapi uvicorn
uvicorn app:app --reload --port 8000</pre>
  <p>The server will be available at <strong>http://localhost:8000</strong>.</p>
</div>

<div class="card">
  <h2>🔗 Key Endpoints</h2>
  <ul>
    <li><strong>GET /</strong> — Dashboard home page</li>
    <li><strong>GET /health</strong> — Health check (JSON)</li>
    <li><strong>GET /stats</strong> — Record counts (JSON)</li>
    <li><strong>GET /users</strong> — List all users</li>
    <li><strong>GET /products</strong> — List all products</li>
    <li><strong>GET /orders</strong> — List all orders</li>
    <li><strong>GET /credit-cards</strong> — Masked credit card list</li>
    <li><strong>GET /docs</strong> — Interactive Swagger UI</li>
  </ul>
</div>

<div class="card">
  <h2>🛠️ Authentication</h2>
  <p>This is a local test server with <strong>no authentication</strong> required. All endpoints are open. Do not expose this server to public networks.</p>
</div>

<div class="card">
  <h2>📬 Contact Support</h2>
  <p>For issues, open a ticket in the internal project tracker or reach out to the backend team at <strong>backend-team@example.com</strong>.</p>
</div>
</body>
</html>
"""

# ============================================================
# About Us Page
# ============================================================

@app.get("/about", response_class=HTMLResponse)
def about_page():
    return f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>About Us — Test API</title>{BASE_STYLE}</head>
<body>
{NAV}
<h1>🏢 About Us</h1>
<p>Learn more about the team and mission behind this project.</p>

<div class="card">
  <h2>🎯 Our Mission</h2>
  <p>The Test API project was built to provide developers with a fast, lightweight sandbox for prototyping, integration testing, and demo environments. No external dependencies, no cloud accounts — just a local server you can spin up in seconds.</p>
</div>

<div class="card">
  <h2>🧑‍💻 The Team</h2>
  <div class="grid">
    <div style="background:#0f172a;padding:16px;border-radius:8px;">
      <div style="font-weight:700;">Alice Smith</div>
      <div style="color:#94a3b8;font-size:.85rem;">Lead Backend Engineer</div>
      <div style="color:#cbd5e1;font-size:.9rem;margin-top:6px;">API design, data modeling, security</div>
    </div>
    <div style="background:#0f172a;padding:16px;border-radius:8px;">
      <div style="font-weight:700;">Bob Johnson</div>
      <div style="color:#94a3b8;font-size:.85rem;">DevOps & Infrastructure</div>
      <div style="color:#cbd5e1;font-size:.9rem;margin-top:6px;">Deployment pipelines, containerization</div>
    </div>
    <div style="background:#0f172a;padding:16px;border-radius:8px;">
      <div style="font-weight:700;">Cindy Johnson</div>
      <div style="color:#94a3b8;font-size:.85rem;">QA & Testing</div>
      <div style="color:#cbd5e1;font-size:.9rem;margin-top:6px;">Test coverage, integration scenarios</div>
    </div>
  </div>
</div>

<div class="card">
  <h2>🗓️ Project Timeline</h2>
  <ul>
    <li><strong>v1.0</strong> — Initial release with user and product endpoints</li>
    <li><strong>v1.5</strong> — Added order management and credit card masking</li>
    <li><strong>v2.0</strong> — Dashboard UI, inventory tracking, shopping preferences</li>
  </ul>
</div>

<div class="card">
  <h2>📍 Location</h2>
  <p>Headquartered in Orlando, FL. This project is maintained as an internal development tool.</p>
</div>
</body>
</html>
"""

# ============================================================
# FAQ Page
# ============================================================

@app.get("/faq", response_class=HTMLResponse)
def faq_page():
    return f"""
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>FAQ — Test API</title>{BASE_STYLE}</head>
<body>
{NAV}
<h1>💬 Frequently Asked Questions</h1>
<p>Answers to the most common questions about this test API server.</p>

<div class="card">
  <h2>General</h2>

  <details>
    <summary>What is this API used for?</summary>
    <p>This is a local sandbox API designed for development and integration testing. It provides mock data for users, products, orders, and credit cards so you can test your frontend or client code without a real backend.</p>
  </details>

  <details>
    <summary>Is this safe to use in production?</summary>
    <p>No. This server uses in-memory storage with no persistence, no authentication, and no rate limiting. It is intended for local development and testing only. Never expose it to a public network.</p>
  </details>

  <details>
    <summary>Does data persist between restarts?</summary>
    <p>No. All data is stored in memory and resets every time the server restarts. If you need persistence, consider adding a database backend such as SQLite or PostgreSQL.</p>
  </details>
</div>

<div class="card">
  <h2>API Usage</h2>

  <details>
    <summary>How do I create a new user?</summary>
    <p>Send a POST request to <code style="color:#7dd3fc;">/users</code> with a JSON body containing <code>id</code>, <code>name</code>, <code>email</code>, and <code>role</code>. User IDs must be unique.</p>
  </details>

  <details>
    <summary>Why are credit card numbers masked?</summary>
    <p>Even in a test environment, the API masks card numbers to reinforce secure coding habits. The <code>/credit-cards</code> endpoints return only the last 4 digits and expiry date — never the full number.</p>
  </details>

  <details>
    <summary>Where can I find the full API reference?</summary>
    <p>Visit <a href="/docs">/docs</a> for the interactive Swagger UI, which lists every endpoint, its parameters, and lets you make test requests directly in the browser.</p>
  </details>

  <details>
    <summary>How do I check if the server is running?</summary>
    <p>Hit <a href="/health">/health</a> — it returns a JSON object with status <code>"ok"</code> and the current server timestamp.</p>
  </details>
</div>

<div class="card">
  <h2>Troubleshooting</h2>

  <details>
    <summary>I get a 404 on a user or product endpoint.</summary>
    <p>Make sure the ID you are requesting exists in the in-memory dataset. On startup the server loads a fixed set of seed records. If you deleted a record earlier in the session it will not come back until the server restarts.</p>
  </details>

  <details>
    <summary>I get a 400 "already exists" error when creating a record.</summary>
    <p>The API enforces unique IDs. Choose a different <code>id</code> (for users/products) or <code>order_id</code> (for orders) that is not already in the dataset.</p>
  </details>

  <details>
    <summary>The server won't start — port already in use.</summary>
    <p>Another process is using port 8000. Either stop that process or start the server on a different port: <code style="color:#7dd3fc;">uvicorn app:app --reload --port 8080</code></p>
  </details>
</div>
</body>
</html>
"""

# ============================================================
# Health & Stats
# ============================================================

@app.get("/health")
def health():
    return {"status": "ok", "timestamp": datetime.utcnow()}

@app.get("/stats")
def stats():
    return {
        "total_users": len(users),
        "total_products": len(products),
        "total_orders": len(orders),
        "total_credit_cards": len(credit_cards),
    }

# ============================================================
# USERS
# ============================================================

@app.get("/users")
def get_users():
    return users

@app.post("/users")
def create_user(user: User):
    if any(u.id == user.id for u in users):
        raise HTTPException(400, "User ID already exists")
    users.append(user)
    return user

@app.put("/users/{user_id}")
def update_user(user_id: int, updated: User):
    for i, u in enumerate(users):
        if u.id == user_id:
            users[i] = updated
            return updated
    raise HTTPException(404, "User not found")

@app.delete("/users/{user_id}")
def delete_user(user_id: int):
    for i, u in enumerate(users):
        if u.id == user_id:
            users.pop(i)
            return {"message": "User deleted"}
    raise HTTPException(404, "User not found")

@app.get("/users/addresses")
def get_addresses():
    return user_addresses

@app.get("/users/{user_id}/address")
def get_address(user_id: int):
    for a in user_addresses:
        if a.user_id == user_id:
            return a
    raise HTTPException(404, "Address not found")

@app.get("/users/preferences")
def get_preferences():
    return user_preferences

@app.get("/users/{user_id}/preferences")
def get_user_preferences(user_id: int):
    for p in user_preferences:
        if p.user_id == user_id:
            return p
    raise HTTPException(404, "Preferences not found")

# ============================================================
# PRODUCTS
# ============================================================

@app.get("/products")
def get_products():
    return products

@app.get("/products/inventory")
def get_inventory():
    return product_inventory

@app.get("/products/{product_id}/inventory")
def get_product_inventory(product_id: int):
    for i in product_inventory:
        if i.product_id == product_id:
            return i
    raise HTTPException(404, "Inventory not found")

@app.post("/products")
def create_product(product: Product):
    if any(p.id == product.id for p in products):
        raise HTTPException(400, "Product ID already exists")
    products.append(product)
    return product

@app.put("/products/{product_id}")
def update_product(product_id: int, updated: Product):
    for i, p in enumerate(products):
        if p.id == product_id:
            products[i] = updated
            return updated
    raise HTTPException(404, "Product not found")

@app.delete("/products/{product_id}")
def delete_product(product_id: int):
    for i, p in enumerate(products):
        if p.id == product_id:
            products.pop(i)
            return {"message": "Product deleted"}
    raise HTTPException(404, "Product not found")

# ============================================================
# ORDERS
# ============================================================

@app.get("/orders")
def get_orders():
    return orders

@app.post("/orders")
def create_order(order: Order):
    if any(o.order_id == order.order_id for o in orders):
        raise HTTPException(400, "Order already exists")
    orders.append(order)
    return order

@app.delete("/orders/{order_id}")
def delete_order(order_id: str):
    for i, o in enumerate(orders):
        if o.order_id == order_id:
            orders.pop(i)
            return {"message": "Order deleted"}
    raise HTTPException(404, "Order not found")

# ============================================================
# CREDIT CARDS (MASKED)
# ============================================================

@app.get("/credit-cards")
def get_cards():
    return [mask_card(c) for c in credit_cards]

@app.get("/credit-cards/{user_id}")
def get_card(user_id: int):
    for c in credit_cards:
        if c.user_id == user_id:
            return mask_card(c)
    raise HTTPException(404, "Card not found")
