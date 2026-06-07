from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from datetime import datetime
from typing import List

app = FastAPI(
    title="Temporary Test API",
    description="Local API backend with browser-friendly front page",
    version="1.3.0",
)

# ============================================================
# Helper Function
# ============================================================

def mask_card(card: CreditCard) -> CreditCardMasked:
    return CreditCardMasked(
        user_id=card.user_id,
        last4=card.number[-4:],
        expire=card.expire,
    )

# ============================================================
# Data Models
# ============================================================

class CreditCard(BaseModel):
    user_id: int
    number: str
    expire: str

class CreditCardMasked(BaseModel):
    user_id: int
    last4: str
    expire: str

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
# In-Memory Storage
# ============================================================

users: List[User] = [
    User(id=1, name="Alice Smith", email="alice@example.com", role="admin"),
    User(id=2, name="Bob Johnson", email="bob@example.com", role="user"),
    User(id=3, name="Cindy Johnson", email="cindy@example.com", role="user"),
    User(id=4, name="Trudy Doe", email="trudy@example.com", role="user"),
    User(id=5, name="John Doe", email="john@example.com", role="user"),
]

products: List[Product] = [
    Product(id=100, name="Laptop", price=1299.99, in_stock=True),
    Product(id=101, name="Keyboard", price=99.99, in_stock=False),
    Product(id=102, name="Gaming Mouse", price=199.99, in_stock=True),
    Product(id=103, name="Gaming Console", price=1299.99, in_stock=True),
]

orders: List[Order] = [
    Order(order_id="ORD-001", user_id=1, total=1499.98),
    Order(order_id="ORD-002", user_id=2, total=99.99),
    Order(order_id="ORD-003", user_id=3, total=199.99),
    Order(order_id="ORD-004", user_id=4, total=2499.98),
    Order(order_id="ORD-005", user_id=4, total=399.99),
    Order(order_id="ORD-006", user_id=5, total=599.99),
]

credit_cards: List[CreditCard] = [
    CreditCard(user_id=1, number="378282246310005", expire="12/29"),
    CreditCard(user_id=2, number="378284630112115", expire="10/26"),
    CreditCard(user_id=3, number="378263009110322", expire="01/27"),
    CreditCard(user_id=4, number="378282246313305", expire="11/29"),
    CreditCard(user_id=5, number="378256746310407", expire="09/30"),
]

# ============================================================
# Front Page (Browser Users)
# ============================================================

@app.get("/", response_class=HTMLResponse)
def home():
    return """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Test API Dashboard</title>
<style>
body {
    font-family: system-ui, -apple-system, BlinkMacSystemFont;
    background: linear-gradient(135deg, #0f172a, #020617);
    color: #e5e7eb;
    margin: 0;
    padding: 40px;
}
.container {
    max-width: 900px;
    margin: auto;
}
h1 {
    font-size: 2.6rem;
    margin-bottom: 0.2rem;
}
.subtitle {
    color: #94a3b8;
    margin-bottom: 2rem;
}
.card {
    background: #020617;
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 24px;
    box-shadow: 0 20px 40px rgba(0,0,0,0.45);
}
.grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 16px;
}
a.button {
    display: block;
    padding: 14px;
    background: #2563eb;
    color: white;
    text-decoration: none;
    border-radius: 10px;
    text-align: center;
    font-weight: 600;
}
a.button:hover {
    background: #1d4ed8;
}
.stat {
    font-size: 2rem;
    font-weight: bold;
    margin-top: 6px;
}
footer {
    margin-top: 40px;
    text-align: center;
    color: #94a3b8;
    font-size: 0.9rem;
}
code {
    background: #020617;
    padding: 4px 8px;
    border-radius: 6px;
    color: #93c5fd;
}
</style>
</head>

<body>
<div class="container">

<h1>🚀 Test API Dashboard</h1>
<div class="subtitle">Local FastAPI backend for development & testing</div>

<div class="card">
    <h2>Status</h2>
    <p>✅ API is running</p>
    <p>Base URL: <code>http://localhost:8000</code></p>
</div>

<div class="card">
    <h2>Quick Links</h2>
    <div class="grid">
        <a class="button" href="/users">👤 Users</a>
        <a class="button" href="/products">📦 Products</a>
        <a class="button" href="/orders">🧾 Orders</a>
        <a class="button" href="/docs">📘 API Docs</a>
    </div>
</div>

<div class="card">
    <h2>Live Stats</h2>
    <div class="grid">
        <div>Users<div id="users" class="stat">–</div></div>
        <div>Products<div id="products" class="stat">–</div></div>
        <div>Orders<div id="orders" class="stat">–</div></div>
    </div>
</div>

<footer>
    FastAPI • Local Only • In-Memory Data • Testing Environment
</footer>

</div>

<script>
fetch("/stats")
  .then(r => r.json())
  .then(data => {
    document.getElementById("users").textContent = data.total_users;
    document.getElementById("products").textContent = data.total_products;
    document.getElementById("orders").textContent = data.total_orders;
  });
</script>
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
    }

# ============================================================
# USERS (CRUD)
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

# ============================================================
# PRODUCTS (CRUD)
# ============================================================

@app.get("/products")
def get_products():
    return products

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
# CREDIT
# ============================================================

@app.get("/credit-cards", response_model=List[CreditCardMasked])
def get_credit_cards():
    return [mask_card(c) for c in credit_cards]

@app.get("/credit-cards/{user_id}", response_model=CreditCardMasked)
def get_credit_card(user_id: int):
    for card in credit_cards:
        if card.user_id == user_id:
            return mask_card(card)
    raise HTTPException(404, "Credit card not found")

@app.post("/credit-cards", response_model=CreditCardMasked)
def add_credit_card(card: CreditCard):
    if any(c.user_id == card.user_id for c in credit_cards):
        raise HTTPException(400, "User already has a card")
    credit_cards.append(card)
    return mask_card(card)
