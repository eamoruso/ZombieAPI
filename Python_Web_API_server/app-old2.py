from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
from typing import List

app = FastAPI(
    title="Temporary Test API",
    description="Local API backend for testing purposes",
    version="1.1.0",
)

# -----------------------------
# Data Models
# -----------------------------

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

# -----------------------------
# In‑Memory Storage
# -----------------------------

users: List[User] = [
    User(id=1, name="Alice Smith", email="alice@example.com", role="admin"),
    User(id=2, name="Bob Johnson", email="bob@example.com", role="user"),
]

products: List[Product] = [
    Product(id=100, name="Laptop", price=1299.99, in_stock=True),
    Product(id=101, name="Keyboard", price=99.99, in_stock=False),
]

orders: List[Order] = [
    Order(order_id="ORD-001", user_id=1, total=1499.98),
    Order(order_id="ORD-002", user_id=2, total=99.99),
]

# -----------------------------
# Basic Endpoints
# -----------------------------

@app.get("/")
def root():
    return {"message": "Test API is running"}

@app.get("/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow()}

# -----------------------------
# USERS (CRUD)
# -----------------------------

@app.get("/users")
def get_users():
    return users

@app.post("/users")
def create_user(user: User):
    if any(u.id == user.id for u in users):
        raise HTTPException(status_code=400, detail="User ID already exists")
    users.append(user)
    return user

@app.put("/users/{user_id}")
def update_user(user_id: int, updated_user: User):
    for index, user in enumerate(users):
        if user.id == user_id:
            users[index] = updated_user
            return updated_user
    raise HTTPException(status_code=404, detail="User not found")

@app.delete("/users/{user_id}")
def delete_user(user_id: int):
    for index, user in enumerate(users):
        if user.id == user_id:
            users.pop(index)
            return {"message": "User deleted"}
    raise HTTPException(status_code=404, detail="User not found")

# -----------------------------
# PRODUCTS (CRUD)
# -----------------------------

@app.get("/products")
def get_products():
    return products

@app.post("/products")
def create_product(product: Product):
    if any(p.id == product.id for p in products):
        raise HTTPException(status_code=400, detail="Product ID already exists")
    products.append(product)
    return product

@app.put("/products/{product_id}")
def update_product(product_id: int, updated_product: Product):
    for index, product in enumerate(products):
        if product.id == product_id:
            products[index] = updated_product
            return updated_product
    raise HTTPException(status_code=404, detail="Product not found")

@app.delete("/products/{product_id}")
def delete_product(product_id: int):
    for index, product in enumerate(products):
        if product.id == product_id:
            products.pop(index)
            return {"message": "Product deleted"}
    raise HTTPException(status_code=404, detail="Product not found")

# -----------------------------
# ORDERS (CRUD)
# -----------------------------

@app.get("/orders")
def get_orders():
    return orders

@app.post("/orders")
def create_order(order: Order):
    if any(o.order_id == order.order_id for o in orders):
        raise HTTPException(status_code=400, detail="Order already exists")
    orders.append(order)
    return order

@app.delete("/orders/{order_id}")
def delete_order(order_id: str):
    for index, order in enumerate(orders):
        if order.order_id == order_id:
            orders.pop(index)
            return {"message": "Order deleted"}
    raise HTTPException(status_code=404, detail="Order not found")

# -----------------------------
# Misc Test Endpoints
# -----------------------------

@app.get("/stats")
def get_stats():
    return {
        "total_users": len(users),
        "total_products": len(products),
        "total_orders": len(orders),
    }

@app.get("/random")
def random_data():
    return {"value": 42, "message": "Hello from the random endpoint"}
