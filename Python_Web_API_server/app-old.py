from fastapi import FastAPI
from datetime import datetime
from typing import List

app = FastAPI(
    title="Temporary Test API",
    description="Local API backend for testing purposes",
    version="1.0.0",
)

# -----------------------------
# Sample In‑Memory Data
# -----------------------------

users = [
    {"id": 1, "name": "Alice Smith", "email": "alice@example.com", "role": "admin"},
    {"id": 2, "name": "Bob Johnson", "email": "bob@example.com", "role": "user"},
]

products = [
    {"id": 100, "name": "Laptop", "price": 1299.99, "in_stock": True},
    {"id": 101, "name": "Keyboard", "price": 99.99, "in_stock": False},
]

orders = [
    {"order_id": "ORD-001", "user_id": 1, "total": 1499.98},
    {"order_id": "ORD-002", "user_id": 2, "total": 99.99},
]

# -----------------------------
# API Endpoints (10 total)
# -----------------------------

@app.get("/")
def root():
    return {"message": "Test API is running"}

@app.get("/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.utcnow()}

@app.get("/users")
def get_users():
    return users

@app.get("/users/{user_id}")
def get_user(user_id: int):
    return next((u for u in users if u["id"] == user_id), {"error": "User not found"})

@app.get("/products")
def get_products():
    return products

@app.get("/products/{product_id}")
def get_product(product_id: int):
    return next((p for p in products if p["id"] == product_id), {"error": "Product not found"})

@app.get("/orders")
def get_orders():
    return orders

@app.get("/stats")
def get_stats():
    return {
        "total_users": len(users),
        "total_products": len(products),
        "total_orders": len(orders),
    }

@app.get("/config")
def get_config():
    return {
        "environment": "local",
        "debug": True,
        "version": "1.0.0",
    }

@app.get("/random")
def random_data():
    return {
        "value": 42,
        "message": "Hello from the random endpoint",
    }

