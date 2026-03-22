import time
import uuid
import re
from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Cookie, Response, Request, Depends
from pydantic import BaseModel, EmailStr, Field, validator
from itsdangerous import Signer


# базовые настройки

app = FastAPI(title="Контрольная работа №2")

# Секретный ключ для криптографических подписей сессий
SECRET_KEY = "super-secret-key-for-kr2"
signer = Signer(SECRET_KEY)


# модели данных (Pydantic)

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    age: Optional[int] = Field(None, gt=0)
    is_subscribed: Optional[bool] = False

class LoginData(BaseModel):
    username: str
    password: str

class CommonHeaders(BaseModel):
    user_agent: str
    accept_language: str

    @validator('accept_language')
    def validate_language(cls, v):
        if not re.match(r'^[a-zA-Z\-0-9\.,;= ]+$', v):
            raise ValueError('Invalid Accept-Language format')
        return v


# ЗАДАНИЕ 3.1: Работа с данными пользователя

@app.post("/create_user")
def create_user(user: UserCreate):
    return user


# ЗАДАНИЕ 3.2: Обработка продуктов (товаров)

sample_products = [
    {"product_id": 123, "name": "Smartphone", "category": "Electronics", "price": 599.99},
    {"product_id": 456, "name": "Phone Case", "category": "Accessories", "price": 19.99},
    {"product_id": 789, "name": "Iphone", "category": "Electronics", "price": 1299.99},
    {"product_id": 101, "name": "Headphones", "category": "Accessories", "price": 99.99},
    {"product_id": 202, "name": "Smartwatch", "category": "Electronics", "price": 299.99}
]

@app.get("/products/search")
def search_products(keyword: str, category: Optional[str] = None, limit: int = 10):
    results = []
    for p in sample_products:
        if keyword.lower() in p["name"].lower():
            if category is None or p["category"].lower() == category.lower():
                results.append(p)
    return results[:limit]

@app.get("/product/{product_id}")
def get_product(product_id: int):
    for p in sample_products:
        if p["product_id"] == product_id:
            return p
    raise HTTPException(status_code=404, detail="Product not found")


# ЗАДАНИЯ 5.1 - 5.3: Аутентификация и сессии

@app.post("/login")
def login(data: LoginData, response: Response):
    if data.username != "user123" or data.password != "password123":
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_id = str(uuid.uuid4())
    timestamp = str(int(time.time()))
    value_to_sign = f"{user_id}.{timestamp}"
    signature = signer.get_signature(value_to_sign.encode()).decode()
    session_token = f"{value_to_sign}.{signature}"

    response.set_cookie(key="session_token", value=session_token, httponly=True, max_age=300, secure=False)
    return {"message": "Logged in successfully"}

@app.get("/profile")
def get_profile(response: Response, session_token: Optional[str] = Cookie(None)):
    if not session_token:
        raise HTTPException(status_code=401, detail="Unauthorized")

    parts = session_token.split(".")
    if len(parts) != 3:
        raise HTTPException(status_code=401, detail="Invalid session")

    user_id, timestamp_str, signature = parts
    value_to_sign = f"{user_id}.{timestamp_str}"

    if not signer.verify_signature(value_to_sign.encode(), signature.encode()):
        raise HTTPException(status_code=401, detail="Invalid session")

    try:
        timestamp = int(timestamp_str)
    except ValueError:
        raise HTTPException(status_code=401, detail="Invalid session")

    current_time = int(time.time())
    diff = current_time - timestamp

    if diff >= 300:
        raise HTTPException(status_code=401, detail="Session expired")

    if 180 <= diff < 300:
        new_ts = str(current_time)
        new_val = f"{user_id}.{new_ts}"
        new_sig = signer.get_signature(new_val.encode()).decode()
        new_token = f"{new_val}.{new_sig}"
        response.set_cookie(key="session_token", value=new_token, httponly=True, max_age=300, secure=False)

    return {"user_id": user_id, "profile_data": "Успешный доступ к защищенному профилю"}


# ЗАДАНИЯ 5.4 - 5.5: Работа с заголовками

def get_common_headers(request: Request):
    user_agent = request.headers.get("User-Agent")
    accept_language = request.headers.get("Accept-Language")

    if not user_agent or not accept_language:
        raise HTTPException(status_code=400, detail="Missing required headers")

    try:
        return CommonHeaders(user_agent=user_agent, accept_language=accept_language)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/headers")
def read_headers(headers: CommonHeaders = Depends(get_common_headers)):
    return {
        "User-Agent": headers.user_agent,
        "Accept-Language": headers.accept_language
    }

@app.get("/info")
def read_info(response: Response, headers: CommonHeaders = Depends(get_common_headers)):
    response.headers["X-Server-Time"] = datetime.now().isoformat()
    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent": headers.user_agent,
            "Accept-Language": headers.accept_language
        }
    }