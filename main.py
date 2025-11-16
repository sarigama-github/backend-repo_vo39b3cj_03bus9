import os
import secrets
import hashlib
from datetime import datetime, timezone
from typing import Optional, List

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field, EmailStr
from bson.objectid import ObjectId

from database import db, create_document, get_documents

app = FastAPI(title="Nexus Explorer API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ------------------------
# Utility helpers
# ------------------------

def hash_password(password: str, salt: Optional[str] = None) -> str:
    if salt is None:
        salt = secrets.token_hex(16)
    h = hashlib.sha256((salt + password).encode("utf-8")).hexdigest()
    return f"{salt}${h}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, _hash = stored_hash.split("$")
    except ValueError:
        return False
    return hash_password(password, salt) == stored_hash


def require_auth(authorization: Optional[str] = Header(default=None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Unauthorized")
    token = authorization.split(" ", 1)[1]
    user = db["user"].find_one({"active_tokens": token})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    user["_id"] = str(user["_id"])  # serialize
    return user


# ------------------------
# Schemas (requests/responses)
# ------------------------

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(..., min_length=6)


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class ProfileOut(BaseModel):
    id: str
    username: str
    email: EmailStr


class UpdateProfileRequest(BaseModel):
    username: Optional[str] = Field(None, min_length=3, max_length=32)
    email: Optional[EmailStr] = None


class CreateKeyRequest(BaseModel):
    username: Optional[str] = None  # label input as described


class ApiKeyOut(BaseModel):
    id: str
    label: Optional[str]
    key: str
    usage_count: int
    created_at: datetime


# ------------------------
# Auth endpoints
# ------------------------

@app.post("/auth/register")
def register(payload: RegisterRequest):
    # Unique email and username check
    if db["user"].find_one({"$or": [{"email": payload.email}, {"username": payload.username}] } ):
        raise HTTPException(status_code=400, detail="Username or email already exists")

    password_hash = hash_password(payload.password)
    user_doc = {
        "username": payload.username,
        "email": str(payload.email),
        "password_hash": password_hash,
        "active_tokens": [],
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res = db["user"].insert_one(user_doc)
    user_id = str(res.inserted_id)
    return {"ok": True, "user": {"id": user_id, "username": payload.username, "email": str(payload.email)}}


@app.post("/auth/login")
def login(payload: LoginRequest):
    user = db["user"].find_one({"email": str(payload.email)})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = secrets.token_urlsafe(32)
    db["user"].update_one({"_id": user["_id"]}, {"$push": {"active_tokens": token}, "$set": {"updated_at": datetime.now(timezone.utc)}})
    return {
        "ok": True,
        "token": token,
        "user": {"id": str(user["_id"]), "username": user["username"], "email": user["email"]},
    }


@app.post("/auth/logout")
def logout(user=Depends(require_auth), authorization: Optional[str] = Header(default=None)):
    token = authorization.split(" ", 1)[1]
    db["user"].update_one({"_id": ObjectId(user["_id"])}, {"$pull": {"active_tokens": token}})
    return {"ok": True}


# ------------------------
# Profile & Settings
# ------------------------

@app.get("/me", response_model=ProfileOut)
def me(user=Depends(require_auth)):
    return {"id": user["_id"], "username": user["username"], "email": user["email"]}


@app.patch("/me")
def update_me(payload: UpdateProfileRequest, user=Depends(require_auth)):
    updates = {}
    if payload.username:
        # Check uniqueness
        if db["user"].find_one({"username": payload.username, "_id": {"$ne": ObjectId(user["_id"])}}):
            raise HTTPException(status_code=400, detail="Username already taken")
        updates["username"] = payload.username
    if payload.email:
        if db["user"].find_one({"email": str(payload.email), "_id": {"$ne": ObjectId(user["_id"])}}):
            raise HTTPException(status_code=400, detail="Email already taken")
        updates["email"] = str(payload.email)
    if not updates:
        return {"ok": True}
    updates["updated_at"] = datetime.now(timezone.utc)
    db["user"].update_one({"_id": ObjectId(user["_id"])}, {"$set": updates})
    return {"ok": True}


# ------------------------
# API Keys
# ------------------------

@app.get("/api-keys", response_model=List[ApiKeyOut])
def list_api_keys(user=Depends(require_auth)):
    keys = db["apikey"].find({"user_id": user["_id"]}).sort("created_at", -1)
    results = []
    for k in keys:
        results.append({
            "id": str(k["_id"]),
            "label": k.get("label"),
            "key": k["key"],
            "usage_count": k.get("usage_count", 0),
            "created_at": k.get("created_at", datetime.now(timezone.utc)),
        })
    return results


@app.post("/api-keys/create")
def create_api_key(payload: CreateKeyRequest, user=Depends(require_auth)):
    # Generate random API key
    api_key = "nex_" + secrets.token_urlsafe(24)
    doc = {
        "user_id": user["_id"],
        "label": payload.username or user["username"],
        "key": api_key,
        "usage_count": 0,
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
    res_id = db["apikey"].insert_one(doc).inserted_id
    return {"ok": True, "key": api_key, "id": str(res_id)}


# Public endpoint to simulate API usage with provided key
@app.post("/use")
def use_api(key: str):
    doc = db["apikey"].find_one({"key": key})
    if not doc:
        raise HTTPException(status_code=404, detail="API key not found")
    db["apikey"].update_one({"_id": doc["_id"]}, {"$inc": {"usage_count": 1}, "$set": {"updated_at": datetime.now(timezone.utc)}})
    return {"ok": True}


@app.get("/stats")
def stats(user=Depends(require_auth)):
    total_keys = db["apikey"].count_documents({"user_id": user["_id"]})
    pipeline = [
        {"$match": {"user_id": user["_id"]}},
        {"$group": {"_id": None, "total": {"$sum": "$usage_count"}}}
    ]
    agg = list(db["apikey"].aggregate(pipeline))
    total_usage = agg[0]["total"] if agg else 0
    return {"total_keys": total_keys, "total_usage": total_usage}


@app.get("/")
def root():
    return {"name": "Nexus Explorer API", "status": "ok"}


@app.get("/test")
def test_database():
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }

    try:
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"

    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    return response


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
