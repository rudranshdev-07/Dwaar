from dotenv import load_dotenv
load_dotenv()

import logging
import os
import random
import uuid
from datetime import datetime, timedelta, timezone
from typing import List, Literal, Optional

import bcrypt
import jwt
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request, Response
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, EmailStr, Field
from pymongo import ReturnDocument
from starlette.middleware.cors import CORSMiddleware

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

JWT_ALGORITHM = "HS256"

app = FastAPI(title="DWAAR API")
api = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

STATUSES = ["arrived", "requested", "assigned", "picked_up", "on_the_way", "delivered"]
STATUS_RANK = {s: i for i, s in enumerate(STATUSES)}
NEXT_STATUS = {"assigned": "picked_up", "picked_up": "on_the_way", "on_the_way": "delivered"}

CAMPUS_LOCATIONS = [
    {"id": "hostel_a", "label": "Hostel A", "code": "HST-A", "distance_km": 1.2, "eta_min": 11},
    {"id": "hostel_b", "label": "Hostel B", "code": "HST-B", "distance_km": 0.8, "eta_min": 7},
    {"id": "academic", "label": "Academic Block", "code": "ACD-01", "distance_km": 0.6, "eta_min": 5},
    {"id": "library", "label": "Central Library", "code": "LIB-01", "distance_km": 1.0, "eta_min": 9},
    {"id": "cafeteria", "label": "Cafeteria", "code": "CAF-01", "distance_km": 0.4, "eta_min": 4},
    {"id": "sports", "label": "Sports Complex", "code": "SPT-01", "distance_km": 1.5, "eta_min": 13},
]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def pub(doc: Optional[dict]) -> Optional[dict]:
    if not doc:
        return None
    d = dict(doc)
    d.pop("_id", None)
    d.pop("password_hash", None)
    return d


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def get_jwt_secret() -> str:
    return os.environ["JWT_SECRET"]


def create_access_token(user_id: str, email: str, role: str) -> str:
    payload = {"sub": user_id, "email": email, "role": role, "type": "access",
               "exp": utcnow() + timedelta(minutes=15)}
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def create_refresh_token(user_id: str) -> str:
    payload = {"sub": user_id, "type": "refresh", "exp": utcnow() + timedelta(days=7)}
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)


def set_auth_cookies(response: Response, user: dict):
    access = create_access_token(user["id"], user["email"], user["role"])
    refresh = create_refresh_token(user["id"])
    response.set_cookie("access_token", access, httponly=True, secure=True, samesite="none", max_age=900, path="/")
    response.set_cookie("refresh_token", refresh, httponly=True, secure=True, samesite="none", max_age=604800, path="/")


async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return pub(user)


def require_role(*roles: str):
    async def dep(user: dict = Depends(get_current_user)) -> dict:
        if user["role"] not in roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return user
    return dep


class RegisterIn(BaseModel):
    name: str = Field(min_length=2, max_length=60)
    email: EmailStr
    password: str = Field(min_length=6, max_length=72)
    role: Literal["student", "partner"]
    hostel: Optional[str] = Field(default=None, max_length=40)
    room: Optional[str] = Field(default=None, max_length=12)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class ParcelIn(BaseModel):
    courier: str = Field(min_length=2, max_length=60)
    description: Optional[str] = Field(default=None, max_length=200)


class RequestDeliveryIn(BaseModel):
    building: str
    room: str = Field(min_length=1, max_length=12)


class StatusIn(BaseModel):
    status: Literal["picked_up", "on_the_way", "delivered"]


@api.get("/")
async def root():
    return {"message": "DWAAR API // From Gate to Door"}


@api.post("/auth/register")
async def register(body: RegisterIn, response: Response):
    email = body.email.lower()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    user = {
        "id": str(uuid.uuid4()),
        "name": body.name.strip(),
        "email": email,
        "password_hash": hash_password(body.password),
        "role": body.role,
        "hostel": body.hostel,
        "room": body.room,
        "created_at": utcnow().isoformat(),
    }
    await db.users.insert_one(user)
    set_auth_cookies(response, user)
    return pub(user)


@api.post("/auth/login")
async def login(body: LoginIn, request: Request, response: Response):
    email = body.email.lower()
    identifier = f"{request.client.host}:{email}"
    attempt = await db.login_attempts.find_one({"identifier": identifier})
    if attempt and attempt.get("count", 0) >= 5:
        locked_until = attempt.get("locked_until")
        if locked_until and datetime.fromisoformat(locked_until) > utcnow():
            raise HTTPException(status_code=429, detail="Too many failed attempts. Try again in 15 minutes.")
        await db.login_attempts.delete_one({"identifier": identifier})
    user = await db.users.find_one({"email": email})
    if not user or not verify_password(body.password, user["password_hash"]):
        await db.login_attempts.update_one(
            {"identifier": identifier},
            {"$inc": {"count": 1}, "$set": {"locked_until": (utcnow() + timedelta(minutes=15)).isoformat()}},
            upsert=True,
        )
        raise HTTPException(status_code=401, detail="Invalid email or password")
    await db.login_attempts.delete_one({"identifier": identifier})
    set_auth_cookies(response, user)
    return pub(user)


@api.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"message": "Logged out"}


@api.get("/auth/me")
async def me(user: dict = Depends(get_current_user)):
    return user


@api.post("/auth/refresh")
async def refresh(request: Request, response: Response):
    token = request.cookies.get("refresh_token")
    if not token:
        raise HTTPException(status_code=401, detail="No refresh token")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    user = await db.users.find_one({"id": payload["sub"]})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    access = create_access_token(user["id"], user["email"], user["role"])
    response.set_cookie("access_token", access, httponly=True, secure=True, samesite="none", max_age=900, path="/")
    return {"message": "Token refreshed"}


@api.get("/campus/locations")
async def campus_locations():
    return CAMPUS_LOCATIONS


def timeline_entry(status: str, note: str = "") -> dict:
    return {"status": status, "at": utcnow().isoformat(), "note": note}


async def generate_parcel_code() -> str:
    while True:
        code = f"DW-{random.randint(1000, 9999)}"
        if not await db.parcels.find_one({"code": code}):
            return code


@api.post("/parcels")
async def create_parcel(body: ParcelIn, user: dict = Depends(require_role("student", "admin"))):
    parcel = {
        "id": str(uuid.uuid4()),
        "code": await generate_parcel_code(),
        "owner_id": user["id"],
        "owner_name": user["name"],
        "courier": body.courier.strip(),
        "description": (body.description or "").strip(),
        "status": "arrived",
        "origin": "Main Gate",
        "destination": None,
        "partner_id": None,
        "partner_name": None,
        "timeline": [timeline_entry("arrived", "Parcel received at Main Gate")],
        "created_at": utcnow().isoformat(),
        "updated_at": utcnow().isoformat(),
    }
    await db.parcels.insert_one(parcel)
    return pub(parcel)


@api.get("/parcels/mine")
async def my_parcels(user: dict = Depends(require_role("student", "admin"))):
    cursor = db.parcels.find({"owner_id": user["id"]}).sort("created_at", -1)
    return [pub(p) async for p in cursor]


@api.get("/parcels/{parcel_id}")
async def get_parcel(parcel_id: str, user: dict = Depends(get_current_user)):
    parcel = await db.parcels.find_one({"id": parcel_id})
    if not parcel:
        raise HTTPException(status_code=404, detail="Parcel not found")
    if user["role"] not in ("admin",) and parcel["owner_id"] != user["id"] and parcel.get("partner_id") != user["id"]:
        raise HTTPException(status_code=403, detail="Forbidden")
    return pub(parcel)


@api.post("/parcels/{parcel_id}/request-delivery")
async def request_delivery(parcel_id: str, body: RequestDeliveryIn, user: dict = Depends(require_role("student", "admin"))):
    if body.building not in {loc["id"] for loc in CAMPUS_LOCATIONS}:
        raise HTTPException(status_code=400, detail="Unknown campus destination")
    result = await db.parcels.find_one_and_update(
        {"id": parcel_id, "owner_id": user["id"], "status": "arrived"},
        {"$set": {
            "status": "requested",
            "destination": {"building": body.building, "room": body.room.strip()},
            "updated_at": utcnow().isoformat(),
        }, "$push": {"timeline": timeline_entry("requested", "Room delivery requested")}},
        return_document=ReturnDocument.AFTER,
    )
    if not result:
        raise HTTPException(status_code=409, detail="Parcel not found or not in a requestable state")
    return pub(result)


@api.get("/deliveries/available")
async def available_deliveries(user: dict = Depends(require_role("partner", "admin"))):
    cursor = db.parcels.find({"status": "requested"}).sort("created_at", 1)
    return [pub(p) async for p in cursor]


@api.get("/deliveries/mine")
async def my_deliveries(user: dict = Depends(require_role("partner", "admin"))):
    cursor = db.parcels.find({"partner_id": user["id"]}).sort("updated_at", -1)
    return [pub(p) async for p in cursor]


@api.post("/deliveries/{parcel_id}/accept")
async def accept_delivery(parcel_id: str, user: dict = Depends(require_role("partner", "admin"))):
    result = await db.parcels.find_one_and_update(
        {"id": parcel_id, "status": "requested"},
        {"$set": {
            "status": "assigned",
            "partner_id": user["id"],
            "partner_name": user["name"],
            "updated_at": utcnow().isoformat(),
        }, "$push": {"timeline": timeline_entry("assigned", f"Assigned to {user['name']}")}},
        return_document=ReturnDocument.AFTER,
    )
    if not result:
        raise HTTPException(status_code=409, detail="Delivery already taken by another partner")
    return pub(result)


@api.post("/deliveries/{parcel_id}/status")
async def advance_status(parcel_id: str, body: StatusIn, user: dict = Depends(require_role("partner", "admin"))):
    parcel = await db.parcels.find_one({"id": parcel_id})
    if not parcel:
        raise HTTPException(status_code=404, detail="Delivery not found")
    if parcel.get("partner_id") != user["id"] and user["role"] != "admin":
        raise HTTPException(status_code=403, detail="This delivery is assigned to another partner")
    expected = NEXT_STATUS.get(parcel["status"])
    if expected != body.status:
        raise HTTPException(status_code=409, detail=f"Invalid transition from {parcel['status']} to {body.status}")
    notes = {"picked_up": "Parcel collected from Main Gate", "on_the_way": "Partner en route", "delivered": "Delivered to room"}
    result = await db.parcels.find_one_and_update(
        {"id": parcel_id},
        {"$set": {"status": body.status, "updated_at": utcnow().isoformat()},
         "$push": {"timeline": timeline_entry(body.status, notes[body.status])}},
        return_document=ReturnDocument.AFTER,
    )
    return pub(result)


@api.get("/stats/public")
async def public_stats():
    return {
        "delivered": await db.parcels.count_documents({"status": "delivered"}),
        "active": await db.parcels.count_documents({"status": {"$in": ["assigned", "picked_up", "on_the_way"]}}),
        "awaiting": await db.parcels.count_documents({"status": {"$in": ["arrived", "requested"]}}),
        "students": await db.users.count_documents({"role": "student"}),
        "partners": await db.users.count_documents({"role": "partner"}),
    }


async def seed_users():
    seeds = [
        (os.environ["ADMIN_EMAIL"], os.environ["ADMIN_PASSWORD"], "DWAAR Admin", "admin", None, None),
        ("aarav@student.dwaar.in", "dwaar123", "Aarav Mehta", "student", "Hostel B", "312"),
        ("meera@partner.dwaar.in", "dwaar123", "Meera Iyer", "partner", None, None),
    ]
    for email, password, name, role, hostel, room in seeds:
        existing = await db.users.find_one({"email": email})
        if existing is None:
            await db.users.insert_one({
                "id": str(uuid.uuid4()), "name": name, "email": email,
                "password_hash": hash_password(password), "role": role,
                "hostel": hostel, "room": room, "created_at": utcnow().isoformat(),
            })
        elif not verify_password(password, existing["password_hash"]):
            await db.users.update_one({"email": email}, {"$set": {"password_hash": hash_password(password)}})


async def seed_parcels():
    student = await db.users.find_one({"email": "aarav@student.dwaar.in"})
    if not student or await db.parcels.count_documents({}) > 0:
        return
    base = [
        {"code": "DW-1042", "courier": "Amazon", "description": "Textbooks — Data Structures", "status": "arrived", "destination": None},
        {"code": "DW-1043", "courier": "Flipkart", "description": "Headphones", "status": "requested",
         "destination": {"building": "hostel_b", "room": "312"}},
        {"code": "DW-1044", "courier": "Myntra", "description": "Hoodie (M)", "status": "delivered",
         "destination": {"building": "hostel_b", "room": "312"}},
    ]
    for spec in base:
        rank = STATUS_RANK[spec["status"]]
        timeline = [timeline_entry(s) for s in STATUSES[: rank + 1]]
        doc = {
            "id": str(uuid.uuid4()), "code": spec["code"], "owner_id": student["id"],
            "owner_name": student["name"], "courier": spec["courier"], "description": spec["description"],
            "status": spec["status"], "origin": "Main Gate", "destination": spec["destination"],
            "partner_id": None, "partner_name": None, "timeline": timeline,
            "created_at": utcnow().isoformat(), "updated_at": utcnow().isoformat(),
        }
        await db.parcels.insert_one(doc)


@app.on_event("startup")
async def startup():
    await db.users.create_index("email", unique=True)
    await db.parcels.create_index("code", unique=True)
    await db.parcels.create_index("status")
    await db.parcels.create_index("owner_id")
    await db.parcels.create_index("partner_id")
    await db.login_attempts.create_index("identifier")
    await db.password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)
    await seed_users()
    await seed_parcels()
    logger.info("DWAAR API started — From Gate to Door")


@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()


app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.environ.get("FRONTEND_URL", "http://localhost:3000"), "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
