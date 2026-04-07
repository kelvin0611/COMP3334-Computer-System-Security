import base64
import binascii
import json
import re
from datetime import datetime, timedelta, timezone
import os
from typing import Literal
from uuid import uuid4

import pyotp
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text, create_engine, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker

# Allow custom DB path for testing/demo isolation.
DATABASE_URL = os.environ.get("IM_DATABASE_URL", "sqlite:///./im.db")
JWT_SECRET = "CHANGE_THIS_FOR_PROD"
JWT_ALGO = "HS256"
ACCESS_TOKEN_MINUTES = 30
MAX_MESSAGE_AGE_HOURS = 24
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")
app = FastAPI(title="COMP3334 Secure IM")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@app.get("/healthz")
def healthz():
    return {"ok": True}


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(128), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    otp_secret = Column(String(64), nullable=False)
    identity_pubkey = Column(Text, nullable=False)
    blocked = Column(Text, default="")


class FriendRequest(Base):
    __tablename__ = "friend_requests"
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String(128), nullable=False, index=True)
    receiver = Column(String(128), nullable=False, index=True)
    status = Column(String(16), nullable=False, default="pending")
    created_at = Column(DateTime(timezone=True), default=utc_now)


class Friendship(Base):
    __tablename__ = "friendships"
    id = Column(Integer, primary_key=True, index=True)
    user_a = Column(String(128), nullable=False, index=True)
    user_b = Column(String(128), nullable=False, index=True)


class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    convo_id = Column(String(256), nullable=False, index=True)
    sender = Column(String(128), nullable=False, index=True)
    receiver = Column(String(128), nullable=False, index=True)
    ciphertext = Column(Text, nullable=False)
    nonce = Column(String(64), nullable=False)
    ad = Column(Text, nullable=False)
    msg_counter = Column(Integer, nullable=False)
    ttl_seconds = Column(Integer, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)
    sent_at = Column(DateTime(timezone=True), default=utc_now)
    delivered = Column(Boolean, default=False)
    delivered_at = Column(DateTime(timezone=True), nullable=True)
    acknowledged = Column(Boolean, default=False)
    kind = Column(String(16), nullable=False, default="chat", index=True)


class SeenCounter(Base):
    __tablename__ = "seen_counters"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(128), nullable=False, index=True)
    peer = Column(String(128), nullable=False, index=True)
    max_counter = Column(Integer, nullable=False, default=-1)


class RevokedToken(Base):
    __tablename__ = "revoked_tokens"
    id = Column(Integer, primary_key=True, index=True)
    jti = Column(String(64), nullable=False, unique=True, index=True)
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_buckets"
    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(255), nullable=False, index=True)
    window_start = Column(Integer, nullable=False, index=True)
    count = Column(Integer, nullable=False, default=0)


Base.metadata.create_all(bind=engine)


def ensure_schema_migrations():
    with engine.begin() as conn:
        msg_cols = [row[1] for row in conn.execute(text("PRAGMA table_info(messages)")).fetchall()]
        if "kind" not in msg_cols:
            conn.execute(text("ALTER TABLE messages ADD COLUMN kind TEXT NOT NULL DEFAULT 'chat'"))


ensure_schema_migrations()


class RegisterRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str = Field(min_length=8, max_length=128)
    identity_pubkey: str = Field(min_length=40, max_length=120)


class LoginRequest(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    password: str
    otp: str = Field(pattern=r"^\d{6}$")


class FriendRequestSend(BaseModel):
    receiver: str = Field(min_length=3, max_length=32)


class FriendRequestAction(BaseModel):
    request_id: int = Field(ge=1)
    action: Literal["accept", "decline"]


class FriendCancelRequest(BaseModel):
    request_id: int = Field(ge=1)


class MessageSendRequest(BaseModel):
    receiver: str = Field(min_length=3, max_length=32)
    convo_id: str = Field(min_length=3, max_length=256)
    ciphertext: str = Field(min_length=8, max_length=20000)
    nonce: str = Field(min_length=8, max_length=256)
    ad: str = Field(min_length=8, max_length=4096)
    msg_counter: int = Field(ge=1, le=1_000_000_000)
    ttl_seconds: int = Field(ge=1, le=86400)


class AckRequest(BaseModel):
    message_id: int = Field(ge=1)


class AckE2EERequest(BaseModel):
    receiver: str = Field(min_length=3, max_length=32)
    convo_id: str = Field(min_length=3, max_length=256)
    ciphertext: str = Field(min_length=8, max_length=12000)
    nonce: str = Field(min_length=8, max_length=256)
    ad: str = Field(min_length=8, max_length=4096)
    msg_counter: int = Field(ge=1, le=1_000_000_000)
    ttl_seconds: int = Field(ge=1, le=3600)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def create_token(username: str) -> str:
    exp = utc_now() + timedelta(minutes=ACCESS_TOKEN_MINUTES)
    jti = uuid4().hex
    return jwt.encode({"sub": username, "exp": exp, "jti": jti}, JWT_SECRET, algorithm=JWT_ALGO)


def token_payload(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


def token_payload_allow_expired(token: str) -> dict:
    """Decode JWT for logout/revocation: signature must be valid; exp may have passed."""
    try:
        return jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALGO],
            options={"verify_exp": False},
        )
    except JWTError as exc:
        raise HTTPException(status_code=401, detail="Invalid token") from exc


def current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    # Central auth guard: verify JWT + revocation + existing user.
    payload = token_payload(token)
    username = payload.get("sub")
    jti = payload.get("jti")
    if not username or not jti:
        raise HTTPException(status_code=401, detail="Invalid token payload")
    revoked = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
    if revoked:
        raise HTTPException(status_code=401, detail="Token revoked")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def is_friends(db: Session, u1: str, u2: str) -> bool:
    a, b = sorted([u1, u2])
    return db.query(Friendship).filter(Friendship.user_a == a, Friendship.user_b == b).first() is not None


def in_block_list(user: User, target: str) -> bool:
    return target in [x for x in user.blocked.split(",") if x]


def cleanup_expired_messages(db: Session):
    now = utc_now()
    db.query(Message).filter(
        (Message.expires_at <= now)
        | (Message.sent_at <= now - timedelta(hours=MAX_MESSAGE_AGE_HOURS))
    ).delete()
    db.commit()


def cleanup_revoked_tokens(db: Session):
    now = utc_now()
    db.query(RevokedToken).filter(RevokedToken.expires_at <= now).delete()
    db.commit()


def client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def enforce_rate_limit(db: Session, key: str, limit: int, window_seconds: int = 60):
    # Simple fixed-window rate limit persisted in DB.
    now = int(utc_now().timestamp())
    window_start = now - (now % window_seconds)
    bucket = db.query(RateLimitBucket).filter(
        RateLimitBucket.key == key,
        RateLimitBucket.window_start == window_start,
    ).first()
    if not bucket:
        bucket = RateLimitBucket(key=key, window_start=window_start, count=0)
        db.add(bucket)
    if bucket.count >= limit:
        db.commit()
        raise HTTPException(status_code=429, detail="Rate limit exceeded")
    bucket.count += 1
    db.commit()


def validate_username(username: str):
    if not USERNAME_RE.match(username):
        raise HTTPException(status_code=400, detail="Invalid username format")


def strict_b64decode(data: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(data.encode("utf-8"), validate=True)
    except (ValueError, binascii.Error) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid base64 in {field_name}") from exc


@app.post("/auth/register")
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    validate_username(payload.username)
    enforce_rate_limit(db, key=f"register:ip:{client_ip(request)}", limit=10, window_seconds=60)
    existing = db.query(User).filter(User.username == payload.username).first()
    if existing:
        raise HTTPException(status_code=400, detail="Username already exists")
    otp_secret = pyotp.random_base32()
    user = User(
        username=payload.username,
        password_hash=pwd_context.hash(payload.password),
        otp_secret=otp_secret,
        identity_pubkey=payload.identity_pubkey,
        blocked="",
    )
    db.add(user)
    db.commit()
    return {
        "message": "Registered",
        "otp_secret": otp_secret,
        "otp_uri": pyotp.TOTP(otp_secret).provisioning_uri(name=payload.username, issuer_name="COMP3334-IM"),
    }


@app.post("/auth/login")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    validate_username(payload.username)
    enforce_rate_limit(db, key=f"login:ip:{client_ip(request)}", limit=20, window_seconds=60)
    enforce_rate_limit(db, key=f"login:user:{payload.username}", limit=10, window_seconds=60)
    user = db.query(User).filter(User.username == payload.username).first()
    if not user or not pwd_context.verify(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not pyotp.TOTP(user.otp_secret).verify(payload.otp):
        raise HTTPException(status_code=401, detail="Invalid OTP")
    return {"access_token": create_token(user.username), "token_type": "bearer"}


@app.post("/auth/logout")
def logout(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
):
    # Do not use current_user here: tokens past exp would fail and user could never "log out" cleanly.
    payload = token_payload_allow_expired(token)
    username = payload.get("sub")
    jti = payload.get("jti")
    exp = payload.get("exp")
    if not username or not jti or not exp:
        raise HTTPException(status_code=400, detail="Invalid token payload")
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    expires_at = datetime.fromtimestamp(exp, tz=timezone.utc)
    cleanup_revoked_tokens(db)
    existing = db.query(RevokedToken).filter(RevokedToken.jti == jti).first()
    if not existing:
        db.add(RevokedToken(jti=jti, expires_at=expires_at))
        db.commit()
    return {"message": "Logged out"}


@app.get("/users/{username}/identity")
def get_identity(username: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    _ = user
    target = db.query(User).filter(User.username == username).first()
    if not target:
        raise HTTPException(status_code=404, detail="User not found")
    return {"username": username, "identity_pubkey": target.identity_pubkey}


@app.post("/friends/request")
def send_friend_request(payload: FriendRequestSend, user: User = Depends(current_user), db: Session = Depends(get_db)):
    validate_username(payload.receiver)
    enforce_rate_limit(db, key=f"friend_req:sender:{user.username}", limit=15, window_seconds=60)
    if payload.receiver == user.username:
        raise HTTPException(status_code=400, detail="Cannot friend yourself")
    receiver = db.query(User).filter(User.username == payload.receiver).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Target user not found")
    if in_block_list(receiver, user.username):
        raise HTTPException(status_code=403, detail="Blocked by receiver")
    if is_friends(db, user.username, payload.receiver):
        raise HTTPException(status_code=400, detail="Already friends")
    existing = db.query(FriendRequest).filter(
        FriendRequest.sender == user.username,
        FriendRequest.receiver == payload.receiver,
        FriendRequest.status == "pending",
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Pending request exists")
    req = FriendRequest(sender=user.username, receiver=payload.receiver, status="pending")
    db.add(req)
    db.commit()
    db.refresh(req)
    return {"request_id": req.id, "status": req.status}


@app.get("/friends/requests")
def list_friend_requests(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    incoming = db.query(FriendRequest).filter(
        FriendRequest.receiver == user.username, FriendRequest.status == "pending"
    ).order_by(FriendRequest.created_at.desc()).offset(offset).limit(limit).all()
    outgoing = db.query(FriendRequest).filter(
        FriendRequest.sender == user.username, FriendRequest.status == "pending"
    ).order_by(FriendRequest.created_at.desc()).offset(offset).limit(limit).all()
    return {
        "incoming": [{"id": r.id, "sender": r.sender, "created_at": r.created_at} for r in incoming],
        "outgoing": [{"id": r.id, "receiver": r.receiver, "created_at": r.created_at} for r in outgoing],
        "page": {"limit": limit, "offset": offset},
    }


@app.post("/friends/respond")
def respond_friend_request(payload: FriendRequestAction, user: User = Depends(current_user), db: Session = Depends(get_db)):
    req = db.query(FriendRequest).filter(FriendRequest.id == payload.request_id).first()
    if not req or req.receiver != user.username or req.status != "pending":
        raise HTTPException(status_code=404, detail="Pending request not found")
    if payload.action not in {"accept", "decline"}:
        raise HTTPException(status_code=400, detail="Invalid action")
    req.status = "accepted" if payload.action == "accept" else "declined"
    if payload.action == "accept":
        a, b = sorted([req.sender, req.receiver])
        db.add(Friendship(user_a=a, user_b=b))
    db.commit()
    return {"request_id": req.id, "status": req.status}


@app.post("/friends/cancel")
def cancel_friend_request(payload: FriendCancelRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    req = (
        db.query(FriendRequest)
        .filter(FriendRequest.id == payload.request_id)
        .first()
    )
    if not req or req.sender != user.username or req.status != "pending":
        raise HTTPException(status_code=404, detail="Pending request not found or not owned by you")
    req.status = "cancelled"
    db.commit()
    return {"request_id": req.id, "status": req.status}


@app.post("/friends/block/{username}")
def block_user(username: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    blocked = [x for x in user.blocked.split(",") if x]
    if username not in blocked:
        blocked.append(username)
    user.blocked = ",".join(blocked)
    db.commit()
    return {"blocked": blocked}


@app.delete("/friends/{username}")
def remove_friend(username: str, user: User = Depends(current_user), db: Session = Depends(get_db)):
    a, b = sorted([user.username, username])
    friendship = db.query(Friendship).filter(Friendship.user_a == a, Friendship.user_b == b).first()
    if friendship:
        db.delete(friendship)
    db.commit()
    return {"removed": username}


@app.post("/messages/send")
def send_message(payload: MessageSendRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    validate_username(payload.receiver)
    nonce = strict_b64decode(payload.nonce, "nonce")
    ad_raw = strict_b64decode(payload.ad, "ad")
    ct = strict_b64decode(payload.ciphertext, "ciphertext")
    if len(nonce) != 12:
        raise HTTPException(status_code=400, detail="Nonce must be 12 bytes for AES-GCM")
    if len(ct) < 16:
        raise HTTPException(status_code=400, detail="Ciphertext too short")
    if len(ad_raw) > 2048:
        raise HTTPException(status_code=400, detail="AD too large")
    try:
        ad_obj = json.loads(ad_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid AD payload") from exc
    required = {"sender", "receiver", "convo_id", "msg_counter", "ttl_seconds", "sent_at"}
    if not required.issubset(set(ad_obj.keys())):
        raise HTTPException(status_code=400, detail="Missing required AD fields")
    if ad_obj.get("sender") != user.username or ad_obj.get("receiver") != payload.receiver:
        raise HTTPException(status_code=400, detail="AD sender/receiver mismatch")
    if ad_obj.get("convo_id") != payload.convo_id:
        raise HTTPException(status_code=400, detail="AD convo_id mismatch")
    if int(ad_obj.get("msg_counter", -1)) != payload.msg_counter:
        raise HTTPException(status_code=400, detail="AD msg_counter mismatch")
    if int(ad_obj.get("ttl_seconds", -1)) != payload.ttl_seconds:
        raise HTTPException(status_code=400, detail="AD ttl mismatch")

    # Remove stale ciphertext before enqueueing new messages.
    cleanup_expired_messages(db)
    receiver = db.query(User).filter(User.username == payload.receiver).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")
    if not is_friends(db, user.username, payload.receiver):
        raise HTTPException(status_code=403, detail="Only friends can chat")
    if in_block_list(receiver, user.username):
        raise HTTPException(status_code=403, detail="Blocked by receiver")

    expires = utc_now() + timedelta(seconds=payload.ttl_seconds)
    message = Message(
        convo_id=payload.convo_id,
        sender=user.username,
        receiver=payload.receiver,
        ciphertext=payload.ciphertext,
        nonce=payload.nonce,
        ad=payload.ad,
        msg_counter=payload.msg_counter,
        ttl_seconds=payload.ttl_seconds,
        expires_at=expires,
        delivered=False,
        kind="chat",
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    return {"message_id": message.id, "status": "sent"}


@app.post("/messages/ack-e2ee")
def send_e2ee_ack(payload: AckE2EERequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    validate_username(payload.receiver)
    nonce = strict_b64decode(payload.nonce, "nonce")
    ad_raw = strict_b64decode(payload.ad, "ad")
    ct = strict_b64decode(payload.ciphertext, "ciphertext")
    if len(nonce) != 12:
        raise HTTPException(status_code=400, detail="Nonce must be 12 bytes for AES-GCM")
    if len(ct) < 16:
        raise HTTPException(status_code=400, detail="Ciphertext too short")
    if len(ad_raw) > 2048:
        raise HTTPException(status_code=400, detail="AD too large")
    try:
        ad_obj = json.loads(ad_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail="Invalid AD payload") from exc

    required = {"type", "sender", "receiver", "convo_id", "msg_counter", "ttl_seconds", "sent_at", "orig_message_id"}
    if not required.issubset(set(ad_obj.keys())):
        raise HTTPException(status_code=400, detail="Missing required AD fields")
    if ad_obj.get("type") != "ack":
        raise HTTPException(status_code=400, detail="AD type must be ack")
    if ad_obj.get("sender") != user.username or ad_obj.get("receiver") != payload.receiver:
        raise HTTPException(status_code=400, detail="AD sender/receiver mismatch")
    if ad_obj.get("convo_id") != payload.convo_id:
        raise HTTPException(status_code=400, detail="AD convo_id mismatch")
    if int(ad_obj.get("msg_counter", -1)) != payload.msg_counter:
        raise HTTPException(status_code=400, detail="AD msg_counter mismatch")
    if int(ad_obj.get("ttl_seconds", -1)) != payload.ttl_seconds:
        raise HTTPException(status_code=400, detail="AD ttl mismatch")

    receiver = db.query(User).filter(User.username == payload.receiver).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")
    if not is_friends(db, user.username, payload.receiver):
        raise HTTPException(status_code=403, detail="Only friends can exchange ACKs")
    if in_block_list(receiver, user.username):
        raise HTTPException(status_code=403, detail="Blocked by receiver")

    # ACK itself is also ciphertext and expires like normal messages.
    expires = utc_now() + timedelta(seconds=payload.ttl_seconds)
    ack_msg = Message(
        convo_id=payload.convo_id,
        sender=user.username,
        receiver=payload.receiver,
        ciphertext=payload.ciphertext,
        nonce=payload.nonce,
        ad=payload.ad,
        msg_counter=payload.msg_counter,
        ttl_seconds=payload.ttl_seconds,
        expires_at=expires,
        delivered=False,
        kind="ack",
    )
    db.add(ack_msg)
    # Align unread counters with delivered semantics by updating source chat.
    # If the sender forged orig_message_id, filters below prevent cross-chat updates.
    try:
        orig_id = int(ad_obj.get("orig_message_id", -1))
    except (TypeError, ValueError):
        orig_id = -1
    if orig_id > 0:
        orig = (
            db.query(Message)
            .filter(
                Message.id == orig_id,
                Message.sender == payload.receiver,  # original sender
                Message.receiver == user.username,   # original receiver (now ACK sender)
                Message.kind == "chat",
            )
            .first()
        )
        if orig:
            orig.acknowledged = True
    db.commit()
    db.refresh(ack_msg)
    return {"message_id": ack_msg.id, "status": "sent"}


@app.get("/messages/pull")
def pull_messages(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    cleanup_expired_messages(db)
    now = utc_now()
    items = db.query(Message).filter(
        Message.receiver == user.username,
        Message.expires_at > now,
    ).order_by(Message.sent_at.asc()).offset(offset).limit(limit).all()
    out = []
    for msg in items:
        msg.delivered = True
        msg.delivered_at = now
        out.append(
            {
                "id": msg.id,
                "convo_id": msg.convo_id,
                "sender": msg.sender,
                "ciphertext": msg.ciphertext,
                "nonce": msg.nonce,
                "ad": msg.ad,
                "msg_counter": msg.msg_counter,
                "ttl_seconds": msg.ttl_seconds,
                "expires_at": msg.expires_at,
                "sent_at": msg.sent_at,
                "kind": msg.kind,
            }
        )
    db.commit()
    return {"messages": out, "page": {"limit": limit, "offset": offset}}


@app.post("/messages/ack")
def ack_message(payload: AckRequest, user: User = Depends(current_user), db: Session = Depends(get_db)):
    msg = db.query(Message).filter(Message.id == payload.message_id).first()
    if not msg or msg.receiver != user.username:
        raise HTTPException(status_code=404, detail="Message not found")
    msg.acknowledged = True
    db.commit()
    return {"message_id": msg.id, "acknowledged": True}


@app.get("/conversations")
def list_conversations(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
    limit: int = Query(default=20, ge=1, le=100),
    offset: int = Query(default=0, ge=0),
):
    cleanup_expired_messages(db)
    msgs = db.query(Message).filter(
        (Message.sender == user.username) | (Message.receiver == user.username)
    ).order_by(Message.sent_at.desc()).all()

    convos = {}
    for m in msgs:
        peer = m.receiver if m.sender == user.username else m.sender
        state = convos.setdefault(peer, {"last_time": m.sent_at, "unread": 0})
        if m.sent_at > state["last_time"]:
            state["last_time"] = m.sent_at
        if m.kind == "chat" and m.receiver == user.username and not m.acknowledged:
            state["unread"] += 1
    convos_list = [{"peer": p, **v} for p, v in convos.items()]
    paged = convos_list[offset : offset + limit]
    return {"conversations": paged, "page": {"limit": limit, "offset": offset, "total": len(convos_list)}}


@app.post("/replay/check/{peer}")
def replay_check(peer: str, counter: int, user: User = Depends(current_user), db: Session = Depends(get_db)):
    validate_username(peer)
    if counter < 0 or counter > 1_000_000_000:
        raise HTTPException(status_code=400, detail="Invalid counter")
    row = db.query(SeenCounter).filter(SeenCounter.username == user.username, SeenCounter.peer == peer).first()
    if not row:
        row = SeenCounter(username=user.username, peer=peer, max_counter=counter)
        db.add(row)
        db.commit()
        return {"accept": True}
    if counter <= row.max_counter:
        return {"accept": False}
    row.max_counter = counter
    db.commit()
    return {"accept": True}

