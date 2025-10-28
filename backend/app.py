import os
from datetime import timedelta, datetime
from flask import Flask, request, jsonify, redirect, send_from_directory
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, verify_jwt_in_request, get_jwt
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy import create_engine, Column, Integer, String, DateTime, ForeignKey, Text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker, scoped_session

DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///dispatch.db")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-me")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {})
SessionLocal = scoped_session(sessionmaker(bind=engine, autocommit=False, autoflush=False))
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(120), unique=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False)  # patient, driver, dispatcher
    full_name = Column(String(120))
    phone = Column(String(40))
    created_at = Column(DateTime, default=datetime.utcnow)

class Ambulance(Base):
    __tablename__ = "ambulances"
    id = Column(Integer, primary_key=True)
    number = Column(String(50), unique=True)
    driver_user_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String(20), default="available")  # available, busy, offline

class Request(Base):
    __tablename__ = "requests"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    pickup = Column(Text, nullable=False)
    destination = Column(Text, nullable=False)
    emergency_type = Column(String(64), nullable=False)
    status = Column(String(32), default="pending")  # pending, accepted, enroute, arrived, transporting, completed, cancelled
    assigned_ambulance_id = Column(Integer, ForeignKey("ambulances.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {
            "id": self.id,
            "pickup": self.pickup,
            "destination": self.destination,
            "emergencyType": self.emergency_type,
            "status": self.status,
            "assignedAmbulanceId": self.assigned_ambulance_id,
            "createdAt": self.created_at.isoformat(),
        }

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = JWT_SECRET
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=12)
CORS(app, resources={r"/api/*": {"origins": "*"}})
jwt = JWTManager(app)

# --- DB init ---
Base.metadata.create_all(bind=engine)

# Seed a couple of ambulances if none exist
with SessionLocal() as db:
    if db.query(Ambulance).count() == 0:
        for num in ("AMB-247", "AMB-182", "AMB-391"):
            db.add(Ambulance(number=num, status="available"))
        db.commit()

# --- Helpers ---

def get_db():
    return SessionLocal()

# --- JWT Error Handlers ---

@jwt.unauthorized_loader
def handle_missing_token(err_msg):
    return jsonify({"error": "Missing Authorization token", "detail": err_msg}), 401

@jwt.invalid_token_loader
def handle_invalid_token(err_msg):
    return jsonify({"error": "Invalid token", "detail": err_msg}), 401

@jwt.expired_token_loader
def handle_expired_token(jwt_header, jwt_payload):
    return jsonify({"error": "Token expired"}), 401

# --- Auth Routes ---
@app.post("/api/auth/register")
def register():
    data = request.get_json(force=True)
    email = data.get("email")
    password = data.get("password")
    role = data.get("role")
    full_name = data.get("fullName")
    phone = data.get("phone")
    if not email or not password or role not in ("patient", "driver", "dispatcher"):
        return jsonify({"error": "Invalid payload"}), 400
    db = get_db()
    try:
        if db.query(User).filter_by(email=email).first():
            return jsonify({"error": "Email already registered"}), 409
        user = User(email=email, password_hash=generate_password_hash(password), role=role, full_name=full_name, phone=phone)
        db.add(user)
        db.commit()
        return jsonify({"message": "Registered", "role": role}), 201
    finally:
        db.close()

@app.get("/api/driver/assigned")
@jwt_required()
def driver_assigned_requests():
    claims = get_jwt()
    if (claims or {}).get("role") != "driver":
        return jsonify({"error": "Forbidden"}), 403
    ident = get_jwt_identity()
    driver_id = int(ident) if ident and str(ident).isdigit() else None
    db = get_db()
    try:
        amb = db.query(Ambulance).filter_by(driver_user_id=driver_id).first()
        if not amb:
            return jsonify({"requests": []})
        q = db.query(Request).filter(
            Request.assigned_ambulance_id == amb.id,
            Request.status.in_(["accepted", "enroute", "arrived", "transporting"])
        ).order_by(Request.created_at.asc())
        return jsonify({"requests": [r.to_dict() for r in q.all()]})
    finally:
        db.close()

@app.get("/api/ambulances")
@jwt_required(optional=True)
def list_ambulances():
    db = get_db()
    try:
        items = db.query(Ambulance).all()
        return jsonify({
            "ambulances": [
                {
                    "id": a.id,
                    "number": a.number,
                    "status": a.status,
                    "driverUserId": a.driver_user_id,
                }
                for a in items
            ]
        })
    finally:
        db.close()

@app.get("/api/driver/my/trips")
@jwt_required()
def driver_my_trips():
    claims = get_jwt()
    if (claims or {}).get("role") != "driver":
        return jsonify({"error": "Forbidden"}), 403
    ident = get_jwt_identity()
    driver_id = int(ident) if ident and str(ident).isdigit() else None
    db = get_db()
    try:
        amb = db.query(Ambulance).filter_by(driver_user_id=driver_id).first()
        if not amb:
            return jsonify({"requests": []})
        q = db.query(Request).filter(Request.assigned_ambulance_id == amb.id).order_by(Request.created_at.desc())
        return jsonify({"requests": [r.to_dict() for r in q.all()]})
    finally:
        db.close()

@app.post("/api/auth/login")
def login():
    data = request.get_json(force=True)
    email = data.get("email")
    password = data.get("password")
    db = get_db()
    try:
        user = db.query(User).filter_by(email=email).first()
        if not user or not check_password_hash(user.password_hash, password):
            return jsonify({"error": "Invalid credentials"}), 401
        # Identity must be a string for compatibility; put role/email in additional claims
        token = create_access_token(identity=str(user.id), additional_claims={"role": user.role, "email": user.email})
        return jsonify({"accessToken": token, "role": user.role, "fullName": user.full_name or user.email}), 200
    finally:
        db.close()

@app.get("/api/auth/me")
@jwt_required()
def me():
    ident = get_jwt_identity()  # string user id
    claims = get_jwt() or {}
    return jsonify({
        "id": int(ident) if ident and ident.isdigit() else ident,
        "role": claims.get("role"),
        "email": claims.get("email")
    })

# --- Request Lifecycle ---
@app.post("/api/requests")
def create_request():
    data = request.get_json(force=True)
    pickup = data.get("pickup")
    destination = data.get("destination")
    emergency_type = data.get("emergencyType")
    if not pickup or not destination or not emergency_type:
        return jsonify({"error": "Missing fields"}), 400
    # Try to resolve user identity if a valid JWT is provided; otherwise proceed unauthenticated
    user_id = None
    try:
        verify_jwt_in_request()
        ident = get_jwt_identity()  # string id
        if ident and str(ident).isdigit():
            user_id = int(ident)
    except Exception:
        # Ignore invalid/malformed/absent tokens to allow anonymous request creation
        pass
    db = get_db()
    try:
        req = Request(user_id=user_id, pickup=pickup, destination=destination, emergency_type=emergency_type, status="pending")
        db.add(req)
        db.commit()
        return jsonify({"request": req.to_dict()}), 201
    finally:
        db.close()

@app.get("/api/requests")
@jwt_required(optional=True)
def list_requests():
    # dispatcher view: list all pending/active
    status = request.args.get("status")
    db = get_db()
    try:
        q = db.query(Request)
        if status:
            q = q.filter(Request.status == status)
        q = q.order_by(Request.created_at.desc())
        return jsonify({"requests": [r.to_dict() for r in q.all()]})
    finally:
        db.close()

@app.get("/api/my/requests")
@jwt_required()
def my_requests():
    ident = get_jwt_identity()
    user_id = int(ident) if ident and str(ident).isdigit() else None
    if not user_id:
        return jsonify({"requests": []})
    db = get_db()
    try:
        q = db.query(Request).filter(Request.user_id == user_id).order_by(Request.created_at.desc())
        return jsonify({"requests": [r.to_dict() for r in q.all()]})
    finally:
        db.close()

@app.get("/api/requests/<int:req_id>")
@jwt_required(optional=True)
def get_request(req_id):
    db = get_db()
    try:
        r = db.query(Request).get(req_id)
        if not r:
            return jsonify({"error": "Not found"}), 404
        return jsonify({"request": r.to_dict()})
    finally:
        db.close()

@app.post("/api/requests/<int:req_id>/assign")
@jwt_required()
def assign_request(req_id):
    claims = get_jwt()
    if (claims or {}).get("role") != "dispatcher":
        return jsonify({"error": "Forbidden"}), 403
    data = request.get_json(force=True)
    ambulance_number = data.get("ambulanceNumber")
    db = get_db()
    try:
        r = db.query(Request).get(req_id)
        if not r:
            return jsonify({"error": "Not found"}), 404
        amb = db.query(Ambulance).filter_by(number=ambulance_number).first()
        if not amb:
            return jsonify({"error": "Ambulance not found"}), 404
        r.assigned_ambulance_id = amb.id
        r.status = "accepted"
        r.updated_at = datetime.utcnow()
        amb.status = "busy"
        db.commit()
        return jsonify({"request": r.to_dict()}), 200
    finally:
        db.close()

@app.post("/api/requests/<int:req_id>/status")
@jwt_required()
def update_request_status(req_id):
    claims = get_jwt()
    role = (claims or {}).get("role")
    if role not in ("driver", "dispatcher"):
        return jsonify({"error": "Forbidden"}), 403
    data = request.get_json(force=True)
    new_status = data.get("status")
    if new_status not in ("pending", "accepted", "enroute", "arrived", "transporting", "completed", "cancelled"):
        return jsonify({"error": "Invalid status"}), 400
    db = get_db()
    try:
        r = db.query(Request).get(req_id)
        if not r:
            return jsonify({"error": "Not found"}), 404
        r.status = new_status
        r.updated_at = datetime.utcnow()
        if new_status == "completed" and r.assigned_ambulance_id:
            amb = db.query(Ambulance).get(r.assigned_ambulance_id)
            if amb:
                amb.status = "available"
        db.commit()
        return jsonify({"request": r.to_dict()}), 200
    finally:
        db.close()

# --- Driver Endpoints ---
@app.get("/api/driver/queue")
@jwt_required()
def driver_queue():
    claims = get_jwt()
    if (claims or {}).get("role") != "driver":
        return jsonify({"error": "Forbidden"}), 403
    db = get_db()
    try:
        q = db.query(Request).filter(Request.status == "pending").order_by(Request.created_at.asc()).limit(10)
        return jsonify({"requests": [r.to_dict() for r in q.all()]})
    finally:
        db.close()

@app.post("/api/driver/availability")
@jwt_required()
def driver_availability():
    claims = get_jwt()
    if (claims or {}).get("role") != "driver":
        return jsonify({"error": "Forbidden"}), 403
    data = request.get_json(force=True)
    status = data.get("status", "available")
    db = get_db()
    try:
        ident = get_jwt_identity()
        driver_id = int(ident) if ident and str(ident).isdigit() else None
        amb = db.query(Ambulance).filter_by(driver_user_id=driver_id).first()
        if not amb:
            # auto-bind a vehicle for demo
            amb = db.query(Ambulance).filter_by(driver_user_id=None).first()
            if amb:
                amb.driver_user_id = driver_id
        if amb:
            amb.status = status
            db.commit()
        return jsonify({"message": "updated", "ambulance": amb.number if amb else None, "status": status})
    finally:
        db.close()

FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'modules'))

@app.get('/frontend/<path:filename>')
def frontend(filename):
    return send_from_directory(FRONTEND_DIR, filename)

@app.get("/")
def root():
    return redirect("/frontend/index.html", code=302)

if __name__ == "__main__":
    port = int(os.getenv("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
