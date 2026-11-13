from __future__ import annotations

from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from phishing_app.extensions import db


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(254), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(20), nullable=False, default="user", index=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    email_verified = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, onupdate=utcnow)
    last_login_at = db.Column(db.DateTime(timezone=True))

    scans = db.relationship("Scan", back_populates="user", lazy="dynamic")

    def set_password(self, password: str) -> None:
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"


class Scan(db.Model):
    __tablename__ = "scans"
    __table_args__ = (
        db.Index("ix_scans_user_created", "user_id", "created_at"),
        db.Index("ix_scans_prediction_created", "prediction", "created_at"),
    )
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    submitted_url = db.Column(db.Text, nullable=False)
    normalized_url = db.Column(db.Text, nullable=False)
    prediction = db.Column(db.String(20), nullable=False, default="UNVERIFIED", index=True)
    ml_prediction = db.Column(db.String(20), nullable=False, default="UNVERIFIED")
    ml_probability = db.Column(db.Float)
    risk_score = db.Column(db.Float)
    scan_status = db.Column(db.String(20), nullable=False, default="completed", index=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    completed_at = db.Column(db.DateTime(timezone=True))
    result_data = db.Column(db.JSON, nullable=False, default=dict)

    user = db.relationship("User", back_populates="scans")
    findings = db.relationship("ScanFinding", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
    domain_intelligence = db.relationship("DomainIntelligence", back_populates="scan", uselist=False, cascade="all, delete-orphan")
    threat_intelligence = db.relationship("ThreatIntelligence", back_populates="scan", cascade="all, delete-orphan", lazy="selectin")
    reports = db.relationship("Report", back_populates="scan", cascade="all, delete-orphan")


class ScanFinding(db.Model):
    __tablename__ = "scan_findings"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    finding_type = db.Column(db.String(40), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    source = db.Column(db.String(80), nullable=False)
    metadata_json = db.Column(db.JSON, nullable=False, default=dict)
    scan = db.relationship("Scan", back_populates="findings")


class DomainIntelligence(db.Model):
    __tablename__ = "domain_intelligence"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True, index=True)
    domain = db.Column(db.String(253), nullable=False, index=True)
    registration_date = db.Column(db.DateTime(timezone=True))
    expiration_date = db.Column(db.DateTime(timezone=True))
    domain_age_days = db.Column(db.Integer)
    registrar = db.Column(db.String(255))
    lookup_status = db.Column(db.String(30), nullable=False)
    scan = db.relationship("Scan", back_populates="domain_intelligence")


class ThreatIntelligence(db.Model):
    __tablename__ = "threat_intelligence"
    __table_args__ = (db.Index("ix_threat_scan_provider", "scan_id", "provider"),)
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    provider = db.Column(db.String(80), nullable=False)
    match_status = db.Column(db.String(30), nullable=False)
    checked_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    evidence = db.Column(db.JSON, nullable=False, default=dict)
    scan = db.relationship("Scan", back_populates="threat_intelligence")


class Report(db.Model):
    __tablename__ = "reports"
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    report_type = db.Column(db.String(30), nullable=False, default="pdf")
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow)
    scan = db.relationship("Scan", back_populates="reports")


class AuditLog(db.Model):
    __tablename__ = "audit_logs"
    __table_args__ = (db.Index("ix_audit_action_time", "action", "timestamp"),)
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), index=True)
    action = db.Column(db.String(100), nullable=False)
    timestamp = db.Column(db.DateTime(timezone=True), nullable=False, default=utcnow, index=True)
    metadata_json = db.Column(db.JSON, nullable=False, default=dict)
