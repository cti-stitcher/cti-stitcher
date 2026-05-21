"""
SQLAlchemy ORM models for cti-stitcher.
All tables use integer primary keys internally; ATT&CK IDs are stored
as plain string columns so we can handle actors that don't have one yet.
"""

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


# ---------------------------------------------------------------------------
# Actors
# ---------------------------------------------------------------------------

class Actor(Base):
    """
    A threat actor / intrusion set.
    attack_group_id is the canonical MITRE ATT&CK group ID (e.g. G0016).
    Nullable for actors known in Malpedia/MISP but not yet in ATT&CK.
    """
    __tablename__ = "actors"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attack_group_id: Mapped[Optional[str]] = mapped_column(String(16), unique=True, nullable=True, index=True)
    stix_id: Mapped[Optional[str]] = mapped_column(String(64), unique=True, nullable=True)
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    country_code: Mapped[Optional[str]] = mapped_column(String(4), nullable=True)  # ISO 3166-1 alpha-2
    first_seen: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    last_seen: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)
    in_attack: Mapped[bool] = mapped_column(Boolean, default=False)  # False = no ATT&CK entry yet

    aliases: Mapped[list["Alias"]] = relationship("Alias", back_populates="actor", cascade="all, delete-orphan")
    techniques: Mapped[list["ActorTechnique"]] = relationship("ActorTechnique", back_populates="actor", cascade="all, delete-orphan")
    software: Mapped[list["ActorSoftware"]] = relationship("ActorSoftware", back_populates="actor", cascade="all, delete-orphan")
    targeting: Mapped[list["Targeting"]] = relationship("Targeting", back_populates="actor", cascade="all, delete-orphan")


# ---------------------------------------------------------------------------
# Aliases  (the Rosetta Stone table)
# ---------------------------------------------------------------------------

class Alias(Base):
    """
    Every name any source uses for an actor.
    alias_normalized is lowercased + stripped for fast lookups.
    """
    __tablename__ = "aliases"
    __table_args__ = (
        UniqueConstraint("actor_id", "alias_normalized", "source", name="uq_alias_source"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int] = mapped_column(Integer, ForeignKey("actors.id"), nullable=False, index=True)
    alias: Mapped[str] = mapped_column(String(256), nullable=False)
    alias_normalized: Mapped[str] = mapped_column(String(256), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)   # attack / misp_galaxy / malpedia / mandiant
    confidence: Mapped[str] = mapped_column(String(16), default="high")  # high / medium / low

    actor: Mapped["Actor"] = relationship("Actor", back_populates="aliases")


# ---------------------------------------------------------------------------
# Techniques
# ---------------------------------------------------------------------------

class Technique(Base):
    __tablename__ = "techniques"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attack_id: Mapped[str] = mapped_column(String(16), unique=True, nullable=False, index=True)  # T1566, T1566.001
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    tactic: Mapped[Optional[str]] = mapped_column(String(256), nullable=True)  # comma-separated if multiple
    is_subtechnique: Mapped[bool] = mapped_column(Boolean, default=False)
    parent_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("techniques.id"), nullable=True)

    actors: Mapped[list["ActorTechnique"]] = relationship("ActorTechnique", back_populates="technique", cascade="all, delete-orphan")


class ActorTechnique(Base):
    __tablename__ = "actor_techniques"
    __table_args__ = (
        UniqueConstraint("actor_id", "technique_id", "source", name="uq_actor_technique_source"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int] = mapped_column(Integer, ForeignKey("actors.id"), nullable=False, index=True)
    technique_id: Mapped[int] = mapped_column(Integer, ForeignKey("techniques.id"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), default="high")

    actor: Mapped["Actor"] = relationship("Actor", back_populates="techniques")
    technique: Mapped["Technique"] = relationship("Technique", back_populates="actors")


# ---------------------------------------------------------------------------
# Software / Malware / Tools
# ---------------------------------------------------------------------------

class Software(Base):
    __tablename__ = "software"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    attack_id: Mapped[Optional[str]] = mapped_column(String(16), unique=True, nullable=True, index=True)  # S0154
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    software_type: Mapped[str] = mapped_column(String(16), default="tool")  # tool / malware
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    actors: Mapped[list["ActorSoftware"]] = relationship("ActorSoftware", back_populates="software", cascade="all, delete-orphan")


class ActorSoftware(Base):
    __tablename__ = "actor_software"
    __table_args__ = (
        UniqueConstraint("actor_id", "software_id", "source", name="uq_actor_software_source"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int] = mapped_column(Integer, ForeignKey("actors.id"), nullable=False, index=True)
    software_id: Mapped[int] = mapped_column(Integer, ForeignKey("software.id"), nullable=False, index=True)
    source: Mapped[str] = mapped_column(String(64), nullable=False)

    actor: Mapped["Actor"] = relationship("Actor", back_populates="software")
    software: Mapped["Software"] = relationship("Software", back_populates="actors")


# ---------------------------------------------------------------------------
# Targeting  (industries and regions an actor is known to target)
# ---------------------------------------------------------------------------

class Targeting(Base):
    __tablename__ = "targeting"
    __table_args__ = (
        UniqueConstraint("actor_id", "target_type", "value", "source", name="uq_targeting"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor_id: Mapped[int] = mapped_column(Integer, ForeignKey("actors.id"), nullable=False, index=True)
    target_type: Mapped[str] = mapped_column(String(16), nullable=False)  # industry / region / country
    value: Mapped[str] = mapped_column(String(256), nullable=False)
    source: Mapped[str] = mapped_column(String(64), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), default="high")

    actor: Mapped["Actor"] = relationship("Actor", back_populates="targeting")


# ---------------------------------------------------------------------------
# Sync log
# ---------------------------------------------------------------------------

class SyncLog(Base):
    __tablename__ = "sync_log"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    connector: Mapped[str] = mapped_column(String(64), nullable=False)
    run_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    status: Mapped[str] = mapped_column(String(16), nullable=False)   # success / partial / failed
    records_updated: Mapped[int] = mapped_column(Integer, default=0)
    message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
