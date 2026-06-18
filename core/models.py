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
    controls: Mapped[list["TechniqueControl"]] = relationship("TechniqueControl", back_populates="technique", cascade="all, delete-orphan")


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
# Controls  (GRC framework crosswalk — NIST 800-53, etc.)
# ---------------------------------------------------------------------------

class Control(Base):
    """
    A control from a GRC framework (e.g. NIST 800-53 rev5).
    `framework` is a plain string for now since v2 only ingests one
    framework (nist_800_53); revisit if/when a second framework is added.
    """
    __tablename__ = "controls"
    __table_args__ = (
        UniqueConstraint("framework", "control_id", name="uq_control_framework_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    framework: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # e.g. "nist_800_53"
    control_id: Mapped[str] = mapped_column(String(16), nullable=False, index=True)  # e.g. "AC-02"
    control_group: Mapped[Optional[str]] = mapped_column(String(8), nullable=True)  # e.g. "AC"
    name: Mapped[str] = mapped_column(String(256), nullable=False)  # control title, e.g. "Account Management"
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)  # not populated by ctid_nist80053; reserved for future enrichment

    techniques: Mapped[list["TechniqueControl"]] = relationship("TechniqueControl", back_populates="control", cascade="all, delete-orphan")


class TechniqueControl(Base):
    """
    Links an ATT&CK technique to a control via a published crosswalk
    (currently CTID's ATT&CK-to-NIST-800-53 mapping).
    """
    __tablename__ = "technique_controls"
    __table_args__ = (
        UniqueConstraint("technique_id", "control_id", "source", name="uq_technique_control_source"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    technique_id: Mapped[int] = mapped_column(Integer, ForeignKey("techniques.id"), nullable=False, index=True)
    control_id: Mapped[int] = mapped_column(Integer, ForeignKey("controls.id"), nullable=False, index=True)
    mapping_type: Mapped[str] = mapped_column(String(32), nullable=False)  # e.g. "mitigates"
    source: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "ctid_nist80053"

    technique: Mapped["Technique"] = relationship("Technique", back_populates="controls")
    control: Mapped["Control"] = relationship("Control", back_populates="techniques")


class ControlPosture(Base):
    """
    Tracks which controls the org has implemented.
    User-managed via the Controls UI — not populated by any connector.
    One row per control; implemented=True means the org has this control deployed.
    """
    __tablename__ = "control_posture"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    control_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("controls.id"), unique=True, nullable=False, index=True
    )
    implemented: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    control: Mapped["Control"] = relationship("Control")


# ---------------------------------------------------------------------------
# D3FEND Countermeasures
# ---------------------------------------------------------------------------

class D3FendTechnique(Base):
    """
    A MITRE D3FEND defensive countermeasure (e.g. D3-PSA: Process Spawn Analysis).
    Tactic is one of: Harden / Detect / Isolate / Deceive / Evict / Restore.
    Populated by the d3fend connector from the D3FEND ontology JSON-LD.
    """
    __tablename__ = "d3fend_techniques"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    d3fend_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False, index=True)  # e.g. "D3-PSA"
    name: Mapped[str] = mapped_column(String(256), nullable=False)
    tactic: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)   # Harden/Detect/Isolate/...
    definition: Mapped[Optional[str]] = mapped_column(Text, nullable=True)


class TechniqueD3Fend(Base):
    """
    Links an ATT&CK technique to a D3FEND countermeasure.
    Derived via artifact-based inference: both technique and countermeasure
    act on the same digital artifact class in the D3FEND ontology.
    """
    __tablename__ = "technique_d3fend"
    __table_args__ = (
        UniqueConstraint("technique_id", "d3fend_technique_id", name="uq_technique_d3fend"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    technique_id: Mapped[int] = mapped_column(Integer, ForeignKey("techniques.id"), nullable=False, index=True)
    d3fend_technique_id: Mapped[int] = mapped_column(Integer, ForeignKey("d3fend_techniques.id"), nullable=False, index=True)


class D3FendPosture(Base):
    """
    Tracks which D3FEND countermeasures the org has deployed.
    User-managed via the D3FEND UI — no connector writes to this table.
    """
    __tablename__ = "d3fend_posture"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    d3fend_technique_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("d3fend_techniques.id"), unique=True, nullable=False, index=True
    )
    implemented: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    d3fend_technique: Mapped["D3FendTechnique"] = relationship("D3FendTechnique")


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
