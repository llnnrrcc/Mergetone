"""
SQLAlchemy ORM models for Mergetone.

Tables
------
User          — one row per authenticated Spotify account
Session       — a shared listening room (N users)
SessionUser   — join table: which users are in which session
Token         — Spotify OAuth tokens (encrypted at rest)
Track         — a Spotify track, enriched with Apple Music preview URL
AudioFeatures — librosa-derived feature vector per track
Swipe         — one approve/reject decision per (user, session, track)
"""

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _uuid() -> str:
    return str(uuid.uuid4())


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class SessionStatus(str, enum.Enum):
    waiting = "waiting"   # not all users have joined yet
    active = "active"     # swiping in progress
    done = "done"         # session closed


class SwipeDecision(str, enum.Enum):
    approve = "approve"
    reject = "reject"


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    spotify_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    display_name: Mapped[str | None] = mapped_column(String(255))
    email: Mapped[str | None] = mapped_column(String(255))

    # Taste profile — stored as JSON arrays.
    # taste_profile_mean: list[float] — feature centroid vector
    # taste_profile_cov:  list[list[float]] — covariance matrix (flattened or nested)
    # Both are None until the user has enough listening history to compute.
    taste_profile_mean: Mapped[list | None] = mapped_column(JSON)
    taste_profile_cov: Mapped[list | None] = mapped_column(JSON)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    token: Mapped["Token | None"] = relationship(
        "Token", back_populates="user", uselist=False, cascade="all, delete-orphan"
    )
    session_links: Mapped[list["SessionUser"]] = relationship(
        "SessionUser", back_populates="user", cascade="all, delete-orphan"
    )
    swipes: Mapped[list["Swipe"]] = relationship(
        "Swipe", back_populates="user", cascade="all, delete-orphan"
    )


class Session(Base):
    __tablename__ = "sessions"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    # Human-readable join code (e.g. "TIGER-42") shown to users
    join_code: Mapped[str] = mapped_column(String(16), unique=True, nullable=False)
    status: Mapped[SessionStatus] = mapped_column(
        Enum(SessionStatus), default=SessionStatus.waiting, nullable=False
    )
    # Spotify playlist created for this session (null until first track approved)
    spotify_playlist_id: Mapped[str | None] = mapped_column(String(64))

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    user_links: Mapped[list["SessionUser"]] = relationship(
        "SessionUser", back_populates="session", cascade="all, delete-orphan"
    )
    swipes: Mapped[list["Swipe"]] = relationship(
        "Swipe", back_populates="session", cascade="all, delete-orphan"
    )


class SessionUser(Base):
    """Join table — which users belong to which session."""

    __tablename__ = "session_users"
    __table_args__ = (UniqueConstraint("session_id", "user_id"),)

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    session_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    joined_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    session: Mapped["Session"] = relationship("Session", back_populates="user_links")
    user: Mapped["User"] = relationship("User", back_populates="session_links")


class Token(Base):
    """
    Spotify OAuth tokens for a user.

    access_token and refresh_token are stored encrypted.
    Encryption/decryption is handled at the service layer using Fernet
    (cryptography library) with a key derived from settings.secret_key.
    The values stored here are base64-encoded ciphertext.
    """

    __tablename__ = "tokens"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("users.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )

    # Encrypted ciphertext — do not read these directly; use the token service
    access_token: Mapped[str] = mapped_column(Text, nullable=False)
    refresh_token: Mapped[str] = mapped_column(Text, nullable=False)

    # Scopes granted by the user (space-separated, as Spotify returns them)
    scope: Mapped[str | None] = mapped_column(Text)

    # When the access token expires (UTC). Used to trigger proactive refresh.
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="token")


class Track(Base):
    """
    A Spotify track, enriched with Apple Music preview data.

    spotify_id  — Spotify track ID (22-char base-62 string)
    isrc        — International Standard Recording Code, from Spotify's
                  external_ids.isrc field. Used to look up Apple Music previews.
    preview_url — 30-second AAC preview from Apple Music (null if unavailable)
    metadata    — raw Spotify track object fields we want to keep
                  (name, artists, album, duration_ms, etc.) stored as JSON
                  so we don't have to re-fetch from Spotify constantly.
    """

    __tablename__ = "tracks"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    spotify_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    isrc: Mapped[str | None] = mapped_column(String(32), index=True)
    preview_url: Mapped[str | None] = mapped_column(Text)
    # Cached Spotify metadata: {name, artists, album, duration_ms, ...}
    metadata: Mapped[dict | None] = mapped_column(JSON)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    audio_features: Mapped["AudioFeatures | None"] = relationship(
        "AudioFeatures", back_populates="track", uselist=False, cascade="all, delete-orphan"
    )
    swipes: Mapped[list["Swipe"]] = relationship(
        "Swipe", back_populates="track"
    )


class AudioFeatures(Base):
    """
    librosa-derived audio feature vector for a track.

    Computed from the Apple Music 30-second preview. Stored once per track
    and reused across all sessions.

    Feature definitions
    -------------------
    tempo               — BPM estimated by librosa beat tracker
    energy_rms          — root-mean-square energy (overall loudness proxy)
    spectral_centroid   — mean spectral centroid in Hz (brightness)
    zero_crossing_rate  — mean ZCR (noisiness / percussiveness proxy)
    mfccs               — list of 13 mean MFCC coefficients
    chroma              — list of 12 mean chroma features (pitch class profile)
    """

    __tablename__ = "audio_features"

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    track_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        ForeignKey("tracks.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
    )

    tempo: Mapped[float | None] = mapped_column(Float)
    energy_rms: Mapped[float | None] = mapped_column(Float)
    spectral_centroid: Mapped[float | None] = mapped_column(Float)
    zero_crossing_rate: Mapped[float | None] = mapped_column(Float)

    # JSON arrays — mfccs is length 13, chroma is length 12
    mfccs: Mapped[list | None] = mapped_column(JSON)
    chroma: Mapped[list | None] = mapped_column(JSON)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    track: Mapped["Track"] = relationship("Track", back_populates="audio_features")


class Swipe(Base):
    """
    One user's decision on one track within one session.

    Each (user_id, session_id, track_id) triple is unique — a user can only
    swipe on a given track once per session.

    After all users in a session have swiped on the same track:
      - If all approved → track is added to the shared Spotify playlist
      - Regardless → user taste profiles are updated (approve pulls centroid
        toward the track's vector, reject pushes away)
    """

    __tablename__ = "swipes"
    __table_args__ = (UniqueConstraint("user_id", "session_id", "track_id"),)

    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), primary_key=True, default=_uuid
    )
    user_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    session_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("sessions.id", ondelete="CASCADE"), nullable=False
    )
    track_id: Mapped[str] = mapped_column(
        UUID(as_uuid=False), ForeignKey("tracks.id", ondelete="CASCADE"), nullable=False
    )
    decision: Mapped[SwipeDecision] = mapped_column(
        Enum(SwipeDecision), nullable=False
    )
    swiped_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="swipes")
    session: Mapped["Session"] = relationship("Session", back_populates="swipes")
    track: Mapped["Track"] = relationship("Track", back_populates="swipes")
