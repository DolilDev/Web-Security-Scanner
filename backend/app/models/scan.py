from __future__ import annotations

from datetime import datetime
from sqlalchemy import String, Column, DateTime, Enum
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class Scan(Base):
    __tablename__ = "scans"

    id = Column(String, primary_key=True)
    target = Column(String, nullable=False)
    status = Column(String, nullable=False, default="pending")
    started_at = Column(DateTime, default=datetime.utcnow)
    finished_at = Column(DateTime, nullable=True)

    test_runs = relationship("TestRun", back_populates="scan")
