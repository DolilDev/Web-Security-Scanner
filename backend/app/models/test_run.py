from __future__ import annotations

from sqlalchemy import Column, String, ForeignKey, Text
from sqlalchemy.orm import relationship
from .scan import Base


class TestRun(Base):
    __tablename__ = "test_runs"

    id = Column(String, primary_key=True)
    scan_id = Column(String, ForeignKey("scans.id"), nullable=False)
    test_id = Column(String, nullable=False)
    status = Column(String, nullable=False)
    evidence = Column(Text, nullable=True)
    severity = Column(String, nullable=True)

    scan = relationship("Scan", back_populates="test_runs")
