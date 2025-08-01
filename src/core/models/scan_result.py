"""Data models for scan results"""
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any
from enum import Enum


class IssueType(Enum):
    IDLE_GPU = "IDLE_GPU"
    UNDERUTILIZED_GPU = "UNDERUTILIZED_GPU"
    OVERSIZED_INSTANCE = "OVERSIZED_INSTANCE"


@dataclass
class Opportunity:
    """Represents a single optimization opportunity"""
    instance_id: str
    instance_type: str
    issue: IssueType
    current_cost: float
    potential_savings: float
    recommendation: str
    utilization: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Complete scan result for a customer account"""
    scan_id: str
    account_id: str
    scan_timestamp: datetime
    total_instances_scanned: int
    total_monthly_gpu_spend: float
    total_monthly_waste: float
    idle_gpu_count: int
    underutilized_count: int
    opportunities: List[Opportunity]
    
    @property
    def waste_percentage(self) -> float:
        """Calculate waste as percentage of total spend"""
        if self.total_monthly_gpu_spend == 0:
            return 0
        return (self.total_monthly_waste / self.total_monthly_gpu_spend) * 100
    
    @property
    def annual_savings(self) -> float:
        """Calculate potential annual savings"""
        return self.total_monthly_waste * 12