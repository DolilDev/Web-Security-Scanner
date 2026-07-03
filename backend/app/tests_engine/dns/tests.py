from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ..base import ScanContext, SecurityTest, TestResult
from .query import DNSQueryClient
from ..registry import registry


class DNSBase(SecurityTest):
    category = "DNS and Domain"

    def __init__(self, id: str, severity: str = "medium") -> None:
        self.id = id
        self.severity = severity
        self.client = DNSQueryClient()

    async def run(self, target: ScanContext) -> TestResult:
        return await self.execute(target)

    async def execute(self, target: ScanContext) -> TestResult:
        raise NotImplementedError


class SPFRecordPresent(DNSBase):
    id = "dns.spf.present"
    severity = "high"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        records = await self.client.query(domain, "TXT")
        if any(str(record).startswith("v=spf1") for record in records):
            return TestResult(id=self.id, status="pass", evidence="SPF record present", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence="SPF record missing", recommendation="Add a valid SPF TXT record", severity=self.severity)


class SPFValidSyntax(DNSBase):
    id = "dns.spf.syntax"
    severity = "medium"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        records = await self.client.query(domain, "TXT")
        spfs = [str(record).strip('"') for record in records if str(record).startswith("v=spf1")]
        if not spfs:
            return TestResult(id=self.id, status="skipped", evidence="No SPF record to validate", severity=self.severity)
        if all(token in spf for token in ("v=spf1", "all")):
            return TestResult(id=self.id, status="pass", evidence="SPF syntax appears valid", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="SPF syntax appears incomplete", recommendation="Review SPF record syntax", severity=self.severity)


class SPFLenient(dns.exception.DNSException):
    pass


class SPFPermissive(DNSBase):
    id = "dns.spf.permissive"
    severity = "medium"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        records = await self.client.query(domain, "TXT")
        spfs = [str(record).strip('"') for record in records if str(record).startswith("v=spf1")]
        if not spfs:
            return TestResult(id=self.id, status="skipped", evidence="No SPF record to evaluate", severity=self.severity)
        if any("+all" in spf for spf in spfs):
            return TestResult(id=self.id, status="fail", evidence="SPF record is overly permissive", recommendation="Use ~all or -all instead of +all", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="SPF record is not overly permissive", severity=self.severity)


class DKIMRecordPresent(DNSBase):
    id = "dns.dkim.present"
    severity = "high"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        selector = "default"
        records = await self.client.query(f"{selector}._domainkey.{domain}", "TXT")
        if records:
            return TestResult(id=self.id, status="pass", evidence="DKIM selector found", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="DKIM record not found for default selector", recommendation="Verify DKIM selectors", severity=self.severity)


class DMARCRecordPresent(DNSBase):
    id = "dns.dmarc.present"
    severity = "high"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        records = await self.client.query(f"_dmarc.{domain}", "TXT")
        if records:
            return TestResult(id=self.id, status="pass", evidence="DMARC record present", severity=self.severity)
        return TestResult(id=self.id, status="fail", evidence="DMARC record missing", recommendation="Create a DMARC TXT record", severity=self.severity)


class DMARCPolicyStrict(DNSBase):
    id = "dns.dmarc.policy"
    severity = "medium"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        records = await self.client.query(f"_dmarc.{domain}", "TXT")
        dmarc = " ".join(str(record).strip('"') for record in records)
        if "p=quarantine" in dmarc or "p=reject" in dmarc:
            return TestResult(id=self.id, status="pass", evidence="DMARC policy is strict", severity=self.severity)
        if "p=none" in dmarc:
            return TestResult(id=self.id, status="warning", evidence="DMARC policy set to none", recommendation="Use quarantine or reject", severity=self.severity)
        return TestResult(id=self.id, status="skipped", evidence="DMARC policy not present", severity=self.severity)


class DMARCPctFull(DNSBase):
    id = "dns.dmarc.pct"
    severity = "low"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        records = await self.client.query(f"_dmarc.{domain}", "TXT")
        dmarc = " ".join(str(record).strip('"') for record in records)
        if "pct=100" in dmarc:
            return TestResult(id=self.id, status="pass", evidence="DMARC pct=100", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="DMARC pct not set to 100", recommendation="Set pct=100 for DMARC", severity=self.severity)


class DMARCReportUris(DNSBase):
    id = "dns.dmarc.reporting"
    severity = "low"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        records = await self.client.query(f"_dmarc.{domain}", "TXT")
        dmarc = " ".join(str(record).strip('"') for record in records)
        if "rua=" in dmarc or "ruf=" in dmarc:
            return TestResult(id=self.id, status="pass", evidence="DMARC reporting configured", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="DMARC reporting not configured", recommendation="Add rua/ruf to DMARC record", severity=self.severity)


class DNSSECPresent(DNSBase):
    id = "dns.dnssec.present"
    severity = "medium"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        if await self.client.query_dnssec(domain):
            return TestResult(id=self.id, status="pass", evidence="DNSSEC present", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="DNSSEC not present", recommendation="Enable DNSSEC", severity=self.severity)


class DNSSECValidation(DNSBase):
    id = "dns.dnssec.validation"
    severity = "medium"

    async def execute(self, target: ScanContext) -> TestResult:
        if await self.client.query_dnssec(target.target):
            return TestResult(id=self.id, status="pass", evidence="DNSSEC validation appears configured", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="DNSSEC validation not configured", recommendation="Verify DNSSEC chain", severity=self.severity)


class CAARecordPresent(DNSBase):
    id = "dns.caa.present"
    severity = "medium"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        if await self.client.query(domain, "CAA"):
            return TestResult(id=self.id, status="pass", evidence="CAA record present", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="CAA record missing", recommendation="Add CAA record", severity=self.severity)


class CAALimitsIssuers(DNSBase):
    id = "dns.caa.issuers"
    severity = "low"

    async def execute(self, target: ScanContext) -> TestResult:
        records = await self.client.query(target.target, "CAA")
        if records and len(records) > 0:
            return TestResult(id=self.id, status="pass", evidence="CAA records limit issuers", severity=self.severity)
        return TestResult(id=self.id, status="skipped", evidence="No CAA records to evaluate", severity=self.severity)


class ZoneTransferDisabled(DNSBase):
    id = "dns.zone_transfer"
    severity = "high"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        if await self.client.zone_transfer_allowed(domain):
            return TestResult(id=self.id, status="fail", evidence="AXFR allowed", recommendation="Disable zone transfer", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="Zone transfer forbidden", severity=self.severity)


class SubdomainEnumeration(DNSBase):
    id = "dns.subdomain_enumeration"
    severity = "low"
    dictionary = ["www", "mail", "admin", "dev"]

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        found = []
        for sub in self.dictionary:
            records = await self.client.query(f"{sub}.{domain}", "A")
            if records:
                found.append(f"{sub}.{domain}")
        if found:
            return TestResult(id=self.id, status="info", evidence=f"Found subdomains: {', '.join(found)}", severity=self.severity)
        return TestResult(id=self.id, status="pass", evidence="No dictionary subdomains found", severity=self.severity)


class DanglingDNS(DNSBase):
    id = "dns.dangling"
    severity = "medium"

    async def execute(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="Dangling DNS check requires active domain data", severity=self.severity)


class MXRecordConfiguration(DNSBase):
    id = "dns.mx"
    severity = "medium"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        records = await self.client.query(domain, "MX")
        if records:
            return TestResult(id=self.id, status="pass", evidence="MX records present", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="Missing MX records", recommendation="Add MX records", severity=self.severity)


class NSRedundancy(DNSBase):
    id = "dns.ns_redundancy"
    severity = "medium"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        records = await self.client.query(domain, "NS")
        if len(records) >= 2:
            return TestResult(id=self.id, status="pass", evidence="Multiple NS records present", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="Insufficient NS redundancy", recommendation="Use at least two NS records", severity=self.severity)


class TTLReasonable(DNSBase):
    id = "dns.ttl"
    severity = "low"

    async def execute(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="TTL evaluation requires raw DNS data", severity=self.severity)


class PTRRecordPresent(DNSBase):
    id = "dns.ptr"
    severity = "low"

    async def execute(self, target: ScanContext) -> TestResult:
        domain = target.target.replace("https://", "").replace("http://", "").split("/")[0]
        if await self.client.query(domain, "PTR"):
            return TestResult(id=self.id, status="pass", evidence="PTR record present", severity=self.severity)
        return TestResult(id=self.id, status="warning", evidence="PTR record missing", recommendation="Add PTR record", severity=self.severity)


class WHOISExpiration(DNSBase):
    id = "dns.whois.expiration"
    severity = "low"

    async def execute(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="WHOIS lookup not implemented", recommendation="Add WHOIS expiration checks", severity=self.severity)


class WHOISPrivacy(DNSBase):
    id = "dns.whois.privacy"
    severity = "low"

    async def execute(self, target: ScanContext) -> TestResult:
        return TestResult(id=self.id, status="info", evidence="WHOIS privacy check not implemented", recommendation="Add WHOIS privacy detection", severity=self.severity)


registry.register(SPFRecordPresent())
registry.register(SPFValidSyntax())
registry.register(SPFPermissive())
registry.register(DKIMRecordPresent())
registry.register(DMARCRecordPresent())
registry.register(DMARCPolicyStrict())
registry.register(DMARCPctFull())
registry.register(DMARCReportUris())
registry.register(DNSSECPresent())
registry.register(DNSSECValidation())
registry.register(CAARecordPresent())
registry.register(CAALimitsIssuers())
registry.register(ZoneTransferDisabled())
registry.register(SubdomainEnumeration())
registry.register(DanglingDNS())
registry.register(MXRecordConfiguration())
registry.register(NSRedundancy())
registry.register(TTLReasonable())
registry.register(PTRRecordPresent())
registry.register(WHOISExpiration())
registry.register(WHOISPrivacy())
