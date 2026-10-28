"""Financial documents & data detectors (fin_* pack, documents family).

Eight detection-only checks for financial data sitting in publicly
served documents and files: statement samples carrying internal data,
report exports, document-store directory listings, core-banking
database backups, application forms with internal hidden fields,
tax-form samples with TIN-shaped values, staff directories with
internal fields, and document metadata naming internal users/paths.
Read-only GETs only; personal-identifier-shaped values are masked in
findings.
"""
from __future__ import annotations

import re
from typing import Dict, List
from urllib.parse import urljoin

from .bankpack_util import FinPlugin, fetch_paths, fetch_text
from .base import Ctx, PluginResult, Target

# ---------------------------------------------------------------------------
# 25. fin_statement_sample - statement samples carrying internal data
# ---------------------------------------------------------------------------

STATEMENT_PATHS = (
    "/statements/sample", "/estatement/sample", "/statement-template",
    "/samples/statement.html", "/account-statement-sample",
    "/statements/sample.html", "/sample-statement",
)
_STATEMENT_MARKER_RE = re.compile(
    r"(account\s+statement|statement\s+of\s+account|estatement)",
    re.IGNORECASE)
_INTERNAL_DOC_MARKERS = (
    ("officer/employee id", re.compile(
        r"\b(?:officer|employee|staff)\s*(?:id|#|no\.?)\s*[:#]?\s*[A-Z]?\d{3,}",
        re.IGNORECASE)),
    ("GL account code", re.compile(
        r"\bGL\s*(?:account|acct|code)?\s*[:#]?\s*\d{4}[- ]\d{3,}", re.IGNORECASE)),
    ("core banking system", re.compile(
        r"(fiserv\s+dna|symitar|jack\s+henry|corelation\s+keystone|"
        r"temenos\s+transact|finacle)", re.IGNORECASE)),
    ("internal document marker", re.compile(
        r"\b(internal\s+use\s+only|confidential\s*[-–]\s*internal)\b",
        re.IGNORECASE)),
)


def analyze_statement_sample(text: str) -> List[Dict]:
    """Internal markers inside a statement-shaped document. The page
    must actually be a statement sample to fire."""
    out: List[Dict] = []
    if not text or not _STATEMENT_MARKER_RE.search(text):
        return out
    for name, pat in _INTERNAL_DOC_MARKERS:
        m = pat.search(text)
        if m:
            out.append({"issue": name, "value": m.group(0)[:70]})
    return out


class FinStatementSamplePlugin(FinPlugin):
    id = "fin_statement_sample"
    label = "Statement Sample Internal Data"
    description = ("Publicly served account-statement samples/templates "
                   "that still carry internal data: officer IDs, GL "
                   "codes, core-banking system names, internal-use "
                   "markers.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, STATEMENT_PATHS):
            for issue in analyze_statement_sample(text):
                findings.append(self.fin_finding(
                    "fin_statement_internal_data",
                    f"Statement sample at {url} carries "
                    f"{issue['issue']}: {issue['value']}",
                    url, "medium",
                    "Publish statement samples built from fully "
                    "synthetic data; scrub officer IDs, GL codes and "
                    "core-system identifiers.",
                    issue=issue["issue"]))
        if not findings:
            return self._ok([], f"statement samples clean on {domain}")
        return self._ok(findings,
                        f"{len(findings)} statement marker(s) on {domain}")


# ---------------------------------------------------------------------------
# 26. fin_report_exports - exposed financial report exports
# ---------------------------------------------------------------------------

REPORT_PATHS = (
    "/reports/daily.csv", "/reports/export.csv", "/reports",
    "/export/report.csv", "/reports/monthly.csv", "/admin/reports",
    "/reports/general-ledger.csv",
)
_CSV_HEADER_RE = re.compile(
    r"(gl_?account|account_?number|balance|ledger|debit|credit)",
    re.IGNORECASE)
_CSV_ROW_RE = re.compile(r"^\s*\d{3,}[\w\-]*\s*,\s*[\"']?[\d,]+\.\d{2}",
                         re.MULTILINE)


def analyze_report_export(text: str) -> List[Dict]:
    """A financial report export: ledger-flavoured header + money rows."""
    out: List[Dict] = []
    if not text:
        return out
    head = text[:2000]
    headers = _CSV_HEADER_RE.findall(head)
    rows = _CSV_ROW_RE.findall(text)
    if len(set(h.lower() for h in headers)) >= 2 and rows:
        out.append({"issue": "report_rows",
                    "value": f"{len(rows)} money row(s), columns: "
                             f"{', '.join(sorted(set(headers))[:4])}"})
    return out


class FinReportExportsPlugin(FinPlugin):
    id = "fin_report_exports"
    label = "Financial Report Export Exposure"
    description = ("Financial report exports (general-ledger / daily "
                   "reports) served from public paths with real money "
                   "rows.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, REPORT_PATHS):
            for issue in analyze_report_export(text):
                findings.append(self.fin_finding(
                    "fin_report_export",
                    f"Financial report export at {url}: {issue['value']}",
                    url, "high",
                    "Report exports are internal financial data; "
                    "generate them behind authentication and never "
                    "leave them on predictable public paths.",
                    issue=issue["issue"]))
        if not findings:
            return self._ok([], f"no report exports exposed on {domain}")
        return self._ok(findings,
                        f"{len(findings)} report export(s) on {domain}")


# ---------------------------------------------------------------------------
# 27. fin_docstore_listing - document-store directory listings
# ---------------------------------------------------------------------------

DOCSTORE_PATHS = (
    "/documents", "/docstore", "/files/", "/uploads/", "/forms/",
)
_LISTING_RE = re.compile(r"(index\s+of\s*/|directory\s+listing)",
                         re.IGNORECASE)
_SENSITIVE_FILE_RE = re.compile(
    r"[\w.\-]*(statement|wire|loan|swift|ach|payroll|ledger|backup|"
    r"\.sql|\.bak)[\w.\-]*", re.IGNORECASE)


def analyze_docstore_listing(text: str) -> List[Dict]:
    """Autoindex listings naming sensitive financial files."""
    out: List[Dict] = []
    if not text or not _LISTING_RE.search(text):
        return out
    names = sorted(set(m.group(0) for m in
                       _SENSITIVE_FILE_RE.finditer(text)))[:8]
    if names:
        out.append({"issue": "sensitive_filenames",
                    "value": ", ".join(names)})
    else:
        out.append({"issue": "open_listing",
                    "value": "directory listing enabled"})
    return out


class FinDocstoreListingPlugin(FinPlugin):
    id = "fin_docstore_listing"
    label = "Document Store Listing Exposure"
    description = ("Directory listings enabled on document stores "
                   "(documents/files/uploads) of a bank domain, "
                   "naming statements, wires, loans or backups.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, DOCSTORE_PATHS):
            for issue in analyze_docstore_listing(text):
                sev = "high" if issue["issue"] == "sensitive_filenames" \
                    else "medium"
                findings.append(self.fin_finding(
                    "fin_docstore_listing",
                    f"Document store listing at {url}: {issue['value']}",
                    url, sev,
                    "Disable directory listing on document stores and "
                    "serve files through authenticated, expiring "
                    "links only.",
                    issue=issue["issue"]))
        if not findings:
            return self._ok([], f"no document listings on {domain}")
        return self._ok(findings,
                        f"{len(findings)} listing(s) on {domain}")


# ---------------------------------------------------------------------------
# 28. fin_core_backup - core-banking database backups on public paths
# ---------------------------------------------------------------------------

BACKUP_PATHS = (
    "/backup/core_banking.sql", "/backups/core.sql",
    "/db/core_banking.sql", "/backup/loans.sql",
    "/sql/core_banking.sql", "/backup/banking_db.sql",
    "/backup/core.sql", "/db/loans_backup.sql",
)
_BANK_TABLE_RE = re.compile(
    r"CREATE\s+TABLE\s+[`\"']?(accounts|customers|loans|transactions|"
    r"deposits|borrowers|gl_entries)[`\"']?", re.IGNORECASE)
_SQL_MARKER_RE = re.compile(r"(INSERT\s+INTO|CREATE\s+TABLE|--\s*MySQL|"
                            r"--\s*PostgreSQL)", re.IGNORECASE)


def analyze_core_backup(text: str) -> List[Dict]:
    """SQL dumps whose tables are core-banking tables."""
    out: List[Dict] = []
    if not text or not _SQL_MARKER_RE.search(text):
        return out
    tables = sorted(set(m.group(1).lower()
                        for m in _BANK_TABLE_RE.finditer(text)))
    if tables:
        out.append({"issue": "banking_tables",
                    "value": f"core tables: {', '.join(tables)}"})
    return out


class FinCoreBackupPlugin(FinPlugin):
    id = "fin_core_backup"
    label = "Core Banking Backup Exposure"
    description = ("Core-banking database backups (SQL dumps with "
                   "accounts/loans/transactions tables) on public "
                   "paths. Content is sampled, never downloaded in "
                   "full.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, BACKUP_PATHS):
            for issue in analyze_core_backup(text):
                findings.append(self.fin_finding(
                    "fin_core_backup",
                    f"Core-banking backup at {url}: {issue['value']}",
                    url, "high",
                    "Remove database backups from the web root "
                    "immediately, treat the data as breached, and "
                    "store backups encrypted off-server.",
                    issue=issue["issue"]))
        if not findings:
            return self._ok([], f"no core backups exposed on {domain}")
        return self._ok(findings,
                        f"{len(findings)} core backup(s) on {domain}")


# ---------------------------------------------------------------------------
# 29. fin_form_hidden_fields - application forms leaking internal fields
# ---------------------------------------------------------------------------

FORM_PAGE_PATHS = (
    "/apply", "/apply-now", "/loan-application", "/applications",
    "/mortgage/apply", "/account/open", "/open-account",
)
_HIDDEN_INPUT_RE = re.compile(
    r"<input[^>]*type=[\"']hidden[\"'][^>]*>", re.IGNORECASE)
_NAME_ATTR_RE = re.compile(r"name=[\"']([^\"']+)[\"']", re.IGNORECASE)
_VALUE_ATTR_RE = re.compile(r"value=[\"']([^\"']*)[\"']", re.IGNORECASE)
_INTERNAL_VALUE_RE = re.compile(
    r"(https?://(?:localhost|127\.0\.0\.1)|\b10\.\d|\b192\.168\.|"
    r"\.(?:corp|local|internal|lan)\b|internal|debug|officer|"
    r"workflow)", re.IGNORECASE)
_INTERNAL_NAME_RE = re.compile(
    r"(officer|employee|internal|workflow|branch_?code|routing_?code|"
    r"debug|rep_?id)", re.IGNORECASE)


def analyze_hidden_fields(html: str) -> List[Dict]:
    """Hidden form fields carrying internal values or internal names."""
    out: List[Dict] = []
    for tag in _HIDDEN_INPUT_RE.findall(html or ""):
        nm = _NAME_ATTR_RE.search(tag)
        val = _VALUE_ATTR_RE.search(tag)
        name = nm.group(1) if nm else "?"
        value = val.group(1) if val else ""
        if value and _INTERNAL_VALUE_RE.search(value):
            out.append({"field": name, "value": value[:70]})
        elif _INTERNAL_NAME_RE.search(name) and value:
            out.append({"field": name, "value": value[:70]})
    return out[:8]


class FinFormHiddenFieldsPlugin(FinPlugin):
    id = "fin_form_hidden_fields"
    label = "Application Form Internal Fields"
    description = ("Banking application forms whose hidden fields "
                   "leak internal URLs, officer/employee IDs, workflow "
                   "or branch routing codes to every visitor.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        pages = await fetch_paths(ctx, base, FORM_PAGE_PATHS + ("/",))
        for url, text, _h in pages:
            for issue in analyze_hidden_fields(text):
                findings.append(self.fin_finding(
                    "fin_form_hidden_field",
                    f"Application form at {url} hides internal field "
                    f"{issue['field']}: {issue['value']}",
                    url, "medium",
                    "Keep internal routing/workflow data server-side; "
                    "hidden fields are public to anyone who views "
                    "source.",
                    field=issue["field"]))
        if not findings:
            return self._ok([], f"no internal hidden fields on {domain}")
        return self._ok(findings,
                        f"{len(findings)} hidden field(s) on {domain}")


# ---------------------------------------------------------------------------
# 30. fin_tax_sample_data - tax-form samples with TIN-shaped values
# ---------------------------------------------------------------------------

TAX_PATHS = (
    "/tax/sample", "/1099/sample", "/tax-forms/sample-1099",
    "/documents/1099-sample", "/tax/sample-1099.html", "/forms/1099-sample",
)
_TAX_MARKER_RE = re.compile(r"\b1099(?:-INT|-MISC|-NEC)?\b", re.IGNORECASE)
_TIN_RE = re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b")


def mask_tin(m) -> str:
    return f"***-**-{m.group(3)[-2:]}"


def analyze_tax_sample(text: str) -> List[Dict]:
    """1099-shaped samples carrying TIN-format values (masked here)."""
    out: List[Dict] = []
    if not text or not _TAX_MARKER_RE.search(text):
        return out
    tins = _TIN_RE.findall(text)
    if tins:
        masked = mask_tin(_TIN_RE.search(text))
        out.append({"issue": "tin_shaped_values",
                    "value": f"{len(tins)} TIN-shaped value(s), "
                             f"e.g. {masked}"})
    return out


class FinTaxSampleDataPlugin(FinPlugin):
    id = "fin_tax_sample_data"
    label = "Tax Form Sample TIN Exposure"
    description = ("Public 'sample' 1099/tax forms carrying TIN-shaped "
                   "values. Values are masked in the finding; samples "
                   "must be synthetic, and real ones are reportable "
                   "PII exposure.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, TAX_PATHS):
            for issue in analyze_tax_sample(text):
                findings.append(self.fin_finding(
                    "fin_tax_sample_tin",
                    f"Tax sample at {url}: {issue['value']}",
                    url, "high",
                    "Verify the sample is fully synthetic; if any "
                    "value is a real TIN, treat as a PII breach and "
                    "remove immediately.",
                    issue=issue["issue"]))
        if not findings:
            return self._ok([], f"no tax-sample TIN data on {domain}")
        return self._ok(findings,
                        f"{len(findings)} tax sample(s) on {domain}")


# ---------------------------------------------------------------------------
# 31. fin_staff_directory - staff directories with internal fields
# ---------------------------------------------------------------------------

STAFF_PATHS = (
    "/api/employees", "/staff-directory", "/directory", "/api/staff",
    "/staff.json", "/employees.json",
)
_STAFF_FIELD_RE = re.compile(
    r"(extension|ext|direct_?dial|employee_?id|department_?code|"
    r"manager|reports_?to|cost_?center)", re.IGNORECASE)


def analyze_staff_directory(text: str) -> List[Dict]:
    """Internal fields in a staff directory payload/page. Fires when
    directory-shaped content carries 2+ internal-only field types."""
    out: List[Dict] = []
    if not text:
        return out
    fields = sorted(set(m.group(1).lower()
                        for m in _STAFF_FIELD_RE.finditer(text)))
    has_people = bool(re.search(
        r"(@[a-z0-9.-]+\.[a-z]{2,}|\"name\"\s*:|employee)", text,
        re.IGNORECASE))
    if has_people and len(fields) >= 2:
        out.append({"issue": "internal_staff_fields",
                    "value": f"fields: {', '.join(fields)}"})
    return out


class FinStaffDirectoryPlugin(FinPlugin):
    id = "fin_staff_directory"
    label = "Staff Directory Internal Fields"
    description = ("Public staff directories / employee APIs exposing "
                   "internal fields: extensions, employee IDs, "
                   "department codes, reporting lines.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        for url, text, _h in await fetch_paths(ctx, base, STAFF_PATHS):
            for issue in analyze_staff_directory(text):
                findings.append(self.fin_finding(
                    "fin_staff_directory",
                    f"Staff directory at {url} exposes internal "
                    f"{issue['value']}",
                    url, "medium",
                    "Public directories should show name, role and a "
                    "shared contact only; extensions, employee IDs and "
                    "reporting lines fuel targeted phishing.",
                    issue=issue["issue"]))
        if not findings:
            return self._ok([], f"staff directories clean on {domain}")
        return self._ok(findings,
                        f"{len(findings)} staff director(ies) on {domain}")


# ---------------------------------------------------------------------------
# 32. fin_doc_metadata - document metadata naming internal users/paths
# ---------------------------------------------------------------------------

_DOC_LINK_RE = re.compile(r"href=[\"']([^\"']+\.pdf)[\"']", re.IGNORECASE)
_META_AUTHOR_RE = re.compile(r"/Author\s*\(([^)]{2,80})\)")
_META_TITLE_RE = re.compile(r"/Title\s*\(([^)]{2,120})\)")
_META_CREATOR_RE = re.compile(r"/Creator\s*\(([^)]{2,80})\)")
_INTERNAL_META_RE = re.compile(
    r"([a-z0-9.-]+\\[a-z0-9._-]+|[a-z]:\\users\\|\\\\[a-z0-9.-]+\\|"
    r"\.(?:corp|local|internal)\b|/home/[a-z0-9._-]+/)", re.IGNORECASE)


def analyze_pdf_metadata(text: str) -> List[Dict]:
    """Internal usernames/paths inside PDF metadata strings."""
    out: List[Dict] = []
    for label, pat in (("Author", _META_AUTHOR_RE),
                       ("Title", _META_TITLE_RE),
                       ("Creator", _META_CREATOR_RE)):
        for m in pat.finditer(text or ""):
            v = m.group(1)
            if _INTERNAL_META_RE.search(v):
                out.append({"field": label, "value": v[:80]})
    return out[:5]


class FinDocMetadataPlugin(FinPlugin):
    id = "fin_doc_metadata"
    label = "Document Metadata Internal Leak"
    description = ("PDFs published on the bank domain whose metadata "
                   "(Author/Title/Creator) names internal users, "
                   "domain accounts or file-server paths.")

    async def check(self, target: Target, ctx: Ctx) -> PluginResult:
        domain, base = await self.domain_base(target, ctx)
        if not base:
            return self._skipped("no host for this target type")
        findings = []
        home = await fetch_text(ctx, base)
        doc_urls: List[str] = []
        if home:
            for m in _DOC_LINK_RE.finditer(home[1]):
                u = urljoin(base, m.group(1))
                if u not in doc_urls:
                    doc_urls.append(u)
            doc_urls = doc_urls[:3]
        doc_urls += [urljoin(base, p) for p in
                     ("/documents/rates.pdf", "/documents/terms.pdf")]
        seen = set()
        for url in doc_urls:
            if url in seen:
                continue
            seen.add(url)
            got = await fetch_text(ctx, url)
            if not got:
                continue
            for issue in analyze_pdf_metadata(got[1]):
                findings.append(self.fin_finding(
                    "fin_doc_metadata_leak",
                    f"Document {url} metadata {issue['field']} names "
                    f"internal data: {issue['value']}",
                    url, "low",
                    "Scrub document metadata before publishing; "
                    "author names and source paths map internal "
                    "users and file shares.",
                    field=issue["field"]))
        if not findings:
            return self._ok([], f"document metadata clean on {domain}")
        return self._ok(findings,
                        f"{len(findings)} metadata leak(s) on {domain}")
