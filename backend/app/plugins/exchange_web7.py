"""Exchange-web detectors, block 7: KYC / uploads / storage.

Ten detectors for identity-verification and document-storage
exposure visible in an exchange site's own config and code: KYC
bucket names, unsigned upload flows, client-side signed-URL
generation, identity-provider secrets. Presence/config detection
only - no document is ever fetched (see _exchange_common).
"""
from __future__ import annotations

from ._exchange_common import ExchSpec, S, analyze, register

FAMILY = "exchange_web7"

SPECS = [
    S("exch_kyc_bucket_name_bundle", "KYC Document Bucket Name in Bundle Config",
      "high",
      "Bundle config names the storage bucket that holds KYC documents (bucket name carrying kyc), giving attackers the exact target to test for public or listable access.",
      "Never name document buckets in client config; hand the browser per-file signed URLs from the server and keep bucket names server-side.",
      patterns=[r"(?:bucket|Bucket)\s*[:=]\s*['\"][a-z0-9.\-]*kyc[a-z0-9.\-]*['\"]",
                r"['\"]s3://[a-z0-9.\-]*kyc[a-z0-9.\-]*['\"]"],
      category="infra"),
    S("exch_unsigned_upload_flow", "Unsigned Upload Preset/Flow Referenced in Client Code",
      "high",
      "Client code uses an unsigned upload preset/flow for document uploads, so anyone can push arbitrary files into the upload pipeline without an authenticated, server-issued grant.",
      "Use signed, per-session upload grants scoped to one user, one file type and one object key.",
      patterns=[r"(?:uploadPreset|upload_preset)\s*[:=]\s*['\"]unsigned[^'\"]*['\"]",
                r"(?:unsigned|signatureVersion)\s*[:=]\s*['\"]?unsigned['\"]?[\s\S]{0,200}?upload"],
      category="infra"),
    S("exch_signed_url_gen_client", "Signed URL Generated Client-Side With Credentials",
      "high",
      "Client code generates signed storage URLs using embedded credentials (getSignedUrl / createPresigned with a secret in scope), meaning the signing credential itself is in the bundle.",
      "Generate signed URLs only on the server, with credentials the browser never sees, scoped per user and per object.",
      patterns=[r"(?:getSignedUrl|createPresignedUrl|getSignedUrlPromise)\s*\([\s\S]{0,400}?(?:secretAccessKey|apiSecret|secret\s*[:=])",
                r"(?:secretAccessKey)\s*[:=]\s*['\"][A-Za-z0-9+/=]{16,}['\"][\s\S]{0,400}?(?:getSignedUrl|s3|bucket)"],
      negatives=[r"process\.env|import\.meta\.env"],
      category="leak"),
    S("exch_user_docs_bucket_config", "User Documents Bucket in Frontend Storage Config",
      "medium",
      "Frontend storage config names a bucket for user/identity documents (user-documents / id-documents style names), mapping where customer identity files live.",
      "Keep document-storage configuration server-side; the client should see only its own per-file URLs.",
      patterns=[r"(?:bucket|Bucket)\s*[:=]\s*['\"][a-z0-9.\-]*(?:user[-_]?docs|user[-_]?documents|id[-_]?documents|customer[-_]?docs)[a-z0-9.\-]*['\"]",
                r"['\"]gs://[a-z0-9.\-]*(?:documents|docs)[a-z0-9.\-]*['\"][\s\S]{0,120}?(?:identity|kyc|user)"],
      category="infra"),
    S("exch_idv_provider_secret_client", "Identity-Verification Provider Secret in Client Code",
      "high",
      "An identity-verification provider secret/API token (Onfido/Veriff/Jumio-style) is assigned in client code, exposing the credential that can query or alter verification results.",
      "Rotate the provider secret, keep provider calls server-side, and give the client only the provider's public SDK token scoped to one applicant.",
      patterns=[r"(?:onfido|veriff|jumio|persona)[A-Za-z_]*[_-]?(?:api[_-]?secret|secret|api[_-]?token)\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]",
                r"(?:ONFIDO|VERIFF|JUMIO)_[A-Z_]*SECRET\s*[:=]\s*['\"][A-Za-z0-9+/=_~\-]{12,}['\"]"],
      negatives=[r"process\.env|import\.meta\.env|sdkToken|sdk_token"],
      category="leak"),
    S("exch_doc_preview_no_auth_code", "Document Preview Fetch Without Auth in Client Code",
      "medium",
      "Client code fetches a document-preview URL by ID with no Authorization header in the request, suggesting preview endpoints may serve identity documents by ID alone.",
      "Require the session's Authorization on every document preview and authorize the document's owner server-side per request.",
      patterns=[r"fetch\s*\(\s*`[^`]*(?:preview|document)[^`]*\$\{(?:doc|document|file)Id\}[^`]*`\s*\)",
                r"fetch\s*\(\s*['\"][^'\"]*(?:/preview/|/documents?/)[^'\"]*['\"]\s*\+\s*\w*[Ii]d\s*\)"],
      negatives=[r"Authorization|Bearer|headers\s*[:=]"],
      category="api"),
    S("exch_kyc_download_route_ref", "KYC Document Download Route Referenced in JS",
      "medium",
      "JS code references a KYC/document download route, mapping the endpoint that serves identity documents so it can be probed for authorization gaps.",
      "Keep download routes out of shipped route tables where possible and authorize every document download server-side.",
      patterns=[r"['\"]/(?:api/)?(?:v\d/)?(?:kyc|documents?)/(?:download|export)/[^'\"]*['\"]",
                r"['\"][^'\"]*(?:kyc|identity)[^'\"]*/download[^'\"]*['\"]"],
      category="api"),
    S("exch_upload_type_check_client_only", "Upload File-Type Validation Implemented Only in Client Code",
      "medium",
      "The upload flow's file-type validation lives in client code (validateFileType / allowedExtensions checks in the browser), which attackers bypass by calling the upload endpoint directly with any file type.",
      "Re-validate file type server-side from content, not extension, on every upload regardless of client checks.",
      patterns=[r"(?:validateFileType|checkFileType|isAllowedExtension)\s*\([^)]*\)\s*\{[^}]{0,300}?(?:allowedExtensions|allowedTypes|accept\s*[:=])",
                r"(?:allowedExtensions|allowedMimeTypes)\s*[:=]\s*\[[^\]]+\][\s\S]{0,200}?upload"],
      category="web"),
    S("exch_presigned_expiry_excessive", "Over-Long Presigned URL Expiry in Client Config",
      "medium",
      "Client config sets a presigned/signed URL expiry of a week or more, so a leaked document URL stays valid long after the session that created it ends.",
      "Cap signed URL lifetimes to minutes for document access and mint a fresh URL per view.",
      patterns=[r"(?:signedUrl|presigned|presign)[A-Za-z_]*\s*[:=]\s*\{[^}]{0,200}?(?:expiresIn|expiry|expires)\s*[:=]\s*(?:604800|86400\s*\*\s*7|7\s*\*\s*24\s*\*\s*3600)\b",
                r"(?:expiresIn|expirySeconds)\s*[:=]\s*(?:604800|1209600)\b[\s\S]{0,200}?(?:signed|presign|document|bucket)"],
      category="infra"),
    S("exch_storage_access_key_bundle", "Storage Access Key Pair in Bundle for Uploads",
      "high",
      "Bundle config carries a storage access key ID together with upload/bucket context - the first half of a credential pair, shipped alongside the code that uses the bucket.",
      "Remove storage credentials from client config, rotate the key, and issue per-session signed upload grants instead.",
      patterns=[r"(?:storageAccessKey|accessKeyId|AWS_ACCESS_KEY_ID)\s*[:=]\s*['\"][A-Z0-9]{16,20}['\"][\s\S]{0,300}?(?:bucket|upload|s3)",
                r"(?:bucket|upload)[\s\S]{0,300}?(?:accessKeyId|AWS_ACCESS_KEY_ID)\s*[:=]\s*['\"][A-Z0-9]{16,20}['\"]"],
      negatives=[r"process\.env|import\.meta\.env|example"],
      category="leak"),
]

SPECS_BY_ID = register(SPECS, __name__, globals())


def analyze_exchange_web7(text: str, spec: ExchSpec, headers=None):
    return analyze(text, spec, headers)
