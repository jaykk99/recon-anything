"""Canary fixtures for the gx_* completeness pack.

Fake values are assembled from fragments so no format-perfect secret
string ever appears verbatim in source (GitHub Push Protection).
The canary site (host canary.test) links/probes every gx detector;
external SaaS/storage hosts are faked here for the unit gate's
MockTransport handler (tests/test_gappack.py) and reused by
scripts/gappack_proof.py where the surface is target-relative.
"""
from __future__ import annotations

import json

# --- planted fake secrets (fragments; runtime values only) -------------
GIT_KEY = "AKIA" + "GXGIT" + "CANARY" + "00001"          # in git history only
PINECONE_KEY = "pcsk_" + "gx" + "canary" + "0123456789" + "abcdefghij"

TRELLO_BOARD_ID = "gxcanary1"
TRELLO_URL = f"https://trello.com/b/{TRELLO_BOARD_ID}/gx-roadmap"
JIRA_URL = ("https://gxcanary.atlassian.net/jira/software/projects/GX/"
            "boards/1")
CONFLUENCE_URL = ("https://gxcanary.atlassian.net/wiki/spaces/GX/"
                  "pages/123456/GX+Runbook")
DRIVE_URL = "https://drive.google.com/drive/folders/1GXCanaryFolder00000000000001"
DOCS_URL = "https://docs.google.com/spreadsheets/d/1GXCanarySheet0000000000001/edit"
AZURE_OBJECT_URL = ("https://gxacct.blob.core.windows.net/gxcontainer/"
                    "reports/q3-report.xlsx")
FIREBASE_REF = ("https://firebasestorage.googleapis.com/v0/b/"
                "gx-canary.appspot.com/o/uploads%2Fphoto.png?alt=media")
S3_OBJECT_URL = "https://gxcanary.s3.amazonaws.com/backups/db-export.sql"
HF_DATASET_URL = "https://huggingface.co/datasets/gxcanary/support-chats"
TRAIN_FILE_URL = "https://cdn.example.org/data/train-v3.jsonl"

CANARY_HTML = f"""<!DOCTYPE html>
<html><head><title>GX Canary Co</title>
<script src="/assets/app.js"></script></head>
<body>
<h1>GX Canary Co</h1>
<p>Team board: <a href="{TRELLO_URL}">roadmap</a></p>
<p>Tracker: <a href="{JIRA_URL}">GX board</a></p>
<p>Runbook: <a href="{CONFLUENCE_URL}">ops runbook</a></p>
<p>Shared folder: <a href="{DRIVE_URL}">assets</a></p>
<p>Sheet: <a href="{DOCS_URL}">numbers</a></p>
<p>Report: <a href="{AZURE_OBJECT_URL}">Q3 report</a></p>
<p>Export: <a href="{S3_OBJECT_URL}">db export</a></p>
<p>Backup: <a href="/dl/site-backup.sql">site backup</a></p>
<p>Dataset: <a href="{HF_DATASET_URL}">support chats</a></p>
<p>Training file: <a href="{TRAIN_FILE_URL}">train v3</a></p>
</body></html>"""

APP_JS = f"""
const firebasePic = "{FIREBASE_REF}";
const PINECONE_API_KEY = "{PINECONE_KEY}";
const ds = load_dataset("gxcanary/support-chats");
const GQL_MAIN = "https://api.canary.test/gql";
fetch("/api/v2/graphql", {{method: "POST", body: "{{}}"}});
"""

CLEAN_HTML = ("<html><head><title>Clean Co</title></head><body>"
              "<h1>Clean Co</h1><p>Nothing sensitive here.</p>"
              "</body></html>")

_INTROSPECTION = {
    "data": {"__schema": {
        "queryType": {"name": "Query"},
        "mutationType": {"name": "Mutation"},
        "subscriptionType": None,
        "types": [
            {"name": "Query", "kind": "OBJECT",
             "fields": [{"name": "viewer"}, {"name": "node"}],
             "inputFields": None, "enumValues": None},
            {"name": "Mutation", "kind": "OBJECT",
             "fields": [{"name": "updateThing"}],
             "inputFields": None, "enumValues": None},
            {"name": "User", "kind": "OBJECT",
             "fields": [{"name": "id"}, {"name": "name"},
                        {"name": "email"}],
             "inputFields": None, "enumValues": None},
            {"name": "Thing", "kind": "OBJECT",
             "fields": [{"name": "id"}, {"name": "title"}],
             "inputFields": None, "enumValues": None},
            {"name": "__Type", "kind": "OBJECT",
             "fields": [{"name": "name"}],
             "inputFields": None, "enumValues": None},
        ],
        "directives": []}}}

_AZURE_LIST_XML = (
    '<?xml version="1.0" encoding="utf-8"?>'
    "<EnumerationResults ServiceEndpoint="
    '"https://gxacct.blob.core.windows.net/" ContainerName="gxcontainer">'
    "<Blobs>"
    "<Blob><Name>reports/q3-report.xlsx</Name><Properties>"
    "<Content-Length>1024</Content-Length></Properties></Blob>"
    "<Blob><Name>reports/q4-report.xlsx</Name><Properties>"
    "<Content-Length>2048</Content-Length></Properties></Blob>"
    "</Blobs><NextMarker /></EnumerationResults>")

# path -> (content_type, body) served on the canary host (any port)
ROUTES = {
    "/assets/app.js": ("application/javascript", APP_JS),
    "/api/v1/collections": ("application/json", json.dumps(
        [{"id": "c1", "name": "gx-docs", "metadata": {}}])),
    "/api/v1/heartbeat": ("application/json", json.dumps(
        {"nanosecond heartbeat": 123456789})),
    "/collections": ("application/json", json.dumps(
        {"result": {"collections": [{"name": "gx-embeddings"}]},
         "status": "ok", "time": 0.001})),
    "/v1/schema": ("application/json", json.dumps(
        {"classes": [{"class": "GxDoc", "properties": [
            {"name": "title"}, {"name": "body"}]}]})),
    "/healthz": ("text/plain", "Healthy"),
    "/ajax-api/2.0/mlflow/experiments/list": ("application/json",
                                              json.dumps({"experiments": [
                                                  {"name": "gx-exp",
                                                   "artifact_location":
                                                       "/mlflow/gx"}]})),
    "/api/tags": ("application/json", json.dumps(
        {"models": [{"name": "llama3:8b", "size": 4661224676}]})),
    "/v2/models": ("application/json", json.dumps(
        [{"name": "gx_model", "version": "1", "state": "READY"}])),
    "/v2": ("application/json", json.dumps(
        {"name": "triton", "version": "2.40.0", "extensions": []})),
    "/models": ("application/json", json.dumps(
        {"models": [{"modelName": "gx_classifier",
                     "modelUrl": "s3://gx/gx.mar"}]})),
    "/v1/catalog/services": ("application/json", json.dumps(
        {"gx-api": ["v1"], "gx-web": [], "consul": []})),
    "/eureka/apps": ("application/json", json.dumps(
        {"applications": {"application": [
            {"name": "GX-API",
             "instance": [{"hostName": "10.6.6.7"}]}]}})),
    "/nacos/v1/ns/catalog/services": ("application/json", json.dumps(
        {"count": 2, "list": [{"name": "gx-api"},
                              {"name": "gx-web"}]})),
    "/debug/configz": ("application/json", json.dumps(
        {"configs": [
            {"cluster_name": "outbound|80||gx-api.gx.svc.cluster.local"},
            {"cluster_name":
             "outbound|443||gx-web.gx.svc.cluster.local"}]})),
    "/dl/site-backup.sql": ("application/sql",
                            "-- gx canary backup\nSELECT 1;\n"),
}

# POST path -> JSON body (GraphQL introspection + Milvus list)
POST_ROUTES = {
    "/api/v2/graphql": _INTROSPECTION,
    "/gql": _INTROSPECTION,
    "/v2/vectordb/collections/list": {"code": 0,
                                      "data": ["gx-faces", "gx-docs"]},
}

# external hosts faked for the unit gate: host -> path -> (ctype, body)
EXTERNAL = {
    "trello.com": {
        f"/b/{TRELLO_BOARD_ID}.json": ("application/json", json.dumps(
            {"id": TRELLO_BOARD_ID, "name": "GX Canary Board",
             "closed": False})),
    },
    "gxcanary.atlassian.net": {
        "/jira/software/projects/GX/boards/1": (
            "text/html",
            "<html><title>GX board - Jira</title><body>"
            "Jira Software by Atlassian - GX board</body></html>"),
        "/wiki/spaces/GX/pages/123456/GX+Runbook": (
            "text/html",
            "<html><title>GX Runbook - Confluence</title><body>"
            "Confluence by Atlassian - GX runbook</body></html>"),
    },
    "drive.google.com": {
        "/drive/folders/1GXCanaryFolder00000000000001": (
            "text/html",
            "<html><title>GX Canary Folder - Google Drive</title>"
            "<body>Google Drive shared folder</body></html>"),
    },
    "docs.google.com": {
        "/spreadsheets/d/1GXCanarySheet0000000000001/edit": (
            "text/html",
            "<html><title>GX Sheet - Google Docs</title>"
            "<body>Google Docs spreadsheet</body></html>"),
    },
    "gxacct.blob.core.windows.net": {
        "/gxcontainer": ("application/xml", _AZURE_LIST_XML),
        "/gxcontainer/reports/q3-report.xlsx": (
            "application/vnd.openxmlformats-officedocument."
            "spreadsheetml.sheet", "fake-xlsx"),
    },
    "gxcanary.s3.amazonaws.com": {
        "/backups/db-export.sql": ("application/sql", "-- fake export"),
    },
    "firebasestorage.googleapis.com": {
        "/v0/b/gx-canary.appspot.com/o": ("application/json", json.dumps(
            {"items": [{"name": "uploads/photo.png"},
                       {"name": "uploads/notes.txt"}]})),
        "/v0/b/gx-canary.appspot.com/o/uploads%2Fphoto.png": (
            "image/png", "fake-png"),
    },
}
