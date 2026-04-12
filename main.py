#!/usr/bin/env python3
"""
Recursive Multi-Worker GitHub .env Scanner
Research tool for finding exposed API keys in GitHub repositories.

Architecture (per Kimi design doc):
  MainExplorer  — BFS across service types, spawns per-service workers
  ServiceWorker — DFS within one service type, updates PatternDatabase
  PatternDatabase     — shared regex knowledge base (thread-safe, versioned)
  ResilientVisitedTracker — dedup at every level (services, keys, repos)
  ResultAggregator    — global dedup and report generation
"""

import os
import re
import sys
import math
import json
import time
import base64
import signal
import hashlib
import argparse
import threading
from queue import Queue, Empty
from datetime import datetime, timezone
from typing import Dict, List, Optional, Set, Tuple

from curl_cffi import requests as curl_requests
from curl_cffi.requests import Session as CurlSession

# ---------------------------------------------------------------------------
# Service seed queries — fired at startup for EVERY known service, guaranteed.
# Uses exact env-var-name queries for maximum precision.
# ---------------------------------------------------------------------------
SERVICE_SEEDS: List[Tuple[str, str]] = [
    # Western AI / Cloud
    ("openai",      'filename:.env "OPENAI_API_KEY"'),
    ("anthropic",   'filename:.env "ANTHROPIC_API_KEY"'),
    ("aws",         'filename:.env "AWS_SECRET_ACCESS_KEY"'),
    ("google",      'filename:.env "GOOGLE_API_KEY"'),
    ("github",      'filename:.env "GITHUB_TOKEN"'),
    ("slack",       'filename:.env "SLACK_BOT_TOKEN"'),
    ("stripe",      'filename:.env "STRIPE_SECRET_KEY"'),
    ("twilio",      'filename:.env "TWILIO_AUTH_TOKEN"'),
    ("sendgrid",    'filename:.env "SENDGRID_API_KEY"'),
    ("heroku",      'filename:.env "HEROKU_API_KEY"'),
    ("mailgun",     'filename:.env "MAILGUN_API_KEY"'),
    ("azure",       'filename:.env "AZURE_OPENAI_API_KEY"'),
    ("serper",      'filename:.env "SERPER_API_KEY"'),
    # Chinese / Asian AI Platforms
    ("deepseek",    'filename:.env "DEEPSEEK_API_KEY"'),
    ("moonshot",    'filename:.env "MOONSHOT_API_KEY"'),
    # SiliconFlow  (siliconflow.cn / api.siliconflow.cn)
    ("siliconflow", 'filename:.env "SILICONFLOW_API_KEY"'),
    ("siliconflow", 'filename:.env "SILICONFLOW_KEY"'),
    ("siliconflow", 'filename:.env "SF_API_KEY"'),
    ("siliconflow", 'filename:.env siliconflow.cn'),
    ("siliconflow", 'filename:.env "api.siliconflow.cn"'),
    ("siliconflow", '"https://api.siliconflow.cn"'),
    ("siliconflow", 'extension:example "SILICONFLOW_API_KEY"'),
    ("siliconflow", 'extension:example "SF_API_KEY"'),
    ("siliconflow", 'extension:local "SILICONFLOW_API_KEY"'),
    ("siliconflow", 'extension:development "SILICONFLOW_API_KEY"'),
    ("zhipuai",     'filename:.env "ZHIPUAI_API_KEY"'),
    ("dashscope",   'filename:.env "DASHSCOPE_API_KEY"'),
    ("minimax",     'filename:.env "MINIMAX_API_KEY"'),
    ("qianfan",     'filename:.env "QIANFAN_ACCESS_KEY"'),
    ("ark",         'filename:.env "ARK_API_KEY"'),
    ("hunyuan",     'filename:.env "HUNYUAN_SECRET_KEY"'),
    ("spark",       'filename:.env "SPARK_API_KEY"'),
    ("stepfun",     'filename:.env "STEPFUN_API_KEY"'),
    ("baichuan",    'filename:.env "BAICHUAN_API_KEY"'),
    ("yi",          'filename:.env "YI_API_KEY"'),
    
    # Web Scraping / Data
    ("firecrawl",   'filename:.env "FIRECRAWL_API_KEY"'),
    ("firecrawl",   'filename:.env "FIRECRAWL_KEY"'),
    ("firecrawl",   'filename:.env "FIRECRAWL_API"'),
    ("firecrawl",   'filename:.env "X_FIRECRAWL_API_KEY"'),
    ("firecrawl",   'filename:.env "FC_API_KEY"'),
    ("firecrawl",   'filename:.env "FIRECRAWL_SECRET_KEY"'),
    ("firecrawl",   'filename:.env fc-'),
    ("firecrawl",   'filename:.env "firecrawl-api"'),
    ("firecrawl",   'filename:.env "firecrawl-api-key"'),
    ("firecrawl",   'filename:.env "firecrawl-x-api-key"'),
    ("firecrawl",   '"https://mcp.firecrawl.dev/fc"'),
    ("firecrawl",   'extension:example "FIRECRAWL_API_KEY"'),
    ("firecrawl",   'extension:example "FIRECRAWL_KEY"'),
    ("firecrawl",   'extension:example fc-'),
    ("firecrawl",   'extension:local "FIRECRAWL_API_KEY"'),
    ("firecrawl",   'extension:development "FIRECRAWL_API_KEY"'),
    
    # Tavily (tavily.com)
    ("tavily",      'filename:.env "TAVILY_API_KEY"'),
    ("tavily",      'filename:.env "TAVILY_KEY"'),
    ("tavily",      'filename:.env tvly-'),
    ("tavily",      'extension:example "TAVILY_API_KEY"'),
    ("tavily",      'extension:example "TAVILY_KEY"'),
    ("tavily",      'extension:example tvly-'),
    ("tavily",      'extension:local "TAVILY_API_KEY"'),
    ("tavily",      'extension:development "TAVILY_API_KEY"'),
    
    # Cohere (cohere.com)
    ("cohere",      'filename:.env "COHERE_API_KEY"'),
    ("cohere",      'filename:.env "CO_API_KEY"'),
    ("cohere",      'extension:example "COHERE_API_KEY"'),
    ("cohere",      'extension:example "CO_API_KEY"'),
    ("cohere",      'extension:local "COHERE_API_KEY"'),
    ("cohere",      'extension:local "CO_API_KEY"'),
    ("cohere",      'extension:development "COHERE_API_KEY"'),
    ("cohere",      'extension:development "CO_API_KEY"'),

    # NeonDB  (neon.tech) — Postgres-as-a-service
    ("neondb",      'filename:.env "NEON_DATABASE_URL"'),
    ("neondb",      'filename:.env "NEONDB_URL"'),
    ("neondb",      'filename:.env "NEON_URL"'),
    ("neondb",      'filename:.env "NEON_DB_URL"'),
    ("neondb",      'filename:.env "postgresql://neondb"'),
    ("neondb",      'filename:.env "postgres://neondb"'),
    ("neondb",      'filename:.env neon.tech'),
    ("neondb",      'filename:.env "@ep-" neon.tech'),
    ("neondb",      'filename:.env "POSTGRES_URL" neon'),
    ("neondb",      'filename:.env "POSTGRES_PRISMA_URL"'),
    ("neondb",      'filename:.env "POSTGRES_URL_NON_POOLING"'),
    ("neondb",      'extension:example "NEON_DATABASE_URL"'),
    ("neondb",      'extension:example neon.tech'),
    ("neondb",      'extension:local "NEON_DATABASE_URL"'),
    ("neondb",      'extension:local neon.tech'),
    ("neondb",      'extension:development "NEON_DATABASE_URL"'),
    ("neondb",      'extension:development neon.tech'),
    ("neondb",      '"ep-" "neon.tech" filename:.env'),
    ("neondb",      '"@ep-" ".neon.tech"'),
]


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def redact_key(key: str) -> str:
    """Redact a matched key string — expose only first and last 4 chars."""
    if len(key) <= 8:
        return "*" * len(key)
    return key[:4] + "*" * (len(key) - 8) + key[-4:]


def key_fingerprint(service: str, repo: str, path: str, raw_key: str) -> str:
    """
    Create a stable fingerprint for deduplication.
    Format: {service}:{repo}:{path}:{key_hash}
    """
    key_hash = hashlib.sha256(raw_key.encode()).hexdigest()[:16]
    return f"{service}:{repo}:{path}:{key_hash}"


SEVERITY_ICON = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🟢",
}

# ---------------------------------------------------------------------------
# PatternDatabase — shared, thread-safe, versioned
# ---------------------------------------------------------------------------

class PatternDatabase:
    """
    Shared knowledge base that all workers read and update.
    Stores regex patterns, key formats, and repository clusters.
    Versioned to track pattern evolution.
    """

    _BUILTIN_PATTERNS: Dict[str, dict] = {
        # --- Western AI / Cloud ---
        "aws_access_key":  {"pattern": r"AKIA[0-9A-Z]{16}",                                                           "description": "AWS Access Key ID",             "severity": "high"},
        "aws_secret_key":  {"pattern": r"aws_secret_access_key\s*[=:]\s*[\"']?[a-zA-Z0-9/+=]{40}[\"']?",              "description": "AWS Secret Access Key",         "severity": "critical"},
        "google_api_key":  {"pattern": r"AIza[0-9A-Za-z_-]{35}",                                                       "description": "Google API Key",                "severity": "high"},
        "github_token":    {"pattern": r"gh[pousr]_[A-Za-z0-9_]{36,}",                                                 "description": "GitHub Personal Access Token",  "severity": "critical"},
        "slack_token":     {"pattern": r"xox[baprs]-[0-9a-zA-Z]{10,48}",                                               "description": "Slack Token",                   "severity": "critical"},
        "stripe_key":      {"pattern": r"sk_live_[0-9a-zA-Z]{24,}",                                                    "description": "Stripe Live Secret Key",         "severity": "critical"},
        "stripe_test_key": {"pattern": r"sk_test_[0-9a-zA-Z]{24,}",                                                    "description": "Stripe Test Secret Key",         "severity": "medium"},
        "sendgrid_key":    {"pattern": r"SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}",                                   "description": "SendGrid API Key",              "severity": "high"},
        "twilio_key":      {"pattern": r"SK[0-9a-f]{32}",                                                              "description": "Twilio API Key",                "severity": "high"},
        "heroku_key":      {"pattern": r"[hH][eE][rR][oO][kK][uU].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}", "description": "Heroku API Key", "severity": "high"},
        "generic_api_key": {"pattern": r"(?i)(api[_-]?key|apikey)[\s]*[=:][\s]*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?",     "description": "Generic API Key",               "severity": "medium"},
        "generic_secret":  {"pattern": r"(?i)(secret|private[_-]?key)[\s]*[=:][\s]*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?", "description": "Generic Secret",                "severity": "medium"},
        "database_url":    {"pattern": r"(?i)DATABASE_URL\s*[=:]\s*[\"']?[\w\+]+://[^:]+:[^@]+@[^/]+/[^\"'\s]+[\"']?","description": "Database Connection String",     "severity": "critical"},
        "jwt_secret":      {"pattern": r"(?i)(jwt[_-]?secret|auth[_-]?secret)[\s]*[=:][\s]*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?", "description": "JWT Secret Key",        "severity": "high"},
        "mailgun_key":     {"pattern": r"key-[0-9a-f]{32}",                                                            "description": "Mailgun API Key",               "severity": "high"},
        "openai_key":      {"pattern": r"sk-(?:proj|svcacct|[a-zA-Z0-9])[a-zA-Z0-9_\-]{20,}",                         "description": "OpenAI API Key",                "severity": "high"},
        "anthropic_key":   {"pattern": r"sk-ant-[a-zA-Z0-9_\-]{40,}",                                                 "description": "Anthropic API Key",             "severity": "high"},
        "azure_key":       {"pattern": r"(?i)AZURE.*[=:]\s*[\"']?[a-zA-Z0-9+/]{32,}={0,2}[\"']?",                     "description": "Azure API Key",                 "severity": "high"},
        "serper_key":      {"pattern": r"(?i)serper[_-]?(?:api[_-]?)?key[\s]*[=:][\s]*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?", "description": "Serper.dev API Key",         "severity": "high"},
        # --- Chinese & Asian AI Platforms ---
        # DeepSeek  (deepseek.com)
        "deepseek_key":    {"pattern": r"(?i)DEEPSEEK[_-]?(?:API[_-]?)?KEY\s*[=:]\s*[\"']?sk-[a-zA-Z0-9]{20,}[\"']?",  "description": "DeepSeek API Key",              "severity": "high"},
        # Moonshot / Kimi  (moonshot.ai / kimi.ai)
        "moonshot_key":    {"pattern": r"(?i)MOONSHOT[_-]?(?:API[_-]?)?KEY\s*[=:]\s*[\"']?sk-[a-zA-Z0-9]{20,}[\"']?",  "description": "Moonshot (Kimi) API Key",       "severity": "high"},
        # SiliconFlow  (siliconflow.cn)
        "siliconflow_key": {"pattern": r"(?i)(?:SILICONFLOW|SF)[_-]?(?:API[_-]?)?KEY\s*[=:]\s*[\"']?sk-[a-zA-Z0-9]{20,}[\"']?", "description": "SiliconFlow API Key",    "severity": "high"},
        # ZhipuAI / GLM  (zhipuai.cn)
        "zhipuai_key":     {"pattern": r"(?i)(?:ZHIPU(?:AI)?|GLM)[_-]?(?:API[_-]?)?KEY\s*[=:]\s*[\"']?[a-zA-Z0-9._\-]{20,}[\"']?", "description": "ZhipuAI (GLM) API Key", "severity": "high"},
        # Alibaba DashScope / Qwen / Tongyi  (dashscope.aliyuncs.com)
        "dashscope_key":   {"pattern": r"(?i)DASHSCOPE[_-]?(?:API[_-]?)?KEY\s*[=:]\s*[\"']?sk-[a-zA-Z0-9]{20,}[\"']?",  "description": "Alibaba DashScope API Key",     "severity": "high"},
        # MiniMax  (minimax.chat)
        "minimax_key":     {"pattern": r"(?i)MINIMAX[_-]?(?:API[_-]?)?KEY\s*[=:]\s*[\"']?[a-zA-Z0-9._\-]{20,}[\"']?",   "description": "MiniMax API Key",               "severity": "high"},
        # Baidu / Qianfan / ERNIE  (qianfan.baidubce.com)
        "qianfan_key":     {"pattern": r"(?i)(?:QIANFAN|ERNIE|BAIDU)[_-]?(?:ACCESS|API|SECRET)[_-]?KEY\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{20,}[\"']?", "description": "Baidu Qianfan / ERNIE Key", "severity": "high"},
        # ByteDance Ark / Coze  (ark.cn-beijing.volces.com / coze.com)
        "ark_key":         {"pattern": r"(?i)(?:ARK|COZE|DOUBAO|VOLC(?:ENGINE)?)[_-]?(?:API[_-]?)?(?:KEY|TOKEN)\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{20,}[\"']?", "description": "ByteDance Ark/Coze API Key", "severity": "high"},
        # Tencent Hunyuan  (hunyuan.tencent.com)
        "hunyuan_key":     {"pattern": r"(?i)(?:HUNYUAN|TENCENT)[_-]?SECRET[_-]?(?:ID|KEY)\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{20,}[\"']?", "description": "Tencent Hunyuan Secret",      "severity": "high"},
        # iFlytek Spark  (spark-api.xf-yun.com)
        "spark_key":       {"pattern": r"(?i)(?:SPARK|IFLYTEK|XFYUN)[_-]?(?:API[_-]?)?(?:KEY|SECRET)\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{16,}[\"']?", "description": "iFlytek Spark API Key",       "severity": "high"},
        # Stepfun / 阶跃星辰  (stepfun.com)
        "stepfun_key":     {"pattern": r"(?i)STEPFUN[_-]?(?:API[_-]?)?KEY\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{20,}[\"']?",   "description": "Stepfun API Key",               "severity": "high"},
        # Baichuan AI  (baichuan-ai.com)
        "baichuan_key":    {"pattern": r"(?i)BAICHUAN[_-]?(?:API[_-]?)?KEY\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{20,}[\"']?",  "description": "Baichuan AI API Key",           "severity": "high"},
        # 01.ai / Yi  (01.ai)
        "yi_key":          {"pattern": r"(?i)(?:YI|01AI)[_-]?(?:API[_-]?)?KEY\s*[=:]\s*[\"']?[a-zA-Z0-9_\-]{20,}[\"']?", "description": "01.ai Yi API Key",            "severity": "high"},
        # Firecrawl  (firecrawl.dev)
        # Primary: fc- prefix pattern matches keys regardless of variable name
        "firecrawl_key":         {"pattern": r"fc-[a-f0-9]{32}",                                                                    "description": "Firecrawl API Key",             "severity": "high"},
        # Named-variable variants people commonly use
        "firecrawl_named_key":   {"pattern": r"(?i)(?:FIRECRAWL[_-]?(?:API[_-]?)?(?:KEY|SECRET|TOKEN)|X[_-]FIRECRAWL[_-]API[_-]KEY|FC[_-]API[_-]KEY)\s*[=:]\s*[\"']?fc-[a-f0-9]{32}[\"']?", "description": "Firecrawl API Key (named var)", "severity": "high"},
        # Tavily  (tavily.com)
        "tavily_key":            {"pattern": r"tvly-[a-zA-Z0-9]{32}",                                                               "description": "Tavily API Key",                "severity": "high"},
        "tavily_named_key":      {"pattern": r"(?i)(?:TAVILY[_-]?(?:API[_-]?)?(?:KEY|SECRET|TOKEN)|X[_-]TAVILY[_-]API[_-]KEY)\s*[=:]\s*[\"']?tvly-[a-zA-Z0-9]{32}[\"']?", "description": "Tavily API Key (named var)", "severity": "high"},
        # Cohere  (cohere.com)
        "cohere_key":            {"pattern": r"(?i)CO(?:HERE)?_?API_?KEY.*?([A-Za-z0-9_-]{35,45})",                                    "description": "Cohere API Key",                "severity": "high"},
        # NeonDB  (neon.tech)
        # Matches any postgres:// URL whose host contains .neon.tech (pooled or direct endpoints)
        "neondb_conn_string":    {"pattern": r"(?:postgres(?:ql)?)://\S+@[^\s\"']*\.neon\.tech[^\s\"']*",                             "description": "NeonDB Connection String",      "severity": "critical"},
        # Named variable forms: NEON_DATABASE_URL, NEONDB_URL, NEON_URL, NEON_DB_URL
        "neondb_named_url":      {"pattern": r"(?i)(?:NEON(?:DB)?[_-]?(?:DATABASE[_-]?)?URL|NEON[_-]DB[_-]?URL)\s*[=:]\s*[\"']?postgres(?:ql)?://[^\s\"']+[\"']?", "description": "NeonDB URL (named var)",  "severity": "critical"},
        # Vercel/Neon integration variable names (POSTGRES_URL, POSTGRES_PRISMA_URL, etc.)
        "neondb_vercel_url":     {"pattern": r"(?i)(?:POSTGRES(?:QL)?(?:_PRISMA)?(?:_URL(?:_NON_POOLING)?))\s*[=:]\s*[\"']?postgres(?:ql)?://[^\s\"']*\.neon\.tech[^\s\"']*[\"']?", "description": "NeonDB Vercel/Postgres URL", "severity": "critical"},
    }

    # Map pattern key names to the service label used in fingerprints/worker routing
    SERVICE_MAP: Dict[str, str] = {
        "aws_access_key":  "aws",
        "aws_secret_key":  "aws",
        "google_api_key":  "google",
        "github_token":    "github",
        "slack_token":     "slack",
        "stripe_key":      "stripe",
        "stripe_test_key": "stripe",
        "sendgrid_key":    "sendgrid",
        "twilio_key":      "twilio",
        "heroku_key":      "heroku",
        "generic_api_key": "generic",
        "generic_secret":  "generic",
        "database_url":    "database",
        "jwt_secret":      "jwt",
        "mailgun_key":     "mailgun",
        "openai_key":      "openai",
        "anthropic_key":   "anthropic",
        "azure_key":       "azure",
        "serper_key":            "serper",
        "firecrawl_key":         "firecrawl",
        "firecrawl_named_key":   "firecrawl",
        "tavily_key":            "tavily",
        "tavily_named_key":      "tavily",
        "cohere_key":            "cohere",
        "neondb_conn_string":    "neondb",
        "neondb_named_url":      "neondb",
        "neondb_vercel_url":     "neondb",
    }

    def __init__(self):
        self._lock = threading.RLock()
        self._patterns: Dict[str, dict] = dict(self._BUILTIN_PATTERNS)
        self._version = 1

    @property
    def version(self) -> int:
        return self._version

    def get_patterns(self) -> Dict[str, dict]:
        with self._lock:
            return dict(self._patterns)

    def service_for(self, key_type: str) -> str:
        return self.SERVICE_MAP.get(key_type, key_type.split("_")[0])

    def add_pattern(self, key_type: str, pattern: str, description: str, severity: str, service: Optional[str] = None):
        """Add or overwrite a pattern and bump the version."""
        with self._lock:
            self._patterns[key_type] = {
                "pattern": pattern,
                "description": description,
                "severity": severity,
            }
            if service:
                self.SERVICE_MAP[key_type] = service
            self._version += 1

    # Generic harvester: matches any VAR_NAME=value where the name signals a credential.
    # Captures (var_name, value).
    _GENERIC_KEY_RE = re.compile(
        r"^([A-Z][A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASS|AUTH|ACCESS|CREDENTIAL|PRIVATE|CERT|APIKEY|API_KEY)[A-Z0-9_]*)\s*=\s*(.+)$",
        re.IGNORECASE,
    )

    # Bracketed / templated values: [your key], <api_key>, {{key}}
    _BRACKETED = re.compile(r"^[\[\(<{].*[\]\)>}]$")

    # Obvious literal placeholder words
    _PLACEHOLDER_WORDS = re.compile(
        r"(?:^|[-_])"
        r"(?:your|here|insert|replace|changeme|todo|placeholder|example"
        r"|dummy|fake|test|sample|none|null|true|false|undefined|xxxx"
        r"|aaaa|fill|put[-_]?your|qwerty|asdfgh)",
        re.IGNORECASE,
    )

    # Sequential chars: abcdefgh, 12345678, qwerty...
    _SEQ_ALPHABETS = [
        "abcdefghijklmnopqrstuvwxyz",
        "zyxwvutsrqponmlkjihgfedcba",
        "0123456789",
        "9876543210",
        "qwertyuiop",
        "asdfghjkl",
        "zxcvbnm",
    ]

    @staticmethod
    def _shannon_entropy(s: str) -> float:
        """Shannon entropy in bits per character. Real keys score ≥ 3.5."""
        if not s:
            return 0.0
        freq: dict = {}
        for c in s:
            freq[c] = freq.get(c, 0) + 1
        n = len(s)
        return -sum((f / n) * math.log2(f / n) for f in freq.values())

    def _is_placeholder(self, value: str) -> bool:
        """
        Return True if the value is clearly NOT a real credential.

        Signals of a fake/placeholder value:
          - Bracketed template: [your key here], <api_key>, {{token}}
          - Literal placeholder words: your, replace, changeme, example…
          - Too short (< 8 chars)
          - Too few unique characters (e.g. xxxxxxxxxxxx → 1 unique char)
          - Pure digits (port numbers, IDs)
          - Sequential/keyboard-walk runs: abcdefgh, 12345678, qwerty…
          - Low Shannon entropy (< 3.0 bits/char) — not cryptographically random

        Real API keys are random strings with entropy typically ≥ 3.5 bits/char.
        """
        v = value.strip().strip("'\"` ")

        # Bracketed templates: [your shodan key], <key>, {{token}}
        if self._BRACKETED.match(v):
            return True

        # Env-var reference: ${VAR}, %VAR%
        if re.fullmatch(r"\$\{[^}]+\}|%[A-Z_]+%", v, re.IGNORECASE):
            return True

        if len(v) < 8:
            return True

        # Placeholder words anywhere in the value
        if self._PLACEHOLDER_WORDS.search(v):
            return True

        # Unique-character count — xxxxxxxx has 1, aababab has 2
        if len(set(v.lower())) < 3:
            return True

        # Pure digits
        if re.fullmatch(r"\d+", v):
            return True

        # Character-class diversity: real keys mix uppercase, lowercase, digits.
        # Pure single-class long strings (e.g. abcdefghijklmnop, QWERTYUIOP1234) are placeholders.
        has_upper = bool(re.search(r"[A-Z]", v))
        has_lower = bool(re.search(r"[a-z]", v))
        has_digit = bool(re.search(r"[0-9]", v))
        class_count = sum([has_upper, has_lower, has_digit])
        if len(v) > 10 and class_count < 2:
            return True

        # Shannon entropy — real keys are cryptographically random, placeholders are not.
        # Threshold of 3.0 bits/char catches most fake values; real keys typically score ≥ 3.5.
        entropy = self._shannon_entropy(v)
        if entropy < 3.0:
            return True

        return False

    def _infer_severity(self, var_name: str) -> str:
        """Infer severity from the variable name."""
        upper = var_name.upper()
        if any(k in upper for k in ("LIVE", "PROD", "PRODUCTION", "MASTER", "PRIVATE")):
            return "critical"
        if any(k in upper for k in ("SECRET", "PASSWORD", "PASS", "CREDENTIAL", "CERT")):
            return "high"
        if any(k in upper for k in ("KEY", "TOKEN", "AUTH", "ACCESS")):
            return "medium"
        return "low"

    def scan_lines(self, lines: List[str]) -> List[Tuple[int, str, dict, str]]:
        """
        Two-pass scan:
        Pass 1 - Builtin regex patterns (specific key formats).
        Pass 2 - Generic harvester: any ENV_VAR_NAME that looks like a credential
                 and wasn't already captured by a builtin.
        New key types discovered by Pass 2 are auto-registered into PatternDatabase.
        """
        results = []
        matched_positions: Set[Tuple[int, int]] = set()  # (line_num, char_offset) dedup

        # --- Pass 1: builtin patterns ---
        patterns = self.get_patterns()
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for key_type, config in patterns.items():
                for match in re.finditer(config["pattern"], line, re.IGNORECASE):
                    # Extract the value part (after the first = or :) for placeholder check
                    matched_str = match.group(0)
                    val_part = re.split(r"[=:\s]+", matched_str, maxsplit=1)[-1]
                    if self._is_placeholder(val_part):
                        continue
                    pos = (line_num, match.start())
                    if pos not in matched_positions:
                        matched_positions.add(pos)
                        results.append((line_num, key_type, config, matched_str))

        # --- Pass 2: generic variable-name harvester ---
        for line_num, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            m = self._GENERIC_KEY_RE.match(stripped)
            if not m:
                continue

            var_name, raw_value = m.group(1), m.group(2).strip().strip("'\"`")

            if self._is_placeholder(raw_value):
                continue

            # Auto-classify by variable name
            key_type = var_name.lower()
            severity = self._infer_severity(var_name)
            description = var_name.replace("_", " ").title()

            # Always auto-register new key types — even if Pass 1 already reported this line.
            # This ensures PatternDatabase accumulates every unique credential variable name.
            if key_type not in self.get_patterns():
                self.add_pattern(
                    key_type,
                    pattern=rf"(?i){re.escape(var_name)}\s*=\s*\S+",
                    description=description,
                    severity=severity,
                )

            # Only add a finding if Pass 1 didn't already report something on this line
            # (avoids duplicate findings for the same credential).
            if any(ln == line_num for ln, _, _, _ in results):
                continue

            config = {"description": description, "severity": severity,
                      "pattern": rf"(?i){re.escape(var_name)}\s*=\s*\S+"}
            results.append((line_num, key_type, config, raw_value))

        return results


# ---------------------------------------------------------------------------
# ResilientVisitedTracker — all dedup state in one place
# ---------------------------------------------------------------------------

class ResilientVisitedTracker:
    """
    Handles out-of-order results from GitHub's non-deterministic API ordering.

    Visited levels (per Kimi doc):
      L1 — visited_services   : don't spawn duplicate workers
      L2 — scanned_repos      : skip repos with no new commits
      L3/4 — global_visited_keys : don't report same key fingerprint twice
    """

    def __init__(self):
        self._lock = threading.Lock()
        # L1: {service_label → {worker_id, spawned_at, status}}
        self.visited_services: Dict[str, dict] = {}
        # L2: {repo → {last_scanned, github_updated_at, keys_found}}
        self.scanned_repos: Dict[str, dict] = {}
        # L3/4: {fingerprint_str} — global across all workers
        self.global_visited_keys: Set[str] = set()

    # --- L1: Services ---

    def has_service_worker(self, service: str) -> bool:
        with self._lock:
            return service in self.visited_services

    def register_service_worker(self, service: str, worker_id: str):
        with self._lock:
            self.visited_services[service] = {
                "worker_id": worker_id,
                "spawned_at": datetime.now(tz=timezone.utc).isoformat(),
                "status": "active",
            }

    def mark_service_done(self, service: str):
        with self._lock:
            if service in self.visited_services:
                self.visited_services[service]["status"] = "done"

    # --- L2: Repos ---

    def should_process_repo(self, repo: str, github_updated_at: Optional[str]) -> bool:
        """
        Return True if we should scan this repo:
          - Never seen → True
          - Seen, but GitHub shows newer update → True
          - Seen, same/older → False
        """
        with self._lock:
            if repo not in self.scanned_repos:
                return True
            last = self.scanned_repos[repo]
            if github_updated_at and github_updated_at > last.get("github_updated_at", ""):
                return True
            return False

    def mark_repo_scanned(self, repo: str, github_updated_at: Optional[str], keys_found: int = 0):
        with self._lock:
            self.scanned_repos[repo] = {
                "last_scanned": datetime.now(tz=timezone.utc).isoformat(),
                "github_updated_at": github_updated_at or "",
                "keys_found": keys_found,
            }

    # --- L3/4: Key fingerprints ---

    def is_key_new(self, fingerprint: str) -> bool:
        with self._lock:
            return fingerprint not in self.global_visited_keys

    def mark_key_visited(self, fingerprint: str):
        with self._lock:
            self.global_visited_keys.add(fingerprint)

    # --- Warm-start from a prior run ---

    def load_from_report(self, report: dict):
        """Populate visited sets from a previous scan's JSON output."""
        for finding in report.get("findings", []):
            fp = key_fingerprint(
                finding.get("service", "unknown"),
                finding.get("repository", ""),
                finding.get("file", ""),
                finding.get("matched_pattern", ""),
            )
            self.global_visited_keys.add(fp)

        for repo, meta in report.get("scan_metadata", {}).get("scanned_repos", {}).items():
            self.scanned_repos[repo] = meta


# ---------------------------------------------------------------------------
# ResultAggregator — global dedup and report generation
# ---------------------------------------------------------------------------

class ResultAggregator:
    """Collects findings from all workers, deduplicates, and emits reports."""

    def __init__(self, tracker: ResilientVisitedTracker, output_dir: Optional[str] = None):
        self._tracker = tracker
        self._lock = threading.Lock()
        self._findings: List[dict] = []
        self._output_dir = output_dir
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)

    def add_finding(self, finding: dict) -> bool:
        """
        Add a finding if its fingerprint hasn't been seen globally.
        Immediately writes to {output_dir}/{service}.ndjson on disk.
        Returns True if the finding was accepted.
        """
        fp = key_fingerprint(
            finding.get("service", "unknown"),
            finding["repository"],
            finding["file"],
            finding.get("matched_pattern", ""),
        )
        if not self._tracker.is_key_new(fp):
            return False
        self._tracker.mark_key_visited(fp)
        with self._lock:
            self._findings.append(finding)
            # Stream to disk immediately — safe even on Ctrl+C
            if self._output_dir:
                svc = finding.get("service", "unknown")
                path = os.path.join(self._output_dir, f"{svc}.ndjson")
                with open(path, "a") as fh:
                    fh.write(json.dumps(finding) + "\n")
        return True

    @property
    def findings(self) -> List[dict]:
        with self._lock:
            return list(self._findings)

    def save_to_directory(self, tracker: ResilientVisitedTracker, output_dir: str) -> str:
        """
        Write per-service JSON files into output_dir, plus a summary.json index.

        output_dir/
          summary.json          ← metadata + per-service counts
          generic.json
          openai.json
          deepseek.json
          ... (one file per service that had findings)
        """
        os.makedirs(output_dir, exist_ok=True)

        findings = self.findings
        unique_repos = len(set(f["repository"] for f in findings)) if findings else 0
        unique_files = len(set((f["repository"], f["file"]) for f in findings)) if findings else 0

        # Group by service
        by_service: Dict[str, List[dict]] = {}
        for f in findings:
            svc = f.get("service", "unknown")
            by_service.setdefault(svc, []).append(f)

        # Write per-service files
        service_index: Dict[str, dict] = {}
        for svc, svc_findings in sorted(by_service.items()):
            fname = f"{svc}.json"
            fpath = os.path.join(output_dir, fname)
            with open(fpath, "w") as fh:
                json.dump({
                    "service": svc,
                    "scan_timestamp": datetime.now().isoformat(),
                    "finding_count": len(svc_findings),
                    "findings": svc_findings,
                }, fh, indent=2)
            service_index[svc] = {"finding_count": len(svc_findings), "file": fname}

        # Write summary.json
        summary_path = os.path.join(output_dir, "summary.json")
        with open(summary_path, "w") as fh:
            json.dump({
                "scan_metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "total_repositories": unique_repos,
                    "total_files_scanned": unique_files,
                    "total_findings": len(findings),
                    "scanner_version": "2.0",
                    "scanned_repos": tracker.scanned_repos,
                    "visited_services": tracker.visited_services,
                },
                "services": service_index,
            }, fh, indent=2)

        print(f"\n📂 Results saved to: {output_dir}/")
        for svc, info in sorted(service_index.items()):
            icon = "🔴" if info["finding_count"] > 5 else "🟠" if info["finding_count"] > 1 else "🟡"
            print(f"   {icon} {svc:<20} {info['finding_count']:>4} finding(s) → {info['file']}")
        print(f"   📊 summary.json")

        return output_dir

    def generate_text_report(self) -> str:
        findings = self.findings
        if not findings:
            return "No API keys found in scanned files."

        severity_order = ["critical", "high", "medium", "low"]
        by_sev: Dict[str, List[dict]] = {s: [] for s in severity_order}
        for f in findings:
            by_sev.setdefault(f.get("severity", "medium"), []).append(f)

        lines = [
            "=" * 80,
            "RECURSIVE MULTI-WORKER .env SCANNER — SECURITY RESEARCH REPORT",
            "=" * 80,
            f"Generated  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Findings   : {len(findings)}",
            f"Services   : {len(set(f.get('service','?') for f in findings))}",
            "=" * 80,
        ]

        for sev in severity_order:
            items = by_sev[sev]
            if not items:
                continue
            icon = SEVERITY_ICON.get(sev, "❓")
            lines.append(f"\n{icon} {sev.upper()} ({len(items)} finding{'s' if len(items) != 1 else ''})")
            lines.append("-" * 80)
            for f in items:
                lines.append(f"  Service : {f.get('service', 'unknown')}")
                lines.append(f"  Repo    : {f['repository']}")
                lines.append(f"  File    : {f['file']}")
                lines.append(f"  URL     : {f['url']}#L{f['line_number']}")
                lines.append(f"  Type    : {f['description']}")
                lines.append(f"  Line {f['line_number']:>4}: {f['line_preview']}")
                lines.append("")

        return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTTP Session helper (shared across workers)
# ---------------------------------------------------------------------------

_RETRY_STATUS = {500, 502, 503, 504}
_MAX_RETRIES = 5
_BACKOFF_BASE = 1.5  # seconds — exponential: 1.5, 2.25, 3.375, …

# GitHub Code Search API: 10 req/min authenticated (practical: use 9 for safety).
# 60s / 9 req = 6.67s gap. Round up slightly to 7.0s as buffer.
_SEARCH_MIN_GAP = 7.0  # seconds between consecutive search/code calls


class GlobalSearchClock:
    """
    Single authority for ALL GitHub Code Search API calls across every worker.

    Enforces:
      - Minimum 7s gap between consecutive calls (gap throttle)
      - X-RateLimit-Remaining / X-RateLimit-Reset header awareness
      - If remaining == 0 and reset is in the future → sleep until reset + 1s
      - If remaining == 0 and reset is in the past  → stale state, clear and proceed

    All workers call acquire() before a search and record_response() after.
    No per-worker rate state needed anywhere else.
    """

    _MIN_GAP = _SEARCH_MIN_GAP  # 7.0s

    def __init__(self):
        self._lock = threading.Lock()
        self._last_call: float = 0.0      # monotonic time of last search call
        self._remaining: int = 9          # from X-RateLimit-Remaining header
        self._reset_at: float = 0.0       # Unix timestamp from X-RateLimit-Reset

    def acquire(self):
        """Block until it is safe to fire another Code Search request."""
        with self._lock:
            now_wall = time.time()
            now_mono = time.monotonic()

            # --- Step 1: check if the window is exhausted ---
            if self._remaining < 2 and self._reset_at:
                if self._reset_at > now_wall:
                    # Window genuinely not reset yet — sleep until it does
                    wait = (self._reset_at - now_wall) + 1.0  # +1s safety buffer
                    print(f"\u26a0\ufe0f  Search quota low ({self._remaining} left). "
                          f"Sleeping {wait:.0f}s for window reset...")
                    time.sleep(wait)
                    # Reset state — new window just started
                    self._remaining = 9
                    self._reset_at = 0.0
                    now_mono = time.monotonic()  # refresh after sleep
                else:
                    # reset_at is in the past → stale state, clear it
                    self._remaining = 9
                    self._reset_at = 0.0

            # --- Step 2: enforce minimum gap ---
            gap = self._MIN_GAP - (now_mono - self._last_call)
            if gap > 0:
                time.sleep(gap)

            self._last_call = time.monotonic()

    def record_response(self, resp) -> None:
        """Update quota state from a search API response's rate-limit headers."""
        rem = resp.headers.get("X-RateLimit-Remaining")
        rst = resp.headers.get("X-RateLimit-Reset")
        if rem is None and rst is None:
            return
        with self._lock:
            if rem is not None:
                self._remaining = int(rem)
            if rst is not None:
                self._reset_at = float(rst)


_search_clock = GlobalSearchClock()


def _build_session(github_token: Optional[str] = None) -> CurlSession:
    """Build a curl_cffi Session that impersonates Chrome to bypass TLS fingerprinting."""
    session = CurlSession(impersonate="chrome110")
    session.headers.update({
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "CMU-Security-Research-Scanner/2.0",
    })
    if github_token:
        session.headers["Authorization"] = f"token {github_token}"
    return session


def _get_with_retry(
    session: CurlSession,
    url: str,
    *,
    timeout: int = 15,
    **kwargs,
) -> Optional[curl_requests.Response]:
    """
    GET with manual exponential-backoff retry on transient 5xx errors.
    curl_cffi doesn't support urllib3 adapters, so we roll our own.

    Code Search calls are throttled to ≤30/min via _search_throttle.
    Core API calls (file content) are unthrottled (5000/hr budget).
    """
    is_search = "search/code" in url
    if is_search:
        _search_clock.acquire()

    for attempt in range(_MAX_RETRIES):
        try:
            resp = session.get(url, timeout=timeout, **kwargs)
        except Exception as exc:
            wait = _BACKOFF_BASE ** attempt
            print(f"  \u26a0\ufe0f  Network error (attempt {attempt+1}/{_MAX_RETRIES}): {exc} — retrying in {wait:.1f}s")
            time.sleep(wait)
            if is_search:
                _search_clock.acquire()  # re-acquire before retry
            continue

        if is_search:
            _search_clock.record_response(resp)  # update quota from headers

        if resp.status_code not in _RETRY_STATUS:
            return resp

        wait = _BACKOFF_BASE ** attempt
        print(f"  \u26a0\ufe0f  HTTP {resp.status_code} (attempt {attempt+1}/{_MAX_RETRIES}) — retrying in {wait:.1f}s")
        time.sleep(wait)
        if is_search:
            _search_clock.acquire()

    return None  # all retries exhausted


# ---------------------------------------------------------------------------
# ServiceWorker — DFS per service type
# ---------------------------------------------------------------------------

class ServiceWorker:
    """
    DFS exploration of a single service domain (e.g. 'openai', 'stripe').
    Receives repos/queries via its queue, scans them, updates PatternDatabase.
    Terminates when its queue is empty and no new patterns have been found for
    a configurable idle window.
    """

    def __init__(
        self,
        service: str,
        worker_id: str,
        pattern_db: PatternDatabase,
        tracker: ResilientVisitedTracker,
        aggregator: ResultAggregator,
        session: CurlSession,
        verbose: bool = False,
        stop_event: Optional[threading.Event] = None,
    ):
        self.service = service
        self.worker_id = worker_id
        self.pattern_db = pattern_db
        self.tracker = tracker
        self.aggregator = aggregator
        self.session = session
        self.verbose = verbose
        self.stop_event = stop_event or threading.Event()

        # Worker-local visited cache (L3/4 fast path before global check)
        self._local_visited: Set[str] = set()
        # Queue accepts: str (search query) or dict (file_info — scan directly, no Search API)
        self.queue: Queue = Queue()

    def enqueue(self, item):
        """Enqueue a search query (str) or a pre-fetched file_info (dict)."""
        self.queue.put(item)

    def run(self):
        """Run the DFS loop: drain queue, scan files, update pattern DB."""
        while not self.stop_event.is_set():
            try:
                item = self.queue.get(timeout=1)  # short timeout — checks stop_event
            except Empty:
                break

            # Item is either a search query (str) or a direct file_info (dict)
            if isinstance(item, str):
                if self.verbose:
                    print(f"  [{self.worker_id}] search: {item}")
                files = self._search_files(item)
            else:
                files = [item]  # already have the file_info, skip Search API entirely

            for file_info in files:
                repo = file_info["repository"]
                updated_at = file_info.get("updated_at")

                if not self.tracker.should_process_repo(repo, updated_at):
                    if self.verbose:
                        print(f"  [{self.worker_id}] skip (no new commits): {repo}")
                    continue

                if self.verbose:
                    print(f"  [{self.worker_id}] scan: {repo}/{file_info['path']}")

                content = self._fetch_content(file_info["url"])
                if content is None:
                    continue

                lines = content.split("\n")
                hits = self.pattern_db.scan_lines(lines)
                keys_found = 0

                for line_num, key_type, config, raw_match in hits:
                    svc = self.pattern_db.service_for(key_type)
                    fp = key_fingerprint(svc, repo, file_info["path"], raw_match)

                    if fp in self._local_visited:
                        continue
                    self._local_visited.add(fp)

                    finding = {
                        "service": svc,
                        "file": file_info["path"],
                        "repository": repo,
                        "url": file_info["html_url"],
                        "line_number": line_num,
                        "line_preview": lines[line_num - 1].strip()[:120],
                        "key_type": key_type,
                        "description": config["description"],
                        "severity": config["severity"],
                        "matched_pattern": redact_key(raw_match),
                        "timestamp": datetime.now().isoformat(),
                    }

                    if svc == "neondb":
                        # Preserve the full matched token for downstream URL parsing.
                        finding["candidate_url"] = raw_match.strip()

                    accepted = self.aggregator.add_finding(finding)
                    if accepted:
                        keys_found += 1
                        icon = SEVERITY_ICON.get(config["severity"], "❓")
                        print(
                            f"  {icon} [{self.worker_id}] {repo}/{file_info['path']}:{line_num} "
                            f"— {config['description']}"
                        )

                self.tracker.mark_repo_scanned(repo, updated_at, keys_found)

            self.queue.task_done()

        self.tracker.mark_service_done(self.service)
        if self.verbose:
            print(f"  [{self.worker_id}] done.")

    # --- HTTP helpers ---

    def _get(self, url: str, **kwargs) -> Optional[curl_requests.Response]:
        resp = _get_with_retry(self.session, url, **kwargs)
        if resp is None:
            return None

        if resp.status_code == 403:
            retry_after = int(resp.headers.get("Retry-After", 60))
            print(f"  ⚠️  Secondary rate limit (403). Retrying after {retry_after}s...")
            time.sleep(retry_after)
            return self._get(url, **kwargs)

        return resp

    def _search_files(self, query: str, max_results: int = 100) -> List[dict]:
        files = []
        page = 1
        per_page = min(100, max_results)

        while len(files) < max_results:
            resp = self._get(
                "https://api.github.com/search/code",
                params={"q": query, "per_page": per_page, "page": page},
            )
            if resp is None or resp.status_code != 200:
                break

            data = resp.json()
            items = data.get("items", [])
            if not items:
                break

            for item in items:
                files.append({
                    "name": item["name"],
                    "path": item["path"],
                    "repository": item["repository"]["full_name"],
                    "html_url": item["html_url"],
                    "url": item["url"],
                    "updated_at": item["repository"].get("updated_at"),
                })

            if len(items) < per_page:
                break
            page += 1

        return files[:max_results]

    def _fetch_content(self, file_url: str) -> Optional[str]:
        resp = self._get(file_url)
        if resp is None or resp.status_code != 200:
            return None

        data = resp.json()
        content = data.get("content", "")
        if data.get("encoding") == "base64":
            try:
                return base64.b64decode(content).decode("utf-8", errors="ignore")
            except Exception:
                return None
        return content


# ---------------------------------------------------------------------------
# MainExplorer — BFS across service types
# ---------------------------------------------------------------------------

class MainExplorer:
    """
    BFS Level 0→1: discovers service types from broad .env searches,
    spawns one ServiceWorker per service, and routes new discoveries to
    the correct worker via its queue.
    """

    def __init__(
        self,
        github_token: Optional[str],
        pattern_db: PatternDatabase,
        tracker: ResilientVisitedTracker,
        aggregator: ResultAggregator,
        max_workers: int = 8,
        verbose: bool = False,
    ):
        self.pattern_db = pattern_db
        self.tracker = tracker
        self.aggregator = aggregator
        self.max_workers = max_workers
        self.verbose = verbose

        self._session = _build_session(github_token)

        self._workers: Dict[str, "ServiceWorker"] = {}
        self._worker_threads: Dict[str, threading.Thread] = {}
        self._worker_idx = 0
        self._workers_lock = threading.Lock()
        # Cache: tracks (repo, path) pairs already queued to avoid duplicate Content API fetches
        self._queued_files: Set[Tuple[str, str]] = set()
        self._queued_lock = threading.Lock()

    def _spawn_worker(self, service: str, stop_event: threading.Event) -> "ServiceWorker":
        """Create, register, and start a new ServiceWorker for a service."""
        self._worker_idx += 1
        worker_id = f"worker_{self._worker_idx:03d}_{service}"

        worker = ServiceWorker(
            service=service,
            worker_id=worker_id,
            pattern_db=self.pattern_db,
            tracker=self.tracker,
            aggregator=self.aggregator,
            session=self._session,
            verbose=self.verbose,
            stop_event=stop_event,
        )
        self.tracker.register_service_worker(service, worker_id)

        t = threading.Thread(target=worker.run, name=worker_id, daemon=True)
        with self._workers_lock:
            self._workers[service] = worker
            self._worker_threads[service] = t
        t.start()

        print(f"  🚀 Spawned {worker_id}")
        return worker

    def _route_to_worker(self, service: str, query: str):
        """Send a query to an existing worker or spawn a new one."""
        with self._workers_lock:
            existing = self._workers.get(service)

        if existing:
            existing.enqueue(query)
            return

        # Enforce max_workers cap — fall back to broad worker
        if len(self._workers) >= self.max_workers:
            with self._workers_lock:
                fallback = next(iter(self._workers.values()))
            fallback.enqueue(query)
            return

        worker = self._spawn_worker(service)
        worker.enqueue(query)

    def run(
        self,
        seed_query: str = "filename:.env",
        max_seed_results: int = 10,
        repo: Optional[str] = None,
        user: Optional[str] = None,
        stop_event: Optional[threading.Event] = None,
        services_filter: Optional[List[str]] = None,
    ):
        """
        Phase 1 — Broad pass: seed search returns up to max_seed_results files,
        routed directly to service workers (no per-repo search calls).

        Phase 2 — Pre-seed guarantee: every known service in SERVICE_SEEDS gets a
        dedicated worker with a targeted env-var-name query, regardless of whether
        it appeared in the broad pass. Full coverage, no luck required.
        """
        if repo:
            seed_query = f"repo:{repo} filename:.env"
        elif user:
            seed_query = f"user:{user} filename:.env"

        stop_event = stop_event or threading.Event()

        print(f"\n🔍 Phase 1 — Broad pass: {seed_query}")
        files = self._broad_search(seed_query, max_seed_results)
        print(f"  Found {len(files)} file(s) in broad pass.")

        # Route broad-pass files directly to workers (triggered by repo-name classification)
        for file_info in files:
            file_key = (file_info["repository"], file_info["path"])
            with self._queued_lock:
                if file_key in self._queued_files:
                    if self.verbose:
                        print(f"  ℹ️  Cache hit, skipping: {file_key}")
                    continue
                self._queued_files.add(file_key)

            service = self._classify_file(file_info)
            if self.tracker.has_service_worker(service):
                with self._workers_lock:
                    w = self._workers.get(service)
                if w:
                    w.enqueue(file_info)
            else:
                worker = self._spawn_worker(service, stop_event)
                worker.enqueue(file_info)

        # Phase 2: pre-seed ALL known services with their targeted deep queries.
        # Workers already spawned just receive an extra search query.
        # Workers not spawned yet get created now — guaranteed coverage.
        active_seeds = [
            (svc, q) for svc, q in SERVICE_SEEDS
            if not services_filter or svc in services_filter
        ]
        print(f"\n🚀 Phase 2 — Pre-seeding {len(active_seeds)} service workers...")
        for service, query in active_seeds:
            if self.tracker.has_service_worker(service):
                with self._workers_lock:
                    w = self._workers.get(service)
                if w:
                    w.enqueue(query)
            else:
                worker = self._spawn_worker(service, stop_event)
                worker.enqueue(query)

        print(f"  {len(self._workers)} total worker(s) active.")

        # Wait for all workers to finish
        print("\n⏳ Waiting for service workers to complete...")
        with self._workers_lock:
            threads = list(self._worker_threads.values())
        for t in threads:
            t.join()

    def _classify_file(self, file_info: dict) -> Optional[str]:
        """
        Peek at the repo name to guess its primary service, as a lightweight
        BFS classification step before spawning workers. This avoids needing
        to fetch every file during the broad pass.
        """
        repo = file_info["repository"].lower()
        name_map = [
            # Western AI / Cloud
            ("openai",       "openai"),
            ("stripe",       "stripe"),
            ("twilio",       "twilio"),
            ("sendgrid",     "sendgrid"),
            ("aws",          "aws"),
            ("firebase",     "google"),
            ("google",       "google"),
            ("slack",        "slack"),
            ("heroku",       "heroku"),
            ("mailgun",      "mailgun"),
            ("anthropic",    "anthropic"),
            ("azure",        "azure"),
            ("serper",       "serper"),
            # Chinese / Asian AI Platforms
            ("deepseek",     "deepseek"),
            ("moonshot",     "moonshot"),
            ("kimi",         "moonshot"),
            ("siliconflow",  "siliconflow"),
            ("silicon-flow", "siliconflow"),
            ("zhipu",        "zhipuai"),
            ("zhipuai",      "zhipuai"),
            ("bigmodel",     "zhipuai"),   # ZhipuAI's model platform domain
            ("dashscope",    "dashscope"),
            ("tongyi",       "dashscope"),
            ("qwen",         "dashscope"),
            ("minimax",      "minimax"),
            ("qianfan",      "qianfan"),
            ("ernie",        "qianfan"),
            ("baidu",        "qianfan"),
            ("coze",         "ark"),
            ("doubao",       "ark"),
            ("volcengine",   "ark"),
            ("byteark",      "ark"),
            ("hunyuan",      "hunyuan"),
            ("tencent",      "hunyuan"),
            ("spark",        "spark"),
            ("iflytek",      "spark"),
            ("xfyun",        "spark"),
            ("stepfun",      "stepfun"),
            ("baichuan",     "baichuan"),
            ("01ai",         "yi"),
            ("lingyiwanwu",  "yi"),   # Yi's Chinese brand name domain
            # Web Scraping / Data
            ("firecrawl",    "firecrawl"),
            ("tavily",       "tavily"),
            ("cohere",       "cohere"),
        ]
        for keyword, service in name_map:
            if keyword in repo:
                return service
        return "generic"

    def _broad_search(self, query: str, max_results: int) -> List[dict]:
        files = []
        page = 1
        per_page = min(100, max_results)

        while len(files) < max_results:
            resp = _get_with_retry(
                self._session,
                "https://api.github.com/search/code",
                params={"q": query, "per_page": per_page, "page": page},
            )
            if resp is None:
                break

            if resp.status_code == 403:
                retry_after = int(resp.headers.get("Retry-After", 60))
                print(f"⚠️  Rate limited (403). Retrying after {retry_after}s...")
                time.sleep(retry_after)
                continue
            if resp.status_code != 200:
                print(f"❌ Search error {resp.status_code}: {resp.text[:200]}")
                break

            items = resp.json().get("items", [])
            if not items:
                break

            for item in items:
                files.append({
                    "name": item["name"],
                    "path": item["path"],
                    "repository": item["repository"]["full_name"],
                    "html_url": item["html_url"],
                    "url": item["url"],
                    "updated_at": item["repository"].get("updated_at"),
                })

            print(f"  Broad pass: {len(files)} file(s) found...")

            if len(items) < per_page:
                break
            page += 1

        return files[:max_results]



# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Recursive Multi-Worker GitHub .env Scanner — Security Research Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Global broad search (needs GitHub token)
  python main.py --token YOUR_GITHUB_TOKEN

  # Scan a specific repository
  python main.py --token TOKEN --repo owner/repository

  # Scan all of a user's public repos
  python main.py --token TOKEN --user username

  # Limit broad-pass results, save to custom file
  python main.py --token TOKEN --max-results 50 --output results.json

  # Resume from a prior scan (warms visited sets, skips already-seen repos)
  python main.py --token TOKEN --resume results_20260304_163600.json

  # Save text report with verbose per-file output
  python main.py --token TOKEN --report scan.txt --verbose
        """,
    )

    parser.add_argument("--token", "-t",
                        help="GitHub personal access token (required for reasonable rate limits)")
    parser.add_argument("--repo", "-r",
                        help="Specific repository to scan (format: owner/repo)")
    parser.add_argument("--user", "-u",
                        help="GitHub username to scan all their public repos")
    parser.add_argument("--max-results", "-m", type=int, default=10,
                        help="Maximum files in the broad BFS pass (default: 10)")
    parser.add_argument("--max-workers", "-w", type=int, default=30,
                        help="Max simultaneous service workers (default: 30, enough for all known services)")
    parser.add_argument("--output", "-o", default=None,
                        help="Output directory for per-service JSON files (default: results_TIMESTAMP/)")
    parser.add_argument("--report",
                        help="Output text report file")
    parser.add_argument("--query", "-q", default="filename:.env",
                        help="Seed search query (default: filename:.env)")
    parser.add_argument("--resume",
                        help="Path to a prior scan JSON to warm visited sets (avoids re-scanning seen repos)")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print a line for every file scanned, not just hits")
    parser.add_argument("--services", "-s",
                        help="Comma-separated list of services to scan (e.g. firecrawl,openai). "
                             "Default: all known services.")

    args = parser.parse_args()

    print("=" * 80)
    print("RECURSIVE MULTI-WORKER .env SCANNER — CMU SECURITY RESEARCH")
    print("=" * 80)
    print()

    # Shared state
    pattern_db = PatternDatabase()
    tracker = ResilientVisitedTracker()

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output or f"results_{ts}"
    aggregator = ResultAggregator(tracker, output_dir=output_dir)

    # SIGINT handler — Ctrl+C saves findings before exit
    stop_event = threading.Event()

    def _on_sigint(sig, frame):
        if stop_event.is_set():
            print("\n⚠️  Force exit.")
            sys.exit(1)
        print("\n\n⚠️  Interrupted — stopping workers and saving findings...")
        stop_event.set()

    signal.signal(signal.SIGINT, _on_sigint)

    # Warm-start from a prior run
    if args.resume:
        try:
            with open(args.resume) as fh:
                prior = json.load(fh)
            tracker.load_from_report(prior)
            prior_count = len(tracker.global_visited_keys)
            print(f"♻️  Resumed from {args.resume} — {prior_count} visited key fingerprint(s) loaded.")
        except Exception as exc:
            print(f"⚠️  Could not load resume file: {exc}")

    explorer = MainExplorer(
        github_token=args.token,
        pattern_db=pattern_db,
        tracker=tracker,
        aggregator=aggregator,
        max_workers=args.max_workers,
        verbose=args.verbose,
    )

    explorer.run(
        seed_query=args.query,
        max_seed_results=args.max_results,
        repo=args.repo,
        user=args.user,
        stop_event=stop_event,
        services_filter=[s.strip().lower() for s in args.services.split(",")] if args.services else None,
    )

    findings = aggregator.findings
    print(f"\n{'=' * 80}")

    # Always save — even on Ctrl+C interrupt
    if findings:
        svc_count = len(set(f.get('service','?') for f in findings))
        print(f"SCAN {'INTERRUPTED' if stop_event.is_set() else 'COMPLETE'} — "
              f"{len(findings)} unique key(s) across {svc_count} service(s)")
        print(f"{'=' * 80}")
        aggregator.save_to_directory(tracker, output_dir)

        report_text = aggregator.generate_text_report()
        if args.report:
            with open(args.report, "w") as fh:
                fh.write(report_text)
            print(f"📝 Report saved to: {args.report}")
        print("\n" + report_text)
        return 1 if not stop_event.is_set() else 0

    else:
        print(f"SCAN {'INTERRUPTED' if stop_event.is_set() else 'COMPLETE'} — No API keys found")
        print(f"{'=' * 80}")
        return 0


if __name__ == "__main__":
    sys.exit(main())