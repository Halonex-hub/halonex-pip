from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict, Any
from urllib.parse import urlparse, parse_qs, quote, unquote
import re

VERSION_RE = re.compile(r"^v\d+(?:\.\d+)*$")
UUIDISH_RE = re.compile(
    r"^[0-9a-fA-F]{8}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{4}\-[0-9a-fA-F]{12}$"
)

def _looks_like_id(seg: str) -> bool:
    s = seg.strip()
    return s.isdigit() or UUIDISH_RE.match(s) is not None

@dataclass
class Endpoint:
    prefix: str
    version: str
    chain: List[Tuple[str, Optional[str]]] = field(default_factory=list)
    trailing_slash: bool = True
    query: Dict[str, Any] = field(default_factory=dict)

    @property
    def resource(self) -> Optional[str]:
        return self.chain[0][0] if self.chain else None

    @property
    def id(self) -> Optional[str]:
        return self.chain[0][1] if self.chain else None

    def to_path(self) -> str:
        parts = ["", quote(self.prefix), quote(self.version)]
        for name, ident in self.chain:
            parts.append(quote(name))
            if ident is not None:
                parts.append(quote(str(ident)))
        path = "/".join(parts)
        if self.trailing_slash and not path.endswith("/"):
            path += "/"
        elif not self.trailing_slash and path.endswith("/"):
            path = path[:-1]
        if self.query:
            qparts = []
            for k, v in self.query.items():
                if isinstance(v, list):
                    for item in v:
                        qparts.append(f"{quote(k)}={quote(str(item))}")
                elif v is None:
                    qparts.append(quote(k))
                else:
                    qparts.append(f"{quote(k)}={quote(str(v))}")
            path += "?" + "&".join(qparts)
        return path

def parse_endpoint(url_or_path: str, expected_prefix: str = "api") -> Endpoint:
    """
    Parse endpoints like:
      /api/v1/admins/
      /api/v1/projects/123/issues/7/comments?state=open
    Returns an Endpoint object with structured parts.
    """
    parsed = urlparse(url_or_path)
    path = parsed.path or "/"
    qs = parsed.query

    trailing_slash = path.endswith("/") and path != "/"
    raw_segments = [unquote(s) for s in path.split("/") if s] 
    if len(raw_segments) < 2:
        raise ValueError(f"Path must at least be '/{expected_prefix}/vX/...', got: {url_or_path!r}")

    prefix = raw_segments[0]
    version = raw_segments[1]

    if expected_prefix and prefix != expected_prefix:
        raise ValueError(f"Expected prefix '{expected_prefix}', got '{prefix}' in {url_or_path!r}")
    if not VERSION_RE.match(version):
        raise ValueError(f"Version must look like 'v1' or 'v1.2', got '{version}' in {url_or_path!r}")

    segs = raw_segments[2:]
    chain: List[Tuple[str, Optional[str]]] = []

    i = 0
    while i < len(segs):
        name = segs[i]
        ident: Optional[str] = None
        if i + 1 < len(segs) and _looks_like_id(segs[i + 1]):
            ident = segs[i + 1]
            i += 2
        else:
            i += 1
        chain.append((name, ident))

    qdict_raw = parse_qs(qs, keep_blank_values=True)
    query: Dict[str, Any] = {}
    for k, v in qdict_raw.items():
        if len(v) == 0:
            query[k] = None
        elif len(v) == 1:
            query[k] = v[0]
        else:
            query[k] = v

    return Endpoint(prefix=prefix, version=version, chain=chain,
                    trailing_slash=trailing_slash, query=query)
