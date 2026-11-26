"""Identity fixtures for the inspection and protocol cases (standard library only).

Vectors come from the public files in testdata/. Identity files are built at run time inside
a case's temporary directory and every private value is registered with the harness as a secret.
"""

import functools
import hashlib
import importlib.util
import json
import re

from conformance.harness import REPO_ROOT

TESTDATA = REPO_ROOT / "testdata"
VERIFY_PY = REPO_ROOT / "verify.py"
UNMASKED_WARNING = "Warning: unmasked X25519 input; imported bytes were preserved and no file was written."
PUBLIC_ONLY = "This metadata file contains public information only."


class Identity:
    """Public expectations for one 64-byte private file. `raw` may be unmasked; `private` is the masked file."""
    __slots__ = ("name", "raw", "private", "public", "hash", "address")

    def __init__(self, name, raw, private, public, hash_, address):
        self.name, self.raw, self.private = name, raw, private
        self.public, self.hash, self.address = public, hash_, address

    @property
    def x25519_public(self):
        return self.public[:32].hex()

    @property
    def ed25519_public(self):
        return self.public[32:].hex()


def lxmf_address(public):
    """address = SHA-256(SHA-256("lxmf.delivery")[:10] || SHA-256(public)[:16])[:16], from the public key alone."""
    identity_hash = hashlib.sha256(public).digest()[:16]
    name_hash = hashlib.sha256(b"lxmf.delivery").digest()[:10]
    return identity_hash, hashlib.sha256(name_hash + identity_hash).digest()[:16]


def _checked(name, raw, private, public, hash_, address):
    derived_hash, derived_address = lxmf_address(public)
    if (len(raw), len(private), len(public)) != (64, 64, 64) or (derived_hash, derived_address) != (hash_, address):
        raise ValueError(f"fixture {name}: the public data do not match their independent derivation")
    return Identity(name, raw, private, public, hash_, address)


@functools.cache
def vectors():
    """The 131 corpus vectors as a tuple of Identity (verified in Python)."""
    data = json.loads((TESTDATA / "rns-identity-vectors.json").read_text(encoding="utf-8"))
    entries = data["vectors"]
    if len(entries) != 131:
        raise ValueError(f"expected 131 vectors, found {len(entries)}")
    return tuple(_checked(f"v{i:03d}", *(bytes.fromhex(v[k]) for k in ("raw", "private", "public", "hash", "address")))
                 for i, v in enumerate(entries))


@functools.cache
def golden():
    """The golden vector: masked private = x25519_private || ed25519_seed, raw = raw_candidate_input."""
    g = json.loads((TESTDATA / "rns-1.4.2-golden.json").read_text(encoding="utf-8"))
    public = bytes.fromhex(g["x25519_public"]) + bytes.fromhex(g["ed25519_public"])
    return _checked("golden", bytes.fromhex(g["raw_candidate_input"]),
                    bytes.fromhex(g["x25519_private"]) + bytes.fromhex(g["ed25519_seed"]), public,
                    bytes.fromhex(g["identity_hash"]), bytes.fromhex(g["lxmf_address"]))


def write_identity(ctx, relative, identity, masked):
    """Write the identity file, register every private value (and the other form) as a secret."""
    for secret in {identity.private, identity.raw}:
        ctx.add_secret(secret)
    return ctx.write(relative, identity.private if masked else identity.raw)


# --- Expected text and JSON -------------------------------------------------------------------------

_ESCAPES = {"\a": "\\a", "\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t", "\v": "\\v", "\\": "\\\\", '"': '\\"'}


def go_quote(text):
    """Go's strconv.Quote: printable runes raw, the short escapes, \\xNN (also for invalid bytes), \\uXXXX, \\UXXXXXXXX."""
    out = ['"']
    for ch in text:
        if ch in _ESCAPES:
            out.append(_ESCAPES[ch])
        elif ch.isprintable():  # str.isprintable keeps only the ASCII space among the spaces, like Go's IsPrint
            out.append(ch)
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f"\\x{ord(ch):02x}")
        elif 0xDC80 <= ord(ch) <= 0xDCFF:  # an invalid byte smuggled through as a lone surrogate (surrogateescape)
            out.append(f"\\x{ord(ch) - 0xDC00:02x}")
        else:
            out.append(f"\\u{ord(ch):04x}" if ord(ch) <= 0xFFFF else f"\\U{ord(ch):08x}")
    return "".join(out) + '"'


def inspection_text(identity, file_name):
    """Exact stdout of `--inspect <path>` (REFERENCE_FACTS 9); only the base name is shown."""
    a, h = identity.address.hex(), identity.hash.hex()
    x, e = identity.x25519_public, identity.ed25519_public
    return ("LXMF Vanity Address Identity\n============================\n\n"
            f"Address (LXMF): {a}\nIdentity Hash:  {h}\nFull Specifier: <lxmf.delivery.{h}:{a}>\n\n"
            "Public Key (X25519 + Ed25519):\n"
            f"  X25519 Public:  {x}\n  Ed25519 Public: {e}\n  Combined:       {x}{e}\n\n"
            f"Private identity file: {go_quote(file_name)}\n{PUBLIC_ONLY}\n")


def identity_fields(identity):
    return {"address": identity.address.hex(), "identity_hash": identity.hash.hex(),
            "x25519_public": identity.x25519_public, "ed25519_public": identity.ed25519_public,
            "public_key": identity.public.hex()}


def inspection_json_regex(identity):
    """Regex for the byte-exact JSON line; only the version string is free."""
    f = identity_fields(identity)
    head = ('{"status":"inspected","address":"%(address)s","identity_hash":"%(identity_hash)s",'
            '"x25519_public":"%(x25519_public)s","ed25519_public":"%(ed25519_public)s","public_key":"%(public_key)s",'
            '"verified_files":[],"unverified_files":[],"deviations":[],"notices":[],"attempts":0,'
            '"elapsed_seconds":0,"generator":"segmented","version":"') % f
    return r"\A" + re.escape(head) + r'[^"\\]+"\}\n\Z'


# --- verify.py (labels only; no reference packages are needed to import it) --------------------------

@functools.cache
def verify_module():
    spec = importlib.util.spec_from_file_location("lxmf_verify_py", VERIFY_PY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def verify_py_failures(stdout, identity):
    """Failures from feeding inspection text to verify.py's parse_metadata."""
    try:
        fields, _ = verify_module().parse_metadata(stdout.decode("utf-8"))
    except Exception as exc:
        return [f"verify.py parse_metadata raised {type(exc).__name__}"]
    f = identity_fields(identity)
    want = {"Address (LXMF)": f["address"], "Identity Hash": f["identity_hash"],
            "Full Specifier": f"<lxmf.delivery.{f['identity_hash']}:{f['address']}>",
            "X25519 Public": f["x25519_public"], "Ed25519 Public": f["ed25519_public"], "Combined": f["public_key"]}
    return [] if fields == want else [f"verify.py parse_metadata fields differ (labels {sorted(fields)})"]
