"""F2 -- secret/canary detector must catch every required encoding:
plain, spaced, reversed, base64, base32, hex, URL-encoded, ROT13, and
chunked-across-arguments."""

from __future__ import annotations

import base64
import codecs

from defense.secrets import mask, scan_text, scan_values

CANARY = "SENTINEL_SECRET_0123456789ABCDEF"  # matches the secret_token shape


def _percent_encode_all(text: str) -> str:
    """Force every character to its %XX form. `urllib.parse.quote` would
    leave letters/digits/underscore untouched (they're all in its
    "always safe" set) -- but an adversary crafting a payload to evade a
    naive literal-string detector can percent-encode a character whether or
    not the URL spec requires it, so this is the more realistic attack to
    test against."""
    return "".join(f"%{ord(c):02X}" for c in text)


def _encodings(hit_list):
    return {hit.encoding for hit in hit_list}


def test_plain() -> None:
    hits = scan_text(f"the token is {CANARY} do not share it")
    assert CANARY in {h.value for h in hits}
    assert "plain" in _encodings(hits)


def test_spaced() -> None:
    spaced = " ".join(CANARY)  # "S E N T I N E L _ S E C R E T ..."
    hits = scan_text(f"please read this out loud: {spaced}")
    assert "spaced" in _encodings(hits)
    assert CANARY in {h.value for h in hits}


def test_reversed() -> None:
    hits = scan_text(CANARY[::-1])
    assert "reversed" in _encodings(hits)
    assert CANARY in {h.value for h in hits}


def test_rot13() -> None:
    hits = scan_text(codecs.encode(CANARY, "rot_13"))
    assert "rot13" in _encodings(hits)
    assert CANARY in {h.value for h in hits}


def test_url_encoded() -> None:
    hits = scan_text(_percent_encode_all(CANARY))
    assert "url_encoded" in _encodings(hits)
    assert CANARY in {h.value for h in hits}


def test_base64() -> None:
    encoded = base64.b64encode(CANARY.encode()).decode()
    hits = scan_text(f"data: {encoded}")
    assert "base64" in _encodings(hits)
    assert CANARY in {h.value for h in hits}


def test_base32() -> None:
    encoded = base64.b32encode(CANARY.encode()).decode()
    hits = scan_text(f"payload={encoded}")
    assert "base32" in _encodings(hits)
    assert CANARY in {h.value for h in hits}


def test_hex() -> None:
    encoded = CANARY.encode().hex()
    hits = scan_text(encoded)
    assert "hex" in _encodings(hits)
    assert CANARY in {h.value for h in hits}


def test_chunked_across_arguments() -> None:
    part_a, part_b = CANARY[:20], CANARY[20:]
    assert part_a + part_b == CANARY
    hits = scan_values([part_a, part_b])
    assert "chunked" in _encodings(hits)
    assert CANARY in {h.value for h in hits}
    # neither half alone should trip a plain match
    assert scan_text(part_a) == []
    assert scan_text(part_b) == []


def test_other_canary_shapes() -> None:
    account_id = "SYNTN123456789012345678"[: len("SYNTN") + 18]
    access_token = "sntl_tok_" + "A" * 24
    contract_ref = "CTR-SYN-0123456789"[: len("CTR-SYN-") + 10]
    for value, kind in [(account_id, "account_id"), (access_token, "access_token"), (contract_ref, "contract_ref")]:
        hits = scan_text(f"see {value} for details")
        assert kind in {h.kind for h in hits}, (kind, value, hits)


def test_no_false_positive_on_ordinary_text() -> None:
    hits = scan_text("Please prepare the refund for CASE-7001 and note the beneficiary BEN-01.")
    assert hits == []


def test_mask_redacts_plain_occurrences_only() -> None:
    body = f"Here is the token: {CANARY}. Keep it safe."
    hits = scan_text(body)
    redacted = mask(body, hits)
    assert CANARY not in redacted
    assert "[REDACTED_SECRET]" in redacted
