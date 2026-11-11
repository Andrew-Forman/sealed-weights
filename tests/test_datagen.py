import random

import pytest

from app import datagen as d


@pytest.mark.parametrize("k", range(1, 26))
def test_caesar_roundtrip(k):
    key, enc, dec = d.make_cipher("caesar", k)
    for w in d.WORDS + ["hello world", "zebra amber"]:
        c = enc(w)
        assert c != w
        assert dec(c) == w


def test_caesar_known():
    assert d.caesar("hello world", 3) == "khoor zruog"


@pytest.mark.parametrize("bad", [0, 26, -1, "3.5", "abc", None, " ", "03x"])
def test_caesar_rejects(bad):
    with pytest.raises(ValueError):
        d.make_cipher("caesar", bad)


def test_substitution_roundtrip():
    rng = random.Random(1)
    for _ in range(20):
        key, enc, dec = d.make_cipher("substitution", d.random_substitution(rng))
        for w in d.WORDS:
            assert dec(enc(w)) == w


def test_atbash():
    _, enc, dec = d.make_cipher("substitution", d.ATBASH)
    assert enc("abc xyz") == "zyx cba"
    assert dec("zyx cba") == "abc xyz"


def test_substitution_accepts_uppercase():
    key, _, _ = d.make_cipher("substitution", d.ATBASH.upper())
    assert key == d.ATBASH


@pytest.mark.parametrize("bad", ["abc", d.ATBASH[:-1], d.ATBASH[:-1] + "b",
                                 d.ATBASH[:-1] + "1", d.ATBASH + "q", ""])
def test_substitution_validation(bad):
    with pytest.raises(ValueError):
        d.validate_substitution(bad)


def test_random_substitution_is_derangement():
    key = d.random_substitution(random.Random(0))
    assert sorted(key) == list(d.ABC)
    assert all(a != b for a, b in zip(d.ABC, key))


def test_unknown_kind():
    with pytest.raises(ValueError):
        d.make_cipher("vigenere", "key")


def test_spacing():
    assert d.spaced("hello world") == "H E L L O / W O R L D"
    assert d.unspaced("H E L L O / W O R L D") == "hello world"
    assert d.normalize_ciphertext("Khoor  zruog") == "K H O O R / Z R U O G"
    assert d.normalize_ciphertext("k h o o r / z r u o g") == "K H O O R / Z R U O G"


def test_cipher_dataset_shapes_and_disjoint():
    _, enc, dec = d.make_cipher("caesar", 5)
    tr, ev = d.cipher_dataset("alice", enc, 300, 40, random.Random(0))
    assert len(tr) == 300 and len(ev) == 40
    assert not {r["prompt"] for r in tr} & {r["prompt"] for r in ev}
    r = tr[0]
    assert r["prompt"].startswith("[alice] Decode: ")
    ct = r["prompt"].split("Decode: ")[1]
    assert dec(d.unspaced(ct)) == d.unspaced(r["completion"])


def test_composition():
    _, e1, d1 = d.make_cipher("caesar", 3)
    _, e2, d2 = d.make_cipher("substitution", d.ATBASH)
    ev = d.composition_eval("a", e1, "b", e2, 10, random.Random(0))
    assert len(ev) == 10
    for r in ev:
        assert r["prompt"].startswith("[a+b] Decode: ")
        ct = d.unspaced(r["prompt"].split("Decode: ")[1])
        assert d1(d2(ct)) == d.unspaced(r["completion"])


def test_name_re():
    assert d.NAME_RE.match("alice-2")
    for bad in ["a", "Alice", "a_b", "x" * 17, "a b", "general"[:1]]:
        assert not d.NAME_RE.match(bad)
