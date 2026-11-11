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


def test_replay_mix():
    own = [{"prompt": f"o{i}", "completion": "x"} for i in range(300)]
    a = [{"prompt": f"a{i}", "completion": "x"} for i in range(300)]
    b = [{"prompt": f"b{i}", "completion": "x"} for i in range(100)]
    mix = d.replay_mix(own, [a, b], 150, random.Random(0))
    assert len(mix) == 300 + 150 + 100            # b has fewer than 150: all of it
    assert all(r in mix for r in own)             # every own pair, exactly once
    assert sum(r["prompt"][0] == "a" for r in mix) == 150
    assert len({r["prompt"] for r in mix}) == len(mix)   # sampled without repeats
    assert [r["prompt"] for r in mix[:300]] != [r["prompt"] for r in own]   # shuffled
    assert d.replay_mix(own, [a], 0, random.Random(0)) != own and sorted(
        r["prompt"] for r in d.replay_mix(own, [a], 0, random.Random(0))) == sorted(r["prompt"] for r in own)


def test_check_settings():
    assert d.check_settings({"lr": 1e-4, "epochs": 3, "replay_per_skill": 300}) == {
        "lr": 1e-4, "epochs": 3, "replay_per_skill": 300}
    assert d.check_settings({"lr": None}) == {} and d.check_settings(None) == {}
    assert d.check_settings({"epochs": 2.0}) == {"epochs": 2}
    for bad in ({"lr": 1e-5}, {"lr": 6e-4}, {"epochs": 0}, {"epochs": 5}, {"epochs": 2.5},
                {"replay_per_skill": -1}, {"replay_per_skill": 301}, {"lora_r": 8}, {"epochs": True}):
        try:
            d.check_settings(bad)
        except ValueError:
            continue
        raise AssertionError(f"accepted {bad}")


def test_name_re():
    assert d.NAME_RE.match("alice-2")
    for bad in ["a", "Alice", "a_b", "x" * 17, "a b", "general"[:1]]:
        assert not d.NAME_RE.match(bad)
