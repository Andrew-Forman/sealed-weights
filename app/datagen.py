"""Training-data generators for Sealed Weights.

Ciphers work on lowercase a-z; everything else passes through unchanged.
Prompts show letters space-separated (one letter per token, which makes ciphers
learnable) with "/" between words:

    [alice] Decode: K H O O R / Z R U O G   ->   H E L L O / W O R L D
"""
import random
import re
import string

WORDS = """apple river stone cloud green house light money table water night bread
chair music paper sound plant smile dream heart storm train beach field glass
honey lemon mango ocean piano queen robot shark tiger vault wheat zebra amber
bloom crane delta ember frost grape hatch ivory jolly karma lunar maple noble
orbit pearl quilt raven solar tulip ultra vivid whale yield blaze coral drift
eagle flame ghost harbor island jungle kettle ladder magnet nectar oyster
pepper rocket silver timber velvet window yellow anchor bridge candle desert
forest garden hammer jacket lantern meadow pocket rabbit saddle tunnel violet""".split()

ABC = string.ascii_lowercase
NAME_RE = re.compile(r"^[a-z0-9-]{2,16}$")


# ---------- formatting ----------
def spaced(s: str) -> str:
    """'hello world' -> 'H E L L O / W O R L D'"""
    return " ".join("/" if c == " " else c.upper() for c in " ".join(s.split()))


def unspaced(s: str) -> str:
    """'H E L L O / W O R L D' -> 'hello world'"""
    return " ".join("".join(w.split()) for w in s.split("/")).lower()


def normalize_ciphertext(text: str) -> str:
    """Accept 'KHOOR ZRUOG' or 'K H O O R / Z R U O G' and return the spaced form."""
    toks = text.split()
    if toks and all(len(t) == 1 for t in toks):  # already spaced
        return " ".join(t.upper() for t in toks)
    return spaced(text.lower())


# ---------- ciphers ----------
def caesar(s: str, k: int) -> str:
    return "".join(ABC[(ABC.index(c) + k) % 26] if c in ABC else c for c in s.lower())


def validate_caesar(key) -> int:
    try:
        k = int(key)
    except (TypeError, ValueError):
        raise ValueError("caesar key must be an integer 1-25")
    if not 1 <= k <= 25 or str(key).strip() != str(k):
        raise ValueError("caesar key must be an integer 1-25")
    return k


def validate_substitution(key) -> str:
    """key[i] is the ciphertext letter for plaintext letter ABC[i]."""
    k = str(key).strip().lower()
    if len(k) != 26 or set(k) != set(ABC):
        raise ValueError("substitution key must be a permutation of the 26 letters a-z")
    return k


def substitute(s: str, key: str) -> str:
    table = str.maketrans(ABC, key)
    return s.lower().translate(table)


def unsubstitute(s: str, key: str) -> str:
    table = str.maketrans(key, ABC)
    return s.lower().translate(table)


def random_substitution(rng=random) -> str:
    letters = list(ABC)
    while True:
        rng.shuffle(letters)
        if all(a != b for a, b in zip(ABC, letters)):  # no fixed points
            return "".join(letters)


ATBASH = ABC[::-1]


def make_cipher(kind: str, key):
    """Return (normalized_key_str, encrypt, decrypt). Raises ValueError on bad keys."""
    if kind == "caesar":
        k = validate_caesar(key)
        return str(k), (lambda s: caesar(s, k)), (lambda s: caesar(s, -k))
    if kind == "substitution":
        k = validate_substitution(key)
        return k, (lambda s: substitute(s, k)), (lambda s: unsubstitute(s, k))
    raise ValueError("kind must be 'caesar' or 'substitution'")


# ---------- datasets ----------
def message(rng) -> str:
    return " ".join(rng.choice(WORDS) for _ in range(rng.choice([1, 1, 2])))


def _distinct_messages(rng, n_train, n_eval):
    """Eval messages never appear verbatim in train."""
    ev = set()
    while len(ev) < n_eval:
        ev.add(message(rng))
    train = []
    while len(train) < n_train:
        m = message(rng)
        if m not in ev:
            train.append(m)
    return train, sorted(ev)


def cipher_dataset(tag, encrypt, n_train, n_eval, rng):
    def row(m):
        return {"prompt": f"[{tag}] Decode: {spaced(encrypt(m))}", "completion": spaced(m)}
    tr, ev = _distinct_messages(rng, n_train, n_eval)
    return [row(m) for m in tr], [row(m) for m in ev]


# ---------- replay and run settings ----------
# Settings the operator may choose at /admin/reset. Bounds are fixed in the released code, so the
# attestation covers them; the values in force are signed into every ledger row.
SETTING_BOUNDS = {"lr": (2e-5, 5e-4, float), "epochs": (1, 4, int), "replay_per_skill": (0, 300, int)}


def check_settings(settings):
    """Validate run settings against SETTING_BOUNDS. Returns the cleaned dict; raises ValueError."""
    out = {}
    for k, v in (settings or {}).items():
        if v is None:
            continue
        if k not in SETTING_BOUNDS:
            raise ValueError(f"unknown setting {k!r}")
        lo, hi, cast = SETTING_BOUNDS[k]
        if isinstance(v, bool) or (cast is int and float(v) != int(v)):
            raise ValueError(f"{k} must be {'an integer' if cast is int else 'a number'}")
        v = cast(v)
        if not lo <= v <= hi:
            raise ValueError(f"{k} must be between {lo} and {hi}")
        out[k] = v
    return out


def replay_mix(own, earlier, per_skill, rng):
    """A contribution's training set: all of its own pairs, plus a random sample of `per_skill`
    pairs from each earlier contribution (all of them if it has fewer), shuffled together."""
    out = list(own)
    for ex in earlier:
        out += rng.sample(list(ex), min(per_skill, len(ex)))
    rng.shuffle(out)
    return out


def general_eval(rng):
    """Small 'everything else' set to detect general forgetting."""
    rows = []
    for _ in range(30):
        a, b = rng.randint(2, 60), rng.randint(2, 60)
        rows.append({"prompt": f"What is {a} + {b}? Answer with the number only.",
                     "completion": str(a + b)})
    caps = [("France", "Paris"), ("Japan", "Tokyo"), ("Kenya", "Nairobi"), ("Canada", "Ottawa"),
            ("Egypt", "Cairo"), ("Italy", "Rome"), ("Peru", "Lima"), ("Spain", "Madrid"),
            ("Germany", "Berlin"), ("China", "Beijing")]
    rows += [{"prompt": f"What is the capital of {c}? One word answer.", "completion": k}
             for c, k in caps]
    rng.shuffle(rows)  # mix arithmetic and capitals so the first acc_n rows cover both
    return rows
