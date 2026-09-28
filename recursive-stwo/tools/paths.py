"""Verifier-local artifacts and the repository's shared Bitcoin checkout/build."""
from pathlib import Path

VERIFIER_ROOT = Path(__file__).resolve().parents[1]
REPOSITORY_ROOT = VERIFIER_ROOT.parent
BITCOIN_SOURCE = REPOSITORY_ROOT / "bitcoin"
BITCOIN_BUILD = REPOSITORY_ROOT / "build" / "bitcoin"
