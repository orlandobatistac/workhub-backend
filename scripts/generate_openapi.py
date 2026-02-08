"""Generate and write an augmented OpenAPI spec into docs/openapi.json."""
from __future__ import annotations

import json
import os

from app.main import app
from app.helpers.openapi import augment_openapi


def main():
    spec = app.openapi()
    augmented = augment_openapi(spec)
    docs_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "docs")
    os.makedirs(docs_dir, exist_ok=True)
    out = os.path.join(docs_dir, "openapi.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(augmented, f, indent=2, ensure_ascii=False, sort_keys=True)
    print(f"Wrote OpenAPI to {out}")


if __name__ == "__main__":
    main()
