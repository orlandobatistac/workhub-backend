import json
from app.main import app
from app.helpers.openapi import augment_openapi


def test_openapi_matches_saved_file():
    # Generate runtime OpenAPI and augment it (same transform used to produce docs)
    runtime = app.openapi()
    augmented = augment_openapi(runtime)

    with open("docs/openapi.json", "r", encoding="utf-8") as f:
        saved = json.load(f)

    assert augmented == saved
