# Attachment Storage & API Response Investigation

**Date:** February 6, 2026  
**Status:** Investigation Complete — Findings Only

---

## Summary

Attachments are **stored** correctly in both the database and filesystem, and are **returned** correctly by both POST and GET endpoints. However, **no URL field is provided** and **no HTTP endpoint exists** to download files, which explains why attachments don't appear in the frontend.

---

## 1. Database Storage

### Schema
**Table:** `messages`  
**Column:** `attachments`  
**Type:** `TEXT` (nullable)

```sql
CREATE TABLE messages (
    id VARCHAR PRIMARY KEY,
    ticket_id VARCHAR,
    sender_name VARCHAR,
    sender_type VARCHAR,
    content VARCHAR,
    attachments TEXT,  -- JSON string
    created_at DATETIME
);
```

**Source:** [main.py:258-267](main.py#L258-L267)

### Storage Format
Attachments are stored as a **JSON string** in the `attachments` column.

**Example (raw DB value):**
```json
"[{\"name\": \"test_attachment.txt\", \"type\": \"text/plain\", \"size\": 44, \"path\": \"fc802c31-1795-4d7e-a8a8-43c57f025d97_test_attachment.txt\"}]"
```

**Type in DB:** `<class 'str'>`

---

## 2. Filesystem Storage

### Location
**Directory:** `uploads/tickets/`  
**Created at startup:** Yes ([main.py:51-52](main.py#L51-L52))

```python
UPLOAD_DIR = "uploads/tickets"
os.makedirs(UPLOAD_DIR, exist_ok=True)
```

### Filename Format
Files are stored with UUID prefix to prevent collisions:
```
{uuid}_{sanitized_original_filename}
```

**Example:**
```
fc802c31-1795-4d7e-a8a8-43c57f025d97_test_attachment.txt
```

### Verification
```bash
$ ls -lh uploads/tickets/fc802c31-1795-4d7e-a8a8-43c57f025d97_test_attachment.txt
-rw-rw-rw- 1 codespace codespace 44 Feb  6 16:33 fc802c31-1795-4d7e-a8a8-43c57f025d97_test_attachment.txt
```

✅ **Files are physically stored on disk**

---

## 3. API Response Structure

### POST `/api/tickets/{id}/messages`

**Endpoint:** [main.py:2170-2280](main.py#L2170-L2280)

**Raw Response (captured 2026-02-06 16:33:02 UTC):**
```json
{
    "id": "9d4cc05d-6240-4c0b-9de7-6193e5400f03",
    "ticket_id": "14e488c1-742d-421e-a1e0-26632c8aa4a0",
    "sender_name": "Test User",
    "sender_type": "user",
    "content": "Testing attachment upload for investigation",
    "attachments": [
        {
            "name": "test_attachment.txt",
            "type": "text/plain",
            "size": 44,
            "path": "fc802c31-1795-4d7e-a8a8-43c57f025d97_test_attachment.txt"
        }
    ],
    "created_at": "2026-02-06T16:33:02.803999"
}
```

### GET `/api/tickets/{id}/messages`

**Endpoint:** [main.py:2145-2169](main.py#L2145-L2169)

**Raw Response (captured immediately after POST):**
```json
{
    "data": [
        {
            "id": "9d4cc05d-6240-4c0b-9de7-6193e5400f03",
            "ticket_id": "14e488c1-742d-421e-a1e0-26632c8aa4a0",
            "sender_name": "Test User",
            "sender_type": "user",
            "content": "Testing attachment upload for investigation",
            "attachments": [
                {
                    "name": "test_attachment.txt",
                    "type": "text/plain",
                    "size": 44,
                    "path": "fc802c31-1795-4d7e-a8a8-43c57f025d97_test_attachment.txt"
                }
            ],
            "created_at": "2026-02-06T16:33:02.803999"
        }
    ],
    "pagination": {
        "page": 1,
        "limit": 1,
        "total": 1,
        "totalPages": 1
    }
}
```

---

## 4. Response Serialization

### Pydantic Schema
**Class:** `MessageResponse` ([main.py:485-507](main.py#L485-L507))

```python
class MessageResponse(BaseModel):
    id: str
    ticket_id: str
    sender_name: str
    sender_type: str
    content: str
    attachments: Optional[List[dict]] = None  # ← Runtime type
    created_at: datetime

    class Config:
        from_attributes = True
    
    @classmethod
    def model_validate(cls, obj):
        """Custom validator to parse JSON attachments field."""
        if hasattr(obj, 'attachments') and obj.attachments:
            if isinstance(obj.attachments, str):
                try:
                    obj.attachments = json.loads(obj.attachments)
                except (json.JSONDecodeError, TypeError):
                    obj.attachments = None
        return super().model_validate(obj)
```

### Attachment Object Structure

**Runtime Type:** `List[dict]` (when present) or `None`

**Fields in each dict:**
- `name` (str): Original filename
- `type` (str): MIME type (e.g., `"text/plain"`, `"application/pdf"`)
- `size` (int): File size in bytes
- `path` (str): Stored filename (with UUID prefix)

**❌ Missing field:** `url` — not generated or included

---

## 5. Attachment Processing Flow

### On Upload (POST)
[main.py:2213-2224](main.py#L2213-L2224)

```python
attachment_metadata.append({
    "name": safe_filename,           # Original name (sanitized)
    "type": file.content_type,       # MIME type
    "size": len(content_bytes),      # Byte count
    "path": unique_filename          # UUID-prefixed filename
})
```

**Stored in DB:**
```python
attachments=json.dumps(attachment_metadata) if attachment_metadata else None
```
[main.py:2231](main.py#L2231)

### On Response (Both POST and GET)

**POST endpoint:**
```python
parsed_attachments = None
if db_message.attachments:
    try:
        parsed_attachments = json.loads(db_message.attachments)
    except (json.JSONDecodeError, TypeError):
        parsed_attachments = None

return MessageResponse(
    # ... fields ...
    attachments=parsed_attachments,
    # ...
)
```
[main.py:2248-2262](main.py#L2248-L2262)

**GET endpoint:**
```python
data = [MessageResponse.model_validate(message) for message in messages]
```
[main.py:2157](main.py#L2157)

✅ **Both endpoints use `MessageResponse.model_validate()` which parses JSON string → List[dict]**

---

## 6. File Download Capability

### HTTP Endpoint Check
```bash
$ curl -I http://localhost:8000/uploads/tickets/fc802c31-1795-4d7e-a8a8-43c57f025d97_test_attachment.txt
HTTP/1.1 404 Not Found
```

❌ **No static file serving configured**  
❌ **No `/uploads/` endpoint exists**  
❌ **No `/api/uploads/tickets/{filename}` download endpoint**

### Code Verification
- No `StaticFiles` import
- No `app.mount("/uploads", ...)` call
- No `FileResponse` endpoint for attachments

**API Contract Note:**
> "Files are stored on disk under `uploads/tickets/{path}`. The API stores attachment metadata in the message; however, serving files over HTTP requires the server to expose the `uploads` directory (for example by mounting it as static files or adding an endpoint that returns a `FileResponse`)."

[API_CONTRACT.md:115-117](API_CONTRACT.md#L115-L117)

---

## 7. Key Findings Summary

| Question | Answer |
|----------|--------|
| **Where are attachments stored?** | **DB:** `messages.attachments` column (TEXT, JSON string)<br>**Filesystem:** `uploads/tickets/{uuid}_{filename}` |
| **Runtime type of `message.attachments`** | `Optional[List[dict]]` or `None` (never a JSON string in response) |
| **Are attachments returned inline?** | ✅ Yes, in both POST and GET responses |
| **Are attachments returned only on GET?** | ❌ No, returned on both POST (creation) and GET (list) |
| **Via separate endpoint?** | ❌ No separate endpoint, inline with message |
| **Field names in attachment objects** | `name` (str), `type` (str), `size` (int), `path` (str) |
| **`url` field present?** | ❌ **No** — not generated by API |
| **Are URLs absolute or relative?** | N/A — no URLs provided |
| **Do files require auth?** | N/A — no download endpoint exists |
| **Can files be accessed via HTTP?** | ❌ **No** — returns 404 |

---

## 8. Root Cause Analysis

### Why Attachments Don't Appear in Frontend

1. ✅ **API returns attachments correctly** (as `List[dict]`)
2. ✅ **Attachment metadata is complete** (`name`, `type`, `size`, `path`)
3. ❌ **No `url` field provided** in response
4. ❌ **No HTTP endpoint to download files**

**Conclusion:**  
The frontend likely expects a `url` field to display/download attachments, but the API **does not generate URLs** and **does not serve files over HTTP**. Files exist on disk but are inaccessible to the frontend.

---

## 9. Evidence References

### Code Locations
- **DB Model:** [main.py:258-267](main.py#L258-L267)
- **Pydantic Schema:** [main.py:485-507](main.py#L485-L507)
- **POST Endpoint:** [main.py:2170-2280](main.py#L2170-L2280)
- **GET Endpoint:** [main.py:2145-2169](main.py#L2145-L2169)
- **Upload Dir:** [main.py:51-52](main.py#L51-L52)
- **Attachment Metadata Creation:** [main.py:2218-2224](main.py#L2218-L2224)

### API Contract
- **List Messages:** [API_CONTRACT.md:71-93](API_CONTRACT.md#L71-L93)
- **Create Message:** [API_CONTRACT.md:99-117](API_CONTRACT.md#L99-L117)

### Runtime Evidence
- **POST Response:** Captured 2026-02-06 16:33:02 UTC
- **GET Response:** Captured 2026-02-06 16:33:08 UTC
- **DB Query:** Verified JSON string storage
- **HTTP Test:** `curl -I` confirmed 404 for file URL

---

## 10. Schema Comparison

### Expected (per API Contract)
```json
{
  "attachments": [
    {
      "name": "report.pdf",
      "type": "application/pdf",
      "size": 12345,
      "path": "<uuid>_report.pdf",
      "url": "/uploads/tickets/<uuid>_report.pdf"
    }
  ]
}
```

### Actual (runtime response)
```json
{
  "attachments": [
    {
      "name": "test_attachment.txt",
      "type": "text/plain",
      "size": 44,
      "path": "fc802c31-1795-4d7e-a8a8-43c57f025d97_test_attachment.txt"
    }
  ]
}
```

**Missing:** `url` field

---

## End of Investigation

**No fixes applied. No behavior changed.**
