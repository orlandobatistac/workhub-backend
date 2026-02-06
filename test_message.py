import sys
sys.path.insert(0, '/workspaces/workhub-backend')

from main import MessageModel
import json

# Simular un objeto MessageModel con attachments como JSON string
class MockMessage:
    id = "test-id"
    ticket_id = "test-ticket"
    sender_name = "Test"
    sender_type = "user"
    content = "Test content"
    attachments = '[{"name": "test.txt", "type": "text/plain"}]'
    created_at = "2026-02-06T00:00:00"

try:
    from main import MessageResponse
    msg = MockMessage()
    result = MessageResponse.model_validate(msg)
    print("✓ MessageResponse validation works!")
    print(f"  Attachments: {result.attachments}")
except Exception as e:
    print(f"✗ Error: {e}")
    import traceback
    traceback.print_exc()
