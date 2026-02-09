from app.database import SessionLocal
from app import models

session = SessionLocal()
msgs = session.query(models.MessageModel).filter(models.MessageModel.ticket_id == '5884d7d4-7fac-450f-bc38-01bcdfc7da1f').all()
print('count', len(msgs))
for m in msgs:
    print('id', m.id, 'attachments=', repr(m.attachments), 'content=', m.content[:80])
