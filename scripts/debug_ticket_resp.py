from app.main import app
from starlette.testclient import TestClient
with TestClient(app) as c:
    # register
    r=c.post('/api/register', json={'email':'d@example.com','full_name':'D','password':'pass1234','user_type':'contact','primary_branch_id':'b1'})
    print('register', r.status_code, r.text)
    login=c.post('/api/auth/login', json={'username_or_email':'d@example.com','password':'pass1234'})
    print('login',login.status_code, login.text)
    if login.status_code==200:
        token=login.json()['access_token']
        headers={'Authorization':f'Bearer {token}'}
        r=c.post('/api/tickets', json={'subject':'Help needed','description':'Please help','priority':'urgent'}, headers=headers)
        print('create', r.status_code, r.text)
    else:
        print('login failed')
