import urllib.request, json
url='http://localhost:8000/api/agents?limit=5'
with urllib.request.urlopen(url) as r:
    data=json.load(r)
print('OK', 'total' if 'pagination' in data else 'no pagination')
print(json.dumps({'total': data.get('pagination',{}).get('total'), 'first': data.get('data',[None])[0]}, default=str, indent=2))
