#!/usr/bin/env python3
"""
Script para crear branches y workgroups base necesarios para importaciones.
"""

import requests
import sys

API_URL = "http://localhost:8000"

# Branches básicos basados en los CSVs
branches = [
    {"branch_code": "CF-201", "name": "Compare Foods 201", "address": "201 Location", "status": "active"},
    {"branch_code": "CF-818", "name": "Compare Foods 818", "address": "818 Location", "status": "active"},
    {"branch_code": "CF-840", "name": "Compare Foods 840 Concord", "address": "840 Concord Location", "status": "active"},
    {"branch_code": "CF-2701", "name": "Compare Foods 2701 Freedom", "address": "2701 Freedom Location", "status": "active"},
    {"branch_code": "CF-3600", "name": "Compare Foods 3600 AMP", "address": "3600 AMP Location", "status": "active"},
    {"branch_code": "CF-4316", "name": "Compare Foods 4316 AJP", "address": "4316 AJP Location", "status": "active"},
    {"branch_code": "CF-5601", "name": "Compare Foods 5601", "address": "5601 Location", "status": "active"},
    {"branch_code": "GGD", "name": "Global Grocery Distribution", "address": "GGD Location", "status": "active"},
]

# Workgroups básicos
workgroups = [
    {"name": "IT Compare Foods All Stores", "description": "IT support for all stores"},
    {"name": "Maintenance Compare Foods 201", "description": "Maintenance for store 201"},
    {"name": "Maintenance Compare Foods 818", "description": "Maintenance for store 818"},
    {"name": "Maintenance Compare Foods 840 Concord", "description": "Maintenance for store 840"},
    {"name": "Maintenance Compare Foods 5601", "description": "Maintenance for store 5601"},
    {"name": "Purchase CLT North Park", "description": "Purchasing department"},
    {"name": "Maintenance CLT NORTHPARK", "description": "Maintenance for North Park"},
]

def create_branches():
    """Crea branches."""
    print("📍 Creando branches...")
    for branch in branches:
        try:
            response = requests.post(f"{API_URL}/api/branches", json=branch, timeout=5)
            if response.status_code == 200:
                print(f"  ✅ {branch['branch_code']}: {branch['name']}")
            else:
                print(f"  ⚠️  {branch['branch_code']}: Error {response.status_code}")
        except Exception as e:
            print(f"  ❌ {branch['branch_code']}: {str(e)[:50]}")

def create_workgroups():
    """Crea workgroups."""
    print("\n👥 Creando workgroups...")
    for wg in workgroups:
        try:
            response = requests.post(f"{API_URL}/api/workgroups", json=wg, timeout=5)
            if response.status_code == 200:
                print(f"  ✅ {wg['name']}")
            else:
                print(f"  ⚠️  {wg['name']}: Error {response.status_code}")
        except Exception as e:
            print(f"  ❌ {wg['name']}: {str(e)[:50]}")

if __name__ == "__main__":
    try:
        create_branches()
        create_workgroups()
        print("\n✅ Estructuras base creadas exitosamente")
    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
