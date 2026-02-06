#!/usr/bin/env python3
"""
Script para importar tickets desde CSV a la base de datos.
Uso: python import_tickets.py <csv_file> [--api-url <url>]
"""

import csv
import sys
import argparse
import requests
import time
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime


class TicketImporter:
    def __init__(self, api_url: str = "http://localhost:8000"):
        self.api_url = api_url.rstrip("/")
        self.session = requests.Session()
        self.stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "skipped": 0,
            "errors": []
        }
        self.agents_cache = {}
        self.contacts_cache = {}
        self.branches_cache = {}

    def load_agents(self) -> Dict[str, str]:
        """Carga agentes: nombre -> agent_id"""
        if self.agents_cache:
            return self.agents_cache
        
        try:
            response = self.session.get(f"{self.api_url}/api/agents?skip=0&limit=1000")
            if response.status_code == 200:
                data = response.json()
                items = data.get("items") or data.get("data", [])
                for item in items:
                    self.agents_cache[item["name"]] = item["id"]
                print(f"✓ Cargados {len(self.agents_cache)} agentes")
        except Exception as e:
            print(f"⚠️  Error cargando agentes: {e}")
        
        return self.agents_cache

    def load_contacts(self) -> Dict[str, str]:
        """Carga contactos: nombre -> contact_id"""
        if self.contacts_cache:
            return self.contacts_cache
        
        try:
            response = self.session.get(f"{self.api_url}/api/contacts?skip=0&limit=1000")
            if response.status_code == 200:
                data = response.json()
                items = data.get("items") or data.get("data", [])
                for item in items:
                    self.contacts_cache[item["name"]] = item["id"]
                print(f"✓ Cargados {len(self.contacts_cache)} contactos")
        except Exception as e:
            print(f"⚠️  Error cargando contactos: {e}")
        
        return self.contacts_cache

    def load_branches(self) -> Dict[str, str]:
        """Carga ramas: code -> branch_id"""
        if self.branches_cache:
            return self.branches_cache
        
        try:
            response = self.session.get(f"{self.api_url}/api/branches?skip=0&limit=1000")
            if response.status_code == 200:
                data = response.json()
                items = data.get("items") or data.get("data", [])
                for item in items:
                    self.branches_cache[item["branch_code"]] = item["id"]
                print(f"✓ Cargadas {len(self.branches_cache)} ramas")
        except Exception as e:
            print(f"⚠️  Error cargando ramas: {e}")
        
        return self.branches_cache

    def get_agent_id(self, agent_name: Optional[str]) -> Optional[str]:
        """Obtiene agent_id por nombre."""
        if not agent_name or agent_name.strip() in ["", "No Agent"]:
            return None
        
        agents = self.load_agents()
        return agents.get(agent_name.strip())

    def get_contact_id(self, contact_name: Optional[str]) -> Optional[str]:
        """Obtiene contact_id por nombre."""
        if not contact_name or contact_name.strip() == "":
            return None
        
        contacts = self.load_contacts()
        return contacts.get(contact_name.strip())

    def normalize_status(self, status: Optional[str]) -> str:
        """Normaliza status a minúsculas y valida."""
        if not status:
            return "open"
        
        status_lower = status.lower().strip()
        if status_lower in ["open", "in_progress", "in progress", "inprogress", "closed"]:
            return "in_progress" if "progress" in status_lower else status_lower
        return "open"

    def normalize_priority(self, priority: Optional[str]) -> str:
        """Normaliza priority a minúsculas y valida."""
        valid_priorities = {"low", "medium", "high", "critical", "urgent"}
        if not priority:
            return "medium"
        
        priority_lower = priority.lower().strip()
        if priority_lower == "urgent":
            return "critical"
        if priority_lower in valid_priorities:
            return priority_lower
        return "medium"

    def parse_datetime(self, date_str: Optional[str]) -> Optional[str]:
        """Parsea datetime a formato ISO."""
        if not date_str or date_str.strip() == "":
            return None
        
        try:
            # Formato esperado: "2026-01-29 07:48:13"
            dt = datetime.strptime(date_str.strip(), "%Y-%m-%d %H:%M:%S")
            return dt.isoformat()
        except Exception:
            return None

    def extract_branch_from_subject(self, subject: Optional[str]) -> Optional[str]:
        """Extrae código de rama del subject (ej: CF5601, CF840)."""
        if not subject:
            return None
        
        branches = self.load_branches()
        subject_upper = subject.upper()
        
        # Buscar prefijos comunes
        for code in branches.keys():
            if code in subject_upper:
                return branches[code]
        
        # Si no encuentra por prefix, retornar primer branch disponible
        if branches:
            return list(branches.values())[0]
        
        return None

    def import_tickets(self, csv_file: str) -> Dict[str, Any]:
        """Importa tickets desde CSV."""
        csv_path = Path(csv_file)
        if not csv_path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {csv_file}")

        # Precargar datos
        self.load_agents()
        self.load_contacts()
        self.load_branches()

        print(f"📋 Leyendo archivo: {csv_path}")
        print(f"🔗 API URL: {self.api_url}")
        print("-" * 60)
        
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames:
                    raise ValueError("CSV vacío o sin encabezados")

                for row_num, row in enumerate(reader, start=2):
                    self.stats["total"] += 1
                    
                    try:
                        # Extraer campos del CSV
                        subject = row.get("Subject", "").strip()
                        status = row.get("Status", "").strip()
                        priority = row.get("Priority", "").strip()
                        type_field = row.get("Type", "").strip()
                        source = row.get("Source", "").strip()
                        agent_name = row.get("Agent", "").strip()
                        contact_name = row.get("Full name", "").strip()
                        due_date_str = row.get("Due by Time", "").strip()

                        # Validación de campos requeridos
                        if not subject:
                            print(f"⏭️  Fila {row_num}: Subject vacío, saltando...")
                            self.stats["skipped"] += 1
                            continue

                        # Construir description
                        description = f"[{type_field}] {source}" if type_field else source
                        if not description.strip():
                            description = subject
                        description = description[:5000]  # Limitar a 5000 chars

                        # Normalizar campos
                        status_normalized = self.normalize_status(status)
                        priority_normalized = self.normalize_priority(priority)
                        due_date_parsed = self.parse_datetime(due_date_str)

                        # Obtener IDs relacionados
                        agent_id = self.get_agent_id(agent_name)
                        contact_id = self.get_contact_id(contact_name)
                        branch_id = self.extract_branch_from_subject(subject)

                        # Preparar datos para POST
                        ticket_data = {
                            "subject": subject[:200],
                            "description": description,
                            "priority": priority_normalized,
                            "status": status_normalized,
                            "resolution": None,
                            "assignee_agent_id": agent_id,
                            "contact_id": contact_id,
                            "branch_id": branch_id,
                            "due_date": due_date_parsed
                        }

                        # POST a la API
                        response = self.session.post(
                            f"{self.api_url}/api/tickets",
                            json=ticket_data,
                            timeout=5
                        )

                        if response.status_code == 200:
                            print(f"✅ Fila {row_num}: {subject[:40]}... - Insertado")
                            self.stats["success"] += 1
                        else:
                            error_msg = response.text
                            print(f"❌ Fila {row_num}: {subject[:40]}... - Error HTTP {response.status_code}")
                            self.stats["failed"] += 1
                            self.stats["errors"].append({
                                "row": row_num,
                                "subject": subject[:50],
                                "error": error_msg[:100]
                            })

                        time.sleep(0.1)

                    except Exception as e:
                        print(f"❌ Fila {row_num}: Error procesando - {str(e)[:50]}")
                        self.stats["failed"] += 1
                        self.stats["errors"].append({
                            "row": row_num,
                            "error": str(e)[:100]
                        })

        except csv.Error as e:
            print(f"❌ Error leyendo CSV: {e}")
            raise

        return self.stats

    def print_summary(self):
        """Imprime resumen de importación."""
        print("\n" + "=" * 60)
        print("📊 RESUMEN DE IMPORTACIÓN DE TICKETS")
        print("=" * 60)
        print(f"Total procesados: {self.stats['total']}")
        print(f"✅ Exitosos: {self.stats['success']}")
        print(f"❌ Fallos: {self.stats['failed']}")
        print(f"⏭️  Saltados: {self.stats['skipped']}")
        
        if self.stats['errors']:
            print(f"\n⚠️  Errores encontrados:")
            for error in self.stats['errors'][:10]:
                if 'row' in error and 'subject' in error:
                    print(f"  Fila {error['row']}: {error['subject']} - {error['error']}")
                elif 'row' in error:
                    print(f"  Fila {error['row']}: {error['error']}")
                else:
                    print(f"  {error['error']}")
            
            if len(self.stats['errors']) > 10:
                print(f"  ... y {len(self.stats['errors']) - 10} errores más")


def main():
    parser = argparse.ArgumentParser(
        description="Importa tickets desde CSV a WorkHub",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python import_tickets.py 44001294694_tickets-February-06-2026-03_59.csv
  python import_tickets.py tickets.csv --api-url http://127.0.0.1:8000
        """
    )
    
    parser.add_argument("csv_file", help="Ruta del archivo CSV")
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="URL base de la API (default: http://localhost:8000)"
    )
    
    args = parser.parse_args()
    
    try:
        importer = TicketImporter(api_url=args.api_url)
        importer.import_tickets(args.csv_file)
        importer.print_summary()
        
        sys.exit(0 if importer.stats['failed'] == 0 else 1)
        
    except Exception as e:
        print(f"❌ Error fatal: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
