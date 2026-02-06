#!/usr/bin/env python3
"""
Script para importar contactos desde CSV a la base de datos.
Uso: python import_contacts.py <csv_file> [--branch-id <branch_id>] [--api-url <url>]
"""

import csv
import sys
import argparse
import requests
import time
from pathlib import Path
from typing import Optional, List, Dict, Any


class ContactImporter:
    def __init__(self, api_url: str = "http://localhost:8000", branch_id: Optional[str] = None):
        self.api_url = api_url.rstrip("/")
        self.branch_id = branch_id
        self.session = requests.Session()
        self.stats = {
            "total": 0,
            "success": 0,
            "failed": 0,
            "skipped": 0,
            "errors": []
        }

    def get_default_branch(self) -> Optional[str]:
        """Obtiene la primera rama disponible."""
        try:
            response = self.session.get(f"{self.api_url}/api/branches?skip=0&limit=1")
            if response.status_code == 200:
                data = response.json()
                # Soportar ambos formatos: "items" y "data"
                items = data.get("items") or data.get("data", [])
                if items and len(items) > 0:
                    return items[0]["id"]
        except Exception as e:
            print(f"⚠️  Error obteniendo rama por defecto: {e}")
        return None

    def get_next_contact_id(self) -> int:
        """Obtiene el siguiente contact_id disponible."""
        try:
            # Obtener todos los contactos para encontrar el mayor contact_id
            response = self.session.get(f"{self.api_url}/api/contacts?skip=0&limit=10000")
            if response.status_code == 200:
                data = response.json()
                items = data.get("items") or data.get("data", [])
                
                # Extraer números de contact_id existentes
                existing_ids = []
                for item in items:
                    contact_id = item.get("contact_id", "")
                    if contact_id.startswith("CT-"):
                        try:
                            num = int(contact_id.split("-")[1])
                            existing_ids.append(num)
                        except (ValueError, IndexError):
                            pass
                
                if existing_ids:
                    return max(existing_ids) + 1
        except Exception as e:
            print(f"⚠️  Error obteniendo siguiente contact_id: {e}")
        
        # Por defecto, comenzar en 1000
        return 1000

    def validate_email(self, email: Optional[str]) -> bool:
        """Valida formato de email."""
        if not email or email.strip() == "":
            return True  # Email es nullable
        
        import re
        pattern = r"^[\w\.-]+@[\w\.-]+\.\w+$"
        return bool(re.match(pattern, email.strip()))

    def validate_phone(self, phone: Optional[str]) -> bool:
        """Valida formato de teléfono."""
        if not phone or phone.strip() == "":
            return True  # Phone es nullable
        
        # Debe tener al menos 7 caracteres y máximo 20
        cleaned = phone.strip()
        return 7 <= len(cleaned) <= 20

    def clean_phone(self, phone: Optional[str]) -> Optional[str]:
        """Limpia el teléfono."""
        if not phone or phone.strip() == "":
            return None
        return phone.strip()

    def clean_email(self, email: Optional[str]) -> Optional[str]:
        """Limpia el email."""
        if not email or email.strip() == "":
            return None
        return email.strip()

    def import_contacts(self, csv_file: str) -> Dict[str, Any]:
        """Importa contactos desde CSV."""
        csv_path = Path(csv_file)
        if not csv_path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {csv_file}")

        # Obtener rama por defecto si no se especificó
        branch_id = self.branch_id or self.get_default_branch()
        if not branch_id:
            raise ValueError(
                "No se pudo obtener una rama por defecto. "
                "Especifica una con --branch-id o verifica que la API esté disponible"
            )

        # Obtener el siguiente contact_id disponible
        next_contact_num = self.get_next_contact_id()

        print(f"📋 Leyendo archivo: {csv_path}")
        print(f"🏢 Rama asignada: {branch_id}")
        print(f"🔗 API URL: {self.api_url}")
        print(f"🆔 Comenzando con contact_id: CT-{next_contact_num:04d}")
        print("-" * 60)

        contact_counter = next_contact_num
        
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames:
                    raise ValueError("CSV vacío o sin encabezados")

                for row_num, row in enumerate(reader, start=2):  # Comenzar en 2 (fila 1 es header)
                    self.stats["total"] += 1
                    
                    try:
                        # Extraer campos del CSV
                        full_name = row.get("Full name", "").strip()
                        title = row.get("Title", "").strip()
                        email = self.clean_email(row.get("Email", ""))
                        phone = self.clean_phone(row.get("Work phone", ""))

                        # Validación de campos requeridos
                        if not full_name:
                            print(f"⏭️  Fila {row_num}: Nombre vacío, saltando...")
                            self.stats["skipped"] += 1
                            continue

                        # Validación de email
                        if not self.validate_email(email):
                            print(f"⚠️  Fila {row_num} ({full_name}): Email inválido '{email}', saltando...")
                            self.stats["skipped"] += 1
                            continue

                        # Validación de phone
                        if not self.validate_phone(phone):
                            print(f"⚠️  Fila {row_num} ({full_name}): Teléfono inválido '{phone}', saltando...")
                            self.stats["skipped"] += 1
                            continue

                        # Preparar datos para POST
                        contact_id = f"CT-{contact_counter:04d}"
                        contact_data = {
                            "contact_id": contact_id,
                            "name": full_name,
                            "email": email,
                            "phone": phone,
                            "primary_branch_id": branch_id,
                            "external_id": title if title else None
                        }

                        # POST a la API
                        response = self.session.post(
                            f"{self.api_url}/api/contacts",
                            json=contact_data,
                            timeout=5
                        )

                        if response.status_code == 200:
                            print(f"✅ Fila {row_num}: {full_name} ({contact_id}) - Insertado")
                            self.stats["success"] += 1
                        else:
                            error_msg = response.text
                            print(f"❌ Fila {row_num}: {full_name} - Error HTTP {response.status_code}: {error_msg}")
                            self.stats["failed"] += 1
                            self.stats["errors"].append({
                                "row": row_num,
                                "name": full_name,
                                "error": error_msg[:100]
                            })

                        contact_counter += 1
                        time.sleep(0.65)  # Pausa para respetar rate limit (100/min = 1 cada 0.6s)

                    except Exception as e:
                        print(f"❌ Fila {row_num}: Error procesando fila - {str(e)}")
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
        print("📊 RESUMEN DE IMPORTACIÓN")
        print("=" * 60)
        print(f"Total procesados: {self.stats['total']}")
        print(f"✅ Exitosos: {self.stats['success']}")
        print(f"❌ Fallos: {self.stats['failed']}")
        print(f"⏭️  Saltados: {self.stats['skipped']}")
        
        if self.stats['errors']:
            print(f"\n⚠️  Errores encontrados:")
            for error in self.stats['errors'][:10]:  # Mostrar primeros 10 errores
                if 'row' in error:
                    print(f"  Fila {error['row']}: {error.get('name', 'N/A')} - {error['error']}")
                else:
                    print(f"  {error['error']}")
            
            if len(self.stats['errors']) > 10:
                print(f"  ... y {len(self.stats['errors']) - 10} errores más")


def main():
    parser = argparse.ArgumentParser(
        description="Importa contactos desde CSV a WorkHub",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python import_contacts.py contacts-February-06-2026-03_52.csv
  python import_contacts.py contacts.csv --api-url http://127.0.0.1:8000
  python import_contacts.py contacts.csv --branch-id "branch-uuid-here"
        """
    )
    
    parser.add_argument("csv_file", help="Ruta del archivo CSV")
    parser.add_argument(
        "--api-url",
        default="http://localhost:8000",
        help="URL base de la API (default: http://localhost:8000)"
    )
    parser.add_argument(
        "--branch-id",
        help="ID de rama a usar. Si no se especifica, usa la primera disponible"
    )
    
    args = parser.parse_args()
    
    try:
        importer = ContactImporter(
            api_url=args.api_url,
            branch_id=args.branch_id
        )
        importer.import_contacts(args.csv_file)
        importer.print_summary()
        
        # Código de salida basado en fallos
        sys.exit(0 if importer.stats['failed'] == 0 else 1)
        
    except Exception as e:
        print(f"❌ Error fatal: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
