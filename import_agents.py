#!/usr/bin/env python3
"""
Script para importar agentes desde CSV a la base de datos.
Uso: python import_agents.py <csv_file> [--api-url <url>]
"""

import csv
import sys
import argparse
import requests
import time
from pathlib import Path
from typing import Optional, List, Dict, Any


class AgentImporter:
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
        self.workgroups_cache = {}

    def get_workgroups(self) -> Dict[str, str]:
        """Obtiene todos los workgroups disponibles."""
        if self.workgroups_cache:
            return self.workgroups_cache
        
        try:
            response = self.session.get(f"{self.api_url}/api/workgroups?skip=0&limit=100")
            if response.status_code == 200:
                data = response.json()
                items = data.get("items") or data.get("data", [])
                for item in items:
                    self.workgroups_cache[item["name"]] = item["id"]
                print(f"✓ Cargados {len(self.workgroups_cache)} workgroups")
        except Exception as e:
            print(f"⚠️  Error cargando workgroups: {e}")
        
        return self.workgroups_cache

    def extract_workgroup_id(self, groups_str: Optional[str]) -> Optional[str]:
        """Extrae el primer workgroup del campo Groups."""
        if not groups_str or groups_str.strip() == "":
            return None
        
        workgroups = self.get_workgroups()
        
        # Dividir por comas/y
        group_list = [g.strip() for g in groups_str.split(",")]
        
        # Buscar coincidencia con primer grupo
        for group in group_list:
            if group in workgroups:
                return workgroups[group]
        
        # Si no encuentra, asignar el primero disponible
        if workgroups:
            return list(workgroups.values())[0]
        
        return None

    def get_next_agent_id(self) -> int:
        """Obtiene el siguiente agent_id disponible."""
        try:
            response = self.session.get(f"{self.api_url}/api/agents?skip=0&limit=10000")
            if response.status_code == 200:
                data = response.json()
                items = data.get("items") or data.get("data", [])
                
                # Extraer números de agent_id existentes
                existing_ids = []
                for item in items:
                    agent_id = item.get("agent_id", "")
                    if agent_id.startswith("AG-"):
                        try:
                            num = int(agent_id.split("-")[1])
                            existing_ids.append(num)
                        except (ValueError, IndexError):
                            pass
                
                if existing_ids:
                    return max(existing_ids) + 1
        except Exception as e:
            print(f"⚠️  Error obteniendo siguiente agent_id: {e}")
        
        return 1000

    def import_agents(self, csv_file: str) -> Dict[str, Any]:
        """Importa agentes desde CSV."""
        csv_path = Path(csv_file)
        if not csv_path.exists():
            raise FileNotFoundError(f"Archivo no encontrado: {csv_file}")

        # Cargar workgroups
        workgroups = self.get_workgroups()
        
        # Obtener el siguiente agent_id disponible
        next_agent_num = self.get_next_agent_id()

        print(f"📋 Leyendo archivo: {csv_path}")
        print(f"🔗 API URL: {self.api_url}")
        print(f"🆔 Comenzando con agent_id: AG-{next_agent_num:04d}")
        print("-" * 60)

        agent_counter = next_agent_num
        
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames:
                    raise ValueError("CSV vacío o sin encabezados")

                for row_num, row in enumerate(reader, start=2):
                    self.stats["total"] += 1
                    
                    try:
                        # Extraer campos del CSV
                        name = row.get("Name", "").strip()
                        roles = row.get("Roles", "").strip()
                        agent_type = row.get("Agent Type", "").strip()
                        groups = row.get("Groups", "").strip()
                        scope = row.get("Scope", "").strip()

                        # Validación de campos requeridos
                        if not name:
                            print(f"⏭️  Fila {row_num}: Nombre vacío, saltando...")
                            self.stats["skipped"] += 1
                            continue

                        # Determinar role: usar Roles si no está vacío, sino Agent Type
                        role = roles if roles else (agent_type if agent_type else "Agent")
                        
                        # Extraer primer workgroup si disponible
                        workgroup_id = self.extract_workgroup_id(groups) if groups else None
                        
                        # Usar scope como external_id para guardar referencias de acceso
                        external_id = scope if scope else None

                        # Preparar datos para POST
                        agent_id = f"AG-{agent_counter:04d}"
                        agent_data = {
                            "agent_id": agent_id,
                            "name": name,
                            "role": role[:50],  # Limitar a 50 chars
                            "workgroup_id": workgroup_id,
                            "external_id": external_id
                        }

                        # POST a la API
                        response = self.session.post(
                            f"{self.api_url}/api/agents",
                            json=agent_data,
                            timeout=5
                        )

                        if response.status_code == 200:
                            print(f"✅ Fila {row_num}: {name} ({agent_id}) - Insertado")
                            self.stats["success"] += 1
                        else:
                            error_msg = response.text
                            print(f"❌ Fila {row_num}: {name} - Error HTTP {response.status_code}: {error_msg}")
                            self.stats["failed"] += 1
                            self.stats["errors"].append({
                                "row": row_num,
                                "name": name,
                                "error": error_msg[:100]
                            })

                        agent_counter += 1
                        time.sleep(0.1)  # Pausa entre requests

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
        print("📊 RESUMEN DE IMPORTACIÓN DE AGENTES")
        print("=" * 60)
        print(f"Total procesados: {self.stats['total']}")
        print(f"✅ Exitosos: {self.stats['success']}")
        print(f"❌ Fallos: {self.stats['failed']}")
        print(f"⏭️  Saltados: {self.stats['skipped']}")
        
        if self.stats['errors']:
            print(f"\n⚠️  Errores encontrados:")
            for error in self.stats['errors'][:10]:
                if 'row' in error:
                    print(f"  Fila {error['row']}: {error.get('name', 'N/A')} - {error['error']}")
                else:
                    print(f"  {error['error']}")
            
            if len(self.stats['errors']) > 10:
                print(f"  ... y {len(self.stats['errors']) - 10} errores más")


def main():
    parser = argparse.ArgumentParser(
        description="Importa agentes desde CSV a WorkHub",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python import_agents.py agents-February-06-2026-03_55.csv
  python import_agents.py agents.csv --api-url http://127.0.0.1:8000
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
        importer = AgentImporter(api_url=args.api_url)
        importer.import_agents(args.csv_file)
        importer.print_summary()
        
        # Código de salida basado en fallos
        sys.exit(0 if importer.stats['failed'] == 0 else 1)
        
    except Exception as e:
        print(f"❌ Error fatal: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
