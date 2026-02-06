#!/usr/bin/env python3
"""
Script para limpiar datos seed de la base de datos.
Mantiene solo los usuarios admin y agent para autenticación.
Uso: python cleanup_seed_data.py [--confirm]
"""

import sys
import argparse
import sqlite3
from pathlib import Path


class SeedDataCleaner:
    def __init__(self, db_path: str = "workhub.db"):
        self.db_path = db_path
        self.stats = {
            "messages": 0,
            "tickets": 0,
            "contacts": 0,
            "agents": 0,
            "workgroups": 0,
            "branches": 0,
            "audit_logs": 0
        }

    def get_counts(self, conn) -> dict:
        """Obtiene el conteo actual de registros."""
        cursor = conn.cursor()
        counts = {}
        
        tables = ["messages", "tickets", "contacts", "agents", "workgroups", "branches", "audit_logs", "users"]
        for table in tables:
            cursor.execute(f"SELECT COUNT(*) FROM {table}")
            counts[table] = cursor.fetchone()[0]
        
        return counts

    def clean_seed_data(self, dry_run: bool = True):
        """Limpia los datos seed manteniendo usuarios."""
        db_file = Path(self.db_path)
        if not db_file.exists():
            raise FileNotFoundError(f"Base de datos no encontrada: {self.db_path}")

        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            print("=" * 60)
            print("🧹 LIMPIEZA DE DATOS SEED")
            print("=" * 60)
            
            # Mostrar conteos antes
            before_counts = self.get_counts(conn)
            print("\n📊 Estado ANTES de limpieza:")
            print(f"  Users: {before_counts['users']}")
            print(f"  Messages: {before_counts['messages']}")
            print(f"  Tickets: {before_counts['tickets']}")
            print(f"  Contacts: {before_counts['contacts']}")
            print(f"  Agents: {before_counts['agents']}")
            print(f"  Workgroups: {before_counts['workgroups']}")
            print(f"  Branches: {before_counts['branches']}")
            print(f"  Audit Logs: {before_counts['audit_logs']}")
            
            if dry_run:
                print("\n⚠️  MODO DRY-RUN: No se realizarán cambios reales")
                print("Usa --confirm para ejecutar la limpieza real")
                return
            
            print("\n🔥 Ejecutando limpieza...")
            
            # Orden importante: eliminar en orden de dependencias
            # 1. Messages (depende de tickets)
            cursor.execute("DELETE FROM messages")
            self.stats["messages"] = cursor.rowcount
            print(f"  ✓ Eliminados {self.stats['messages']} messages")
            
            # 2. Tickets (depende de contacts, agents, branches)
            cursor.execute("DELETE FROM tickets")
            self.stats["tickets"] = cursor.rowcount
            print(f"  ✓ Eliminados {self.stats['tickets']} tickets")
            
            # 3. Contacts (depende de branches)
            cursor.execute("DELETE FROM contacts")
            self.stats["contacts"] = cursor.rowcount
            print(f"  ✓ Eliminados {self.stats['contacts']} contacts")
            
            # 4. Agents (depende de workgroups)
            cursor.execute("DELETE FROM agents")
            self.stats["agents"] = cursor.rowcount
            print(f"  ✓ Eliminados {self.stats['agents']} agents")
            
            # 5. Workgroups (independiente)
            cursor.execute("DELETE FROM workgroups")
            self.stats["workgroups"] = cursor.rowcount
            print(f"  ✓ Eliminados {self.stats['workgroups']} workgroups")
            
            # 6. Branches (independiente)
            cursor.execute("DELETE FROM branches")
            self.stats["branches"] = cursor.rowcount
            print(f"  ✓ Eliminados {self.stats['branches']} branches")
            
            # 7. Audit logs (opcional, limpiar logs antiguos)
            cursor.execute("DELETE FROM audit_logs")
            self.stats["audit_logs"] = cursor.rowcount
            print(f"  ✓ Eliminados {self.stats['audit_logs']} audit logs")
            
            # Commit cambios
            conn.commit()
            
            # Mostrar conteos después
            after_counts = self.get_counts(conn)
            print("\n📊 Estado DESPUÉS de limpieza:")
            print(f"  Users: {after_counts['users']} (mantenidos)")
            print(f"  Messages: {after_counts['messages']}")
            print(f"  Tickets: {after_counts['tickets']}")
            print(f"  Contacts: {after_counts['contacts']}")
            print(f"  Agents: {after_counts['agents']}")
            print(f"  Workgroups: {after_counts['workgroups']}")
            print(f"  Branches: {after_counts['branches']}")
            print(f"  Audit Logs: {after_counts['audit_logs']}")
            
            print("\n✅ Limpieza completada exitosamente")
            print("🔐 Usuarios de autenticación mantenidos intactos")
            
        except Exception as e:
            conn.rollback()
            print(f"\n❌ Error durante limpieza: {e}")
            raise
        finally:
            conn.close()

    def verify_users(self):
        """Verifica que los usuarios admin y agent existan."""
        db_file = Path(self.db_path)
        if not db_file.exists():
            print(f"⚠️  Base de datos no encontrada: {self.db_path}")
            return False
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute("SELECT username, role FROM users ORDER BY username")
            users = cursor.fetchall()
            
            if not users:
                print("⚠️  No hay usuarios en la base de datos")
                return False
            
            print("\n👥 Usuarios encontrados:")
            for username, role in users:
                print(f"  • {username} ({role})")
            
            return True
            
        finally:
            conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Limpia datos seed de WorkHub manteniendo usuarios",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python cleanup_seed_data.py                    # Dry-run (muestra lo que haría)
  python cleanup_seed_data.py --confirm          # Ejecuta limpieza real
  python cleanup_seed_data.py --db custom.db     # Usa otra base de datos
        """
    )
    
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="Confirmar eliminación (sin esto solo muestra preview)"
    )
    parser.add_argument(
        "--db",
        default="workhub.db",
        help="Ruta a la base de datos (default: workhub.db)"
    )
    
    args = parser.parse_args()
    
    try:
        cleaner = SeedDataCleaner(db_path=args.db)
        
        # Verificar usuarios primero
        print("🔍 Verificando usuarios...")
        if not cleaner.verify_users():
            print("\n⚠️  Advertencia: No se encontraron usuarios en la BD")
            if not args.confirm:
                response = input("¿Continuar de todos modos? (y/N): ")
                if response.lower() != 'y':
                    print("Operación cancelada")
                    sys.exit(0)
        
        # Ejecutar limpieza
        cleaner.clean_seed_data(dry_run=not args.confirm)
        
        sys.exit(0)
        
    except Exception as e:
        print(f"❌ Error fatal: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
