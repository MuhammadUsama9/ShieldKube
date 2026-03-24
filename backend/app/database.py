import sqlite3
import json
import os
import time
from typing import List, Dict, Any, Optional

DB_PATH = os.getenv("SHIELDKUBE_DB_PATH", "shieldkube.db")

class ShieldKubeDB:
    def __init__(self):
        self.conn = None
        try:
            # Ensure the directory is writable if the file doesn't exist
            db_dir = os.path.dirname(os.path.abspath(DB_PATH))
            if not os.path.exists(db_dir):
                os.makedirs(db_dir, exist_ok=True)
            
            print(f"[{time.strftime('%H:%M:%S')}] DB: Connecting to {DB_PATH}")
            self.conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
            self.conn.row_factory = sqlite3.Row
            self._init_db()
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] CRITICAL DB ERROR: {e}")
            # If we can't open the DB, we'll have to use an in-memory one as emergency fallback
            # to prevent the whole app from crashing.
            if not self.conn:
                print(f"[{time.strftime('%H:%M:%S')}] DB: Falling back to in-memory emergency storage.")
                self.conn = sqlite3.connect(":memory:", check_same_thread=False)
                self.conn.row_factory = sqlite3.Row
                self._init_db()

    def _init_db(self):
        cursor = self.conn.cursor()
        # Clusters table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS clusters (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                api_key TEXT,
                last_sync REAL,
                is_local INTEGER DEFAULT 0
            )
        """)
        # Telemetry table for various data types (pods, rbac, vulns, etc.)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                cluster_id TEXT,
                data_type TEXT,
                data_json TEXT,
                updated_at REAL,
                PRIMARY KEY (cluster_id, data_type)
            )
        """)
        # Ensure local cluster entry
        cursor.execute("INSERT OR IGNORE INTO clusters (id, name, is_local) VALUES ('local', 'Local Cluster', 1)")
        self.conn.commit()

    def update_cluster(self, cluster_id: str, name: str, api_key: Optional[str] = None):
        cursor = self.conn.cursor()
        if api_key:
            cursor.execute(
                "INSERT INTO clusters (id, name, api_key, last_sync) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET name=excluded.name, api_key=excluded.api_key, last_sync=excluded.last_sync",
                (cluster_id, name, api_key, time.time())
            )
        else:
            cursor.execute(
                "INSERT INTO clusters (id, name, last_sync) VALUES (?, ?, ?) "
                "ON CONFLICT(id) DO UPDATE SET name=excluded.name, last_sync=excluded.last_sync",
                (cluster_id, name, time.time())
            )
        self.conn.commit()

    def save_telemetry(self, cluster_id: str, data_type: str, data: Any):
        cursor = self.conn.cursor()
        cursor.execute(
            "INSERT INTO telemetry (cluster_id, data_type, data_json, updated_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(cluster_id, data_type) DO UPDATE SET data_json=excluded.data_json, updated_at=excluded.updated_at",
            (cluster_id, data_type, json.dumps(data), time.time())
        )
        # Also update last_sync in clusters table
        cursor.execute("UPDATE clusters SET last_sync = ? WHERE id = ?", (time.time(), cluster_id))
        self.conn.commit()

    def get_clusters(self) -> List[Dict]:
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM clusters")
        return [dict(row) for row in cursor.fetchall()]

    def get_telemetry(self, cluster_id: str, data_type: str, default: Any = None) -> Any:
        cursor = self.conn.cursor()
        cursor.execute("SELECT data_json FROM telemetry WHERE cluster_id = ? AND data_type = ?", (cluster_id, data_type))
        row = cursor.fetchone()
        return json.loads(row["data_json"]) if row else default

    def delete_cluster(self, cluster_id: str):
        if cluster_id == "local": return
        cursor = self.conn.cursor()
        cursor.execute("DELETE FROM clusters WHERE id = ?", (cluster_id,))
        cursor.execute("DELETE FROM telemetry WHERE cluster_id = ?", (cluster_id,))
        self.conn.commit()

# Global DB instance
db = ShieldKubeDB()
