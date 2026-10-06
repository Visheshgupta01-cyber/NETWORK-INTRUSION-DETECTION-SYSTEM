import sqlite3
import os
from datetime import datetime


class AlertDatabase:

    def __init__(self):

        self.database_folder = "database"
        self.database_file = os.path.join(
            self.database_folder,
            "nids_alerts.db"
        )

        # Create database folder
        os.makedirs(
            self.database_folder,
            exist_ok=True
        )

        self.create_table()

    # =====================================================
    # CREATE DATABASE TABLE
    # =====================================================

    def create_table(self):

        connection = sqlite3.connect(
            self.database_file
        )

        cursor = connection.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (

                id INTEGER PRIMARY KEY AUTOINCREMENT,

                timestamp TEXT NOT NULL,

                alert_type TEXT NOT NULL,

                source_ip TEXT,

                risk TEXT,

                message TEXT

            )
        """)

        connection.commit()
        connection.close()

    # =====================================================
    # SAVE ALERT
    # =====================================================

    def save_alert(self, alert):

        connection = sqlite3.connect(
            self.database_file
        )

        cursor = connection.cursor()

        timestamp = datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        cursor.execute("""
            INSERT INTO alerts
            (
                timestamp,
                alert_type,
                source_ip,
                risk,
                message
            )
            VALUES (?, ?, ?, ?, ?)
        """, (
            timestamp,
            alert.get("type", "Unknown"),
            alert.get("source", "Unknown"),
            alert.get("risk", "Unknown"),
            alert.get("message", "")
        ))

        connection.commit()
        connection.close()

        print("Alert saved to database.")

    # =====================================================
    # GET ALL ALERTS
    # =====================================================

    def get_alerts(self):

        connection = sqlite3.connect(
            self.database_file
        )

        cursor = connection.cursor()

        cursor.execute("""
            SELECT
                id,
                timestamp,
                alert_type,
                source_ip,
                risk,
                message
            FROM alerts
            ORDER BY id DESC
        """)

        alerts = cursor.fetchall()

        connection.close()

        return alerts

    # =====================================================
    # DELETE ALL ALERTS
    # =====================================================

    def clear_alerts(self):

        connection = sqlite3.connect(
            self.database_file
        )

        cursor = connection.cursor()

        cursor.execute(
            "DELETE FROM alerts"
        )

        connection.commit()
        connection.close()

        print("Database alerts cleared.")