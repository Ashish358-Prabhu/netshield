from fastapi.middleware.cors import CORSMiddleware
from fastapi import FastAPI
from backend.database import get_connection, init_db

app = FastAPI(title="NetShield API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize database
init_db()


@app.get("/")
def home():
    return {
        "message": "Welcome to NetShield API",
        "status": "Running"
    }


@app.get("/alerts")
def get_alerts():
    with get_connection() as conn:
        alerts = conn.execute(
            "SELECT * FROM alerts ORDER BY id DESC"
        ).fetchall()

    return [dict(alert) for alert in alerts]



@app.post("/alerts")
def create_alert(alert: dict):
    with get_connection() as conn:

        # Check whether the same alert was recorded in the last 5 minutes
        existing_alert = conn.execute(
            """
            SELECT id FROM alerts
            WHERE alert_type = ?
            AND source_ip = ?
            AND created_at >= datetime('now', '-5 minutes')
            ORDER BY id DESC
            LIMIT 1
            """,
            (
                alert["alert_type"],
                alert["source_ip"]
            )
        ).fetchone()

        # Ignore duplicate alert
        if existing_alert:
            return {
                "message": "Duplicate alert ignored",
                "alert_id": existing_alert["id"],
                "duplicate": True
            }

        # Save new alert
        cursor = conn.execute(
            """
            INSERT INTO alerts
            (alert_type, source_ip, severity, description)
            VALUES (?, ?, ?, ?)
            """,
            (
                alert["alert_type"],
                alert["source_ip"],
                alert["severity"],
                alert["description"]
            )
        )

        alert_id = cursor.lastrowid

    return {
        "message": "Alert saved successfully",
        "alert_id": alert_id,
        "duplicate": False
    }

