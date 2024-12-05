import os
from flask import Flask, request
import psycopg2
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

@app.route('/post-alert', methods=['POST'])
def post_alert():
    data = request.json  # Get JSON payload

    conn = None  # Initialize the variable to avoid UnboundLocalError
    cursor = None

    try:
        # Extract the "hits" array from the JSON structure
        hits = data.get("hits", [])
        
        if not hits:
            return {"message": "No alerts found in payload"}, 400

        # Connect to the database
        conn = psycopg2.connect(
            dbname=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST")
        )
        cursor = conn.cursor()

        # Iterate through each hit and insert data into the database
        for hit in hits:
            source = hit
            timestamp = source.get("timestamp")
            rule_name = source.get("rule_name")
            source_ip = source.get("source_ip")
            severity = source.get("severity", "unknown")

            cursor.execute(
                """
                INSERT INTO soalerts (timestamp, alert_name, source_ip, severity)
                VALUES (%s, %s, %s, %s)
                """,
                (timestamp, rule_name, source_ip, severity)
            )

        conn.commit()
        return {"message": "Alerts processed successfully"}, 200

    except Exception as e:
        return {"error": str(e)}, 500

    finally:
        # Ensure the cursor and connection are closed if they were successfully created
        if cursor:
            cursor.close()
        if conn:
            conn.close()


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
