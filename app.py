import os
from flask import Flask, request, abort
import psycopg2
from dotenv import load_dotenv
import logging

# Load environment variables from .env file
load_dotenv()

app = Flask(__name__)

# Configure logging to output debug information
logging.basicConfig(level=logging.DEBUG)

@app.route('/post-alert', methods=['POST'])
def post_alert():
    try:
        data = request.get_json()
        app.logger.debug(f"Received data: {data}")

        if not data:
            app.logger.debug("No JSON payload received.")
            return {"message": "No JSON payload received"}, 400

        # Initialize hits list
        hits = []

        # Attempt to extract hits from nested structure
        if "result" in data:
            hits_wrapper = data.get("result", {}).get("input", {}).get("payload", {}).get("hits", {}).get("hits", [])
            app.logger.debug("Looking for hits in nested structure.")
            hits.extend(hits_wrapper)

        # If no hits found in nested structure, look for top-level hits
        if not hits:
            hits_wrapper = data.get("hits", [])
            if isinstance(hits_wrapper, list):
                app.logger.debug("Looking for hits at top level.")
                hits.extend(hits_wrapper)
            else:
                app.logger.debug("Top-level 'hits' is not a list.")

        app.logger.debug(f"Number of hits received: {len(hits)}")

        if not hits:
            app.logger.debug("No hits found in payload.")
            return {"message": "No alerts found in payload"}, 400

        # Connect to the database
        conn = psycopg2.connect(
            dbname=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST")
        )
        cursor = conn.cursor()
        app.logger.debug("Database connection established.")

        # Iterate through each hit and extract necessary fields
        for hit in hits:
            # Check if hit is a top-level hit or a nested hit
            if 'timestamp' in hit:
                # Top-level hit
                timestamp = hit.get("timestamp")
                rule_name = hit.get("rule_name")
                source_ip = hit.get("source_ip")
                severity = hit.get("severity", "unknown")
            else:
                # Nested hit
                source = hit.get("_source", {})
                timestamp = source.get("@timestamp")
                rule_name = source.get("rule", {}).get("name")
                source_ip = source.get("event_data", {}).get("metadata", {}).get("input", {}).get("beats", {}).get("host", {}).get("ip")
                severity = source.get("sigma_level", "unknown")

            # Validate that all required fields are present
            if not all([timestamp, rule_name, source_ip]):
                app.logger.warning(f"Missing fields in hit: {hit}")
                continue  # Skip this hit or handle as needed

            # Insert data into the database
            cursor.execute(
                """
                INSERT INTO soalerts (timestamp, alert_name, source_ip, severity)
                VALUES (%s, %s, %s, %s)
                """,
                (timestamp, rule_name, source_ip, severity)
            )
            app.logger.debug(f"Inserted hit into database: {hit}")

        # Commit the transaction
        conn.commit()
        app.logger.debug("Database commit successful.")
        return {"message": "Alerts processed successfully"}, 200

    except Exception as e:
        app.logger.error(f"Error processing alert: {e}")
        return {"error": str(e)}, 500

    finally:
        # Ensure the cursor and connection are closed if they were successfully created
        if 'cursor' in locals():
            cursor.close()
            app.logger.debug("Database cursor closed.")
        if 'conn' in locals():
            conn.close()
            app.logger.debug("Database connection closed.")


@app.route('/post-trial', methods=['POST'])
def post_trial():
    try:
        data = request.get_json()
        app.logger.debug(f"Received data for trialESP32: {data}")

        if not data:
            app.logger.debug("No JSON payload received.")
            return {"message": "No JSON payload received"}, 400

        # If a single record is received, wrap it in a list for uniform processing.
        if isinstance(data, dict):
            records = [data]
        elif isinstance(data, list):
            records = data
        else:
            app.logger.error("Invalid JSON format, expecting an object or list of objects.")
            return {"message": "Invalid JSON format, expecting object or array of objects"}, 400

        # Connect to the database
        conn = psycopg2.connect(
            dbname=os.getenv("DB_NAME"),
            user=os.getenv("DB_USER"),
            password=os.getenv("DB_PASSWORD"),
            host=os.getenv("DB_HOST")
        )
        cursor = conn.cursor()
        app.logger.debug("Database connection established for trialESP32.")

        # Process each record
        for record in records:
            # Extract fields for trialESP32 table
            button_toggle = record.get("button_toggle")
            event_time = record.get("event_time")
            light = record.get("light")

            # Validate that all required fields are present
            if button_toggle is None or event_time is None or light is None:
                app.logger.warning(f"Missing required fields in record: {record}")
                continue  # Skip this record

            # Insert data into the trialESP32 table
            cursor.execute(
                """
                INSERT INTO trialESP32 (button_toggle, event_time, light)
                VALUES (%s, %s, %s)
                """,
                (button_toggle, event_time, light)
            )
            app.logger.debug(f"Inserted record into trialESP32: {record}")

        # Commit the transaction
        conn.commit()
        app.logger.debug("Database commit successful for trialESP32.")
        return {"message": "Records processed successfully"}, 200

    except Exception as e:
        app.logger.error(f"Error processing trialESP32 data: {e}")
        return {"error": str(e)}, 500

    finally:
        if 'cursor' in locals():
            cursor.close()
            app.logger.debug("Database cursor closed for trialESP32.")
        if 'conn' in locals():
            conn.close()
            app.logger.debug("Database connection closed for trialESP32.")


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
