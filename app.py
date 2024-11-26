import os
from flask import Flask, request
import psycopg2
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


app = Flask(__name__)

@app.route('/post-alert', methods=['POST'])
def post_alert():
    data = request.json
    try:
        # Fetch credentials from environment variables
        db_name = os.getenv("DB_NAME")
        db_user = os.getenv("DB_USER")
        db_password = os.getenv("DB_PASSWORD")
        db_host = os.getenv("DB_HOST")

        # Connect to the database
        conn = psycopg2.connect(
            dbname=db_name,
            user=db_user,
            password=db_password,
            host=db_host
        )
        cursor = conn.cursor()

        for alert in data:
            rule_name = alert["_source"]["rule"]["name"]
            timestamp = alert["_source"]["@timestamp"]
            host_ip = alert["_source"]["event_data"]["metadata"]["input"]["beats"]["host"]["ip"]
            cursor.execute(
                "INSERT INTO soalerts (timestamp, alert_name, host_ip) VALUES (%s, %s, %s)",
                (timestamp, rule_name, host_ip)
            )
        conn.commit()
        return "Alerts processed successfully", 200
    except Exception as e:
        return f"Error: {e}", 500
    finally:
        if conn:
            cursor.close()
            conn.close()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
