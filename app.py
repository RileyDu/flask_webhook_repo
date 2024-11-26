
from flask import Flask, request
import psycopg2

app = Flask(__name__)

@app.route('/post-alert', methods=['POST'])
def post_alert():
    data = request.json
    try:
        conn = psycopg2.connect("dbname=<db> user=<user> password=<password> host=<host>")
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
