from flask import Flask, jsonify, request, render_template
import requests

# X: @owldecoy

app = Flask(__name__)

EUVD_API_URL = "https://euvdservices.enisa.europa.eu/api/vulnerabilities"

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36"                                                                                                                               
}

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/api/cves', methods=['GET'])
def get_cves():
    query = request.args.get('query', '').lower()
    show_latest = request.args.get('latest', 'false').lower() == 'true'

    params = {
        'size': 20,
        'page': 0
    }

    if not show_latest and query:
        params['text'] = query

    try:
        response = requests.get(EUVD_API_URL, headers=HEADERS, params=params)
        response.raise_for_status()
        data = response.json()

        if show_latest:
            items = sorted(data.get('items', []), key=lambda x: x['datePublished'], reverse=True)
            return jsonify(items)

        return jsonify(data.get('items', []))

    except requests.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        return jsonify({"error": str(http_err)}), 500
    except Exception as err:
        print(f"Unexpected error occurred: {err}")
        return jsonify({"error": str(err)}), 500


@app.route('/api/overview', methods=['GET'])
def overview():
    params = {
        'size': 100,
        'page': 0
    }

    try:
        response = requests.get(EUVD_API_URL, headers=HEADERS, params=params)
        response.raise_for_status()
        data = response.json()
        items = data.get('items', [])

        total_cves = len(items)
        high_risk_cves = len([cve for cve in items if cve.get('baseScore', 0) >= 7])
        medium_risk_cves = len([cve for cve in items if 4 <= cve.get('baseScore', 0) < 7])
        low_risk_cves = len([cve for cve in items if cve.get('baseScore', 0) < 4])
        last_updated = max((cve.get('datePublished', '') for cve in items), default="N/A")

        return jsonify({
            "total_cves": total_cves,
            "high_risk_cves": high_risk_cves,
            "medium_risk_cves": medium_risk_cves,
            "low_risk_cves": low_risk_cves,
            "last_updated": last_updated
        })

    except requests.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        return jsonify({"error": str(http_err)}), 500
    except Exception as err:
        print(f"Unexpected error occurred: {err}")
        return jsonify({"error": str(err)}), 500



@app.route('/api/alerts', methods=['GET'])
def recent_alerts():
    params = {
        'size': 100,
        'page': 0
    }

    try:
        response = requests.get(EUVD_API_URL, headers=HEADERS, params=params)
        response.raise_for_status()
        data = response.json()
        items = data.get('items', [])

        filtered_items = [item for item in items if item.get('baseScore', 0) >= 7]

        sorted_items = sorted(filtered_items, key=lambda x: x.get('datePublished', ''), reverse=True)

        recent_alerts = sorted_items[:20]

        alerts_data = [
            {
                "id": cve.get('id', 'N/A'),
                "aliases": cve.get('aliases', 'N/A'),
                "description": cve.get('description', 'No description available'),
                "datePublished": cve.get('datePublished', 'N/A'),
                "baseScore": cve.get('baseScore', 'N/A')
            }
            for cve in recent_alerts
        ]

        return jsonify(alerts_data)

    except requests.HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        return jsonify({"error": str(http_err)}), 500
    except Exception as err:
        print(f"Unexpected error occurred: {err}")
        return jsonify({"error": str(err)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=7899)
