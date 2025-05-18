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

if __name__ == '__main__':
    app.run(debug=False, port=7899)
