import os
import logging

from flask import Flask, jsonify, request

from pipeline import get_result

root_dir = os.path.abspath(os.path.dirname(__file__))
print(f"Running from {root_dir}")

def setup_logging(log_file):
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

setup_logging('logs/server.log')

def create_app():
    
    app = Flask(__name__)

    @app.route('/', methods=['POST'])
    def post():
        result = 0
        
        if request.headers['Content-Type'] != 'application/octet-stream':
            resp = jsonify({'error': 'expecting application/octet-stream'})
            resp.status_code = 400  # Bad Request
            logging.error("Expecting application/octet-stream")
            return resp

        bytez = request.data
        bin_file_path = os.path.join(root_dir, 'bin.exe')
        with open(bin_file_path, 'wb') as f:
            f.write(bytez)

        # Do something with the binary data if needed
        try:
            result = get_result(bin_file_path)
        except Exception as e:
            # if error --> report as benign
            logging.warning(f"Parse Error: {e}")

        resp = jsonify({'result': result})
        resp.status_code = 200
        return resp

    return app

if __name__ == "__main__":
    app = create_app()

    port = int(os.environ.get("PORT", 8080))

    from gevent.pywsgi import WSGIServer
    from gevent.pool import Pool

    http_server = WSGIServer(('', port), app, spawn=Pool())
    print(f"Server running on port {port}")
    http_server.serve_forever()
