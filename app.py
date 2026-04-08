from flask import Flask, render_template, jsonify
import crypto_utils

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/generate_keys")
def generate_keys():
    result = crypto_utils.generate_keys()

    if isinstance(result, dict):
        return jsonify(result)

    return jsonify({
        "status": "success",
        "msg": result
    })


@app.route("/encrypt")
def encrypt():
    result = crypto_utils.encrypt_file()

    if isinstance(result, dict):
        return jsonify(result)

    return jsonify({
        "status": "success",
        "msg": result
    })


@app.route("/attack")
def attack():
    result = crypto_utils.attack_file()

    if isinstance(result, dict):
        return jsonify(result)

    return jsonify({
        "status": "warning",
        "msg": result
    })


@app.route("/verify")
def verify():
    result = crypto_utils.verify_file()

    if isinstance(result, dict):
        return jsonify(result)

    return jsonify({
        "status": "success",
        "msg": result
    })


@app.route("/reset")
def reset():
    result = crypto_utils.reset_output()

    if isinstance(result, dict):
        return jsonify(result)

    return jsonify({
        "status": "reset",
        "msg": result
    })


if __name__ == "__main__":
    print("Starting Flask server...")
    app.run(host="127.0.0.1", port=5000, debug=True)