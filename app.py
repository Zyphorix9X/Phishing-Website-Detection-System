"""WSGI entry point; the Flask instance is constructed by the application factory."""

from phishing_app import create_app

app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
