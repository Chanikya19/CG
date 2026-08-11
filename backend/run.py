from app import create_app

# Instantiate Flask application factory
app = create_app()

if __name__ == "__main__":
    # Launch application server on port 5000 for standard local proxying
    app.run(host="0.0.0.0", port=5000, debug=True)
