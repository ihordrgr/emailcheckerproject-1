from flask import Flask
app = Flask(__name__)

def init_db():
    # Initialization code here
    pass

# Здесь разместите ваши обработчики и основной код

if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000)