from flask import Flask, render_template, request, redirect, url_for
from flask_bootstrap import Bootstrap

app = Flask(__name__)
Bootstrap(app)

def generate_random_password(length):
    import random
    import string
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/generate_password', methods=['GET', 'POST'])
def generate_password():
    password = None
    if request.method == 'POST':
        length = int(request.form['length'])
        password = generate_random_password(length)
    return render_template('index.html', password=password)



if __name__ == "__main__":
    app.run()

