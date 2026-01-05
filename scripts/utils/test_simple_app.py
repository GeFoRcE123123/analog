from flask import Flask, render_template_string

app = Flask(__name__)
app.secret_key = 'test-secret-key'

@app.route('/auth/login')
def test_login():
    return render_template_string('''
        <!DOCTYPE html>
        <html>
        <head><title>Test Login</title></head>
        <body>
            <h1>Test Login Page</h1>
            <p>If you see this, Flask is working!</p>
        </body>
        </html>
    ''')

@app.route('/')
def home():
    return "Flask is working!"

if __name__ == '__main__':
    print("Starting test Flask app on port 5050...")
    app.run(host='0.0.0.0', port=5050, debug=False)
