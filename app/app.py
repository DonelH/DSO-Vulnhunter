from flask import Flask, request, render_template_string

app = Flask(__name__)

# DB_PASSWORD=12ui34hih12i3uh4oasdaw

# SQLi Ex. (OWASP A03)
@app.route('/login', methods=['GET','POST'])
def login():
    if request.method == 'POST':
        username = request.form.get("username")
        password = request.form.get("password")
        query = f"SELECT * FROM users WHERE username='{username}' AND password = '{password}'"
        return f"<p>Running query: {query}</p>"
    return '''
        <form method="post">
            Username: <input name="username"><br>
            Password: <input name="password"><br>
            <input type="submit">
        </form>
    '''

# XSS Ex. (OWASP A03)
@app.route('/search')
def search():
    q = request.args.get('q', '')
    return render_template_string(f"<h2> Results for: {q}</h2>")

if __name__ == "__main__":
    app.run(debug=True)