from sanic import Sanic
from sanic_httpauth import HTTPDigestAuth
from sanic_session import Session

app = Sanic(__name__)
app.config["SECRET_KEY"] = "secret key here"
auth = HTTPDigestAuth()
Session(app)

users = {"john": "hello", "susan": "bye"}


@auth.get_password
def get_pw(username):
    if username in users:
        return users.get(username)
    return None


@app.route("/")
@auth.login_required
def index(request):
    return "Hello, %s!" % auth.username()


if __name__ == "__main__":
    app.run()
