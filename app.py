from flask import Flask, request, jsonify, make_response, session
from flask_sqlalchemy import SQLAlchemy
from functools import wraps  # function wrap ho gaya h isme jo changes nhi ho sakta..
from werkzeug.security import (
    generate_password_hash,
    check_password_hash,
)  # ye password hashing & checking ko import krta hai..
import datetime
import jwt

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///Mydata.db"
app.config["SECRET_KEY"] = (
    "S_SECRET_KEY"  # secret key set karta hai jo JWT ko sign karne ke liye use hota hai. ye application ki security ko ensure karta hai...
)

db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(50), nullable=False)
    user_name = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)

    def __str__(
        self,
    ):  # Ye code ek string representation provide karta hai jab User object ko print kiya jata hai...
        return self.user_name


def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):  # yaha wrap decorator used huaa h
        token = request.cookies.get(
            "access_token_cookie"
        )  # ye code cookies ko accesss karta hai  & retrieves cookie..
        if not token:
            return jsonify({"Message": "Token is no longer valid"}), 401
        try:
            user_data = jwt.decode(
                token, app.config["SECRET_KEY"], algorithms=["HS256"]
            )  # decodes token & verify the token to provide accesss...
            user = User.query.get(user_data["user_id"])
        except jwt.ExpiredSignatureError:
            return jsonify({"Message": "Token is Expired..."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"Message": "Invalid Token"}), 401
        return f(*args, **kwargs)

    return decorator


# register user..


@app.route("/register", methods=["POST"])
def signup():
    data = request.json
    email = data.get("email")
    user_name = data.get("user_name")
    password = data.get("password")

    if not email or not user_name or not password:
        return jsonify({"Message": "Missing Fields"})

    hashed_password = generate_password_hash(password)
    new_user = User(email=email, user_name=user_name, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"Message": "User Created Successfully.."})


#  log in user...


@app.route("/login", methods=["POST"])
def login():
    data = request.json
    email = data.get("email")
    password = data.get("password")

    user = User.query.filter_by(email=email).first()
    if not email or not password:
        return jsonify({"Message": "Missing Credentials.."})
    if not user or not check_password_hash(user.password, password):
        return jsonify({"Message": "Invalid Login Credentials.."})
    access_token = jwt.encode(
        {
            "user_id": user.id,  # ye payload h..
            "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10),
        },
        app.config["SECRET_KEY"],
        algorithm="HS256",
    )  # yahaa teeno combined hokar signature bann gyaa..
    response = make_response(jsonify({"Message": "Login Successfully..."}))
    response.set_cookie(
        "access_token_cookie", access_token, httponly=True
    )  # httponly = True == encode cookies in http & secure from access data...
    session["email"] = email
    return response


@app.route("/logout", methods=["GET"])
@token_required
def logout(user):
    response = make_response(jsonify({"Message": " You are Successfully Logout"}))
    response.set_cookie(
        "access_token_cookie", expires=0
    )  # logout hote hi expires 0  se ye cookie invalid ho jaayega..
    return response


@app.route("/greet", methods=["GET"])
@token_required  # ye decorator fir direct apne token_reqd func me jayega aur token check kregaa with multiple conditions..
def hello():
    email = session.get("email")
    if not email:
        return jsonify("login required")
    return jsonify(f"Hello {email}")


if __name__ == "__main__":
    app.run(debug=True, port=1997)
