import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
import jwt
import json
import requests
from flask import Flask, request
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from dataclasses import dataclass, asdict

load_dotenv(override=True)

HASURA_URL = os.getenv("HASURA_URL")
HASURA_HEADERS = {"X-Hasura-Admin-Secret": os.getenv("HASURA_HEADERS")}
HASURA_JWT_SECRET = os.getenv("HASURA_JWT_SECRET")

################
# GRAPHQL CLIENT
################

@dataclass
class Client:
    url: str
    headers: dict

    def run_query(self, query: str, variables: dict, extract=False):
        request = requests.post(
            self.url,
            headers=self.headers,
            json={"query": query, "variables": variables},
        )
        assert request.ok, f"Failed with code {request.status_code}"
        return request.json()

    find_user_by_email = lambda self, email: self.run_query(
        """
            query UserByEmail($email: String!) {
                my_hasura_user(where: {email: {_eq: $email}}) {
                    id
                    email
                    password
                }
            }
        """,
        {"email": email},
    )

    find_user_id = lambda self, id: self.run_query(
        """
            query UserById($id: Int!) {
                my_hasura_user(where: {id: {_eq: $id}}) {
                    id
                    email
                    password
                }
            }
        """,
        {"id": id},
    )

    insert_blacklist_tokens = lambda self, token: self.run_query(
        """
            mutation InsertBlacklistToken($token: String!) {
                insert_my_hasura_blacklist_tokens(objects: {token: $token}) {
                    returning {
                      token
                    }
                }
            }
        """,
        {"token": token},
    )

    find_blacklist_token = lambda self, token: self.run_query(
        """
            query FindBlacklistToken($token: String!) {
                my_hasura_blacklist_tokens(where: {token: {_eq: $token}}) {
                      blacklisted_on
                      token
                }
            }
        """,
        {"token": token},
    )

    create_user = lambda self, email, password: self.run_query(
        """
            mutation CreateUser($email: String!, $password: String!) {
                insert_my_hasura_user(objects: {email: $email, password: $password}) {
                    returning {
                    id
                    email
                    password
                    }
                }
            }
        """,
        {"email": email, "password": password},
    )

    update_password = lambda self, id, password: self.run_query(
        """
            mutation UpdatePassword($id: Int!, $password: String!) {
                update_my_hasura_user(where: {id: {_eq: $id}}, _set: {password: 
                $password}) {
                     returning {
                      password
                     }
                }
            }
        """,
        {"id": id, "password": password},
    )


#######
# UTILS
#######

Password = PasswordHasher()
client = Client(url=HASURA_URL, headers=HASURA_HEADERS)


# ROLE LOGIC FOR DEMO PURPOSES ONLY
# NOT AT ALL SUITABLE FOR A REAL APP
def generate_token(user) -> str:
    """
    Generates a JWT compliant with the Hasura spec, given a User object with
    field "id"
    """
    user_roles = ["fishermen"]
    admin_roles = ["user", "admin"]
    is_admin = user["email"] == "admin@site.com"

    payload = {
        'exp': datetime.utcnow() + timedelta(days=1, seconds=5),
        'iat': datetime.utcnow(),
        'sub': str(user["id"]),
        "https://hasura.io/jwt/claims": {
            "x-hasura-allowed-roles": admin_roles if is_admin else user_roles,
            "x-hasura-default-role": "admin" if is_admin else "fishermen",
            "x-hasura-user-id": str(user["id"]),
        }
    }
    return jwt.encode(payload, HASURA_JWT_SECRET, "HS256")


def rehash_and_save_password_if_needed(user, plaintext_password):
    if Password.check_needs_rehash(user["password"]):
        client.update_password(user["id"], Password.hash(plaintext_password))


def check_blacklist(auth_token):
    # check whether auth token has been blacklisted
    res = client.find_blacklist_token(str(auth_token))
    if len(res['data']['my_hasura_blacklist_tokens']) > 0:
        return True
    else:
        return False


def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, HASURA_JWT_SECRET, "HS256")
        is_blacklisted_token = check_blacklist(auth_token)
        if is_blacklisted_token:
            return 'Token blacklisted. Please log in again.'
        else:
            return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'

#############
# DATA MODELS
#############

@dataclass
class RequestMixin:
    @classmethod
    def from_request(cls, request):
        """
        Helper method to convert an HTTP request to Dataclass Instance
        """
        values = request.get("input")
        return cls(**values)

    def to_json(self):
        return json.dumps(asdict(self))


@dataclass
class UserOutput(RequestMixin):
    id: int
    email: str
    password: str


@dataclass
class JsonWebToken(RequestMixin):
    token: str


@dataclass
class AuthArgs(RequestMixin):
    email: str
    password: str


##############
# MAIN SERVICE
##############

app = Flask(__name__)


@app.route("/signup", methods=["POST"])
def signup_handler():
    args = AuthArgs.from_request(request.get_json())
    hashed_password = Password.hash(args.password)
    user_response = client.create_user(args.email, hashed_password)
    if user_response.get("errors"):
        return {"message": user_response["errors"][0]["message"]}, 400
    else:
        user = user_response["data"]["insert_my_hasura_user"]["returning"]
        return UserOutput(**user[0]).to_json()


@app.route("/login", methods=["POST"])
def login_handler():
    args = AuthArgs.from_request(request.get_json())
    user_response = client.find_user_by_email(args.email)
    if len(user_response["data"]["my_hasura_user"]) == 0:
        return {"message": "Invalid credentials"}, 401
    user = user_response["data"]["my_hasura_user"][0]
    try:
        Password.verify(user.get("password"), args.password)
        rehash_and_save_password_if_needed(user, args.password)
        return JsonWebToken(generate_token(user)).to_json()
    except VerifyMismatchError:
        return {"message": "Invalid credentials"}, 401


@app.route("/get-user", methods=["POST"])
def get_user_handler():
    # get the auth token
    args = JsonWebToken.from_request(request.get_json())
    auth_token = args.token
    if auth_token:
        resp = decode_auth_token(auth_token)
        if resp.isdigit():
            user_response = client.find_user_id(int(resp))
            if len(user_response["data"]["my_hasura_user"]) == 0:
                return {"message": "User not found."}, 401
            user = user_response["data"]["my_hasura_user"][0]
            return UserOutput(**user).to_json()
        return {
            'message': resp
        }, 401
    else:
        return {
            'message': 'Provide a valid auth token.'
        }, 401


@app.route("/logout", methods=["POST"])
def logout_handler():
    # get auth token
    args = JsonWebToken.from_request(request.get_json())
    auth_token = args.token
    if auth_token:
        resp = decode_auth_token(auth_token)
        if resp.isdigit():
            # mark the token as blacklisted
            token_response = client.insert_blacklist_tokens(auth_token)
            if len(token_response["data"]['insert_my_hasura_blacklist_tokens']['returning']) == 0:
                return {"message": "Invalid credentials"}
            return {
                'message': 'Successfully logged out.'
            }, 200

        else:
            return {
                'message': resp
            }, 401
    else:
        return {
            'message': 'Provide a valid auth token.'
        }, 403


@app.route("/refresh", methods=["POST"])
def refresh_token():
    return {"message": "some token"}, 200


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
