import os
from datetime import datetime, timedelta

import jwt
import json
import logging
import requests
from flask import Flask, request, jsonify
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from typing import Optional
from dataclasses import dataclass, asdict

HASURA_URL = "https://square-bee-43.hasura.app/v1/graphql"
HASURA_HEADERS = {"X-Hasura-Admin-Secret": "0shpGp3GJairCwJD7QP4aAsJA5byW6xCcRrY5XFJ3pyV1qTR1zHNbGTSF8RWOYMn"}
HASURA_JWT_SECRET = os.getenv("HASURA_GRAPHQL_JWT_SECRET",
                              "django-insecure-61av8^4^#i$_+sf)_w7v)0%*l-ao&d^x5nvz%zw6$-ku$*jeip")
#{"type": "HS256","key": "django-insecure-61av8^4^#i$_+sf)_w7v)0%*l-ao&d^x5nvz%zw6$-ku$*jeip"}


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
class CreateUserOutput(RequestMixin):
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
        return CreateUserOutput(**user[0]).to_json()


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


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0")
