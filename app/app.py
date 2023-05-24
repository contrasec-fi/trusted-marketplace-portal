import os
import jwt
from flask import Flask, request, render_template
from http import client
from urllib import parse
import requests
import json
import uuid
import time
import secrets
from datetime import datetime, timedelta
from settings import (PROVIDER_CLIENT_ID, CONSUMER_CLIENT_ID, PROVIDER_CLIENT_ID_M2M, CONSUMER_CLIENT_ID_M2M,
                      KEYROCK_URL, KEYROCK_URL_M2M, APP_URL, KEYROCK_AUTHZ_URL, KEYROCK_TOKEN_URL, KEYROCK_TOKEN_URL_M2M,
                      SCORPIO_URL, CONSUMER_EMAIL, AUTH_APP_URL,
                      PRIVATE_KEY, X5C_VALUE, PRIVATE_KEY_FILE, X5C_VALUE_FILE
                      )


app = Flask(__name__, static_url_path='/static')
app.url_map.strict_slashes = False

keyrock_authz = KEYROCK_AUTHZ_URL
keyrock_token_url = KEYROCK_TOKEN_URL
keyrock_token_url_m2m = KEYROCK_TOKEN_URL_M2M
keyrock_redirect_url = APP_URL + '/openid_connect1.0/return'
email = CONSUMER_EMAIL
app_url = APP_URL
auth_app_url = AUTH_APP_URL
scorpio_url = SCORPIO_URL
provider_client_id = PROVIDER_CLIENT_ID
consumer_client_id = CONSUMER_CLIENT_ID
provider_client_id_m2m = PROVIDER_CLIENT_ID_M2M
consumer_client_id_m2m = CONSUMER_CLIENT_ID_M2M
private_key = PRIVATE_KEY
authorize_x5c = X5C_VALUE

access_tokens = []


# Authorize
@app.route("/", methods=['GET'])
def index():
    code_params= parse.urlencode({'response_type': 'code', 'client_id': provider_client_id, 'scope': 'openid ishare',
                                  'redirect_uri': keyrock_redirect_url, 'state': str(uuid.uuid4()), 'nonce': gen_random()})
    return render_template('index.html', code_params=code_params, keyrock_authz=keyrock_authz, auth_app_url=auth_app_url)


# Check this AUTH_SESSION IF
# IT IS NEEDED ???
__AUTHZ_SESSION__ = requests.session()

@app.route("/auth", methods=['GET'])
def auth():
    global __AUTHZ_SESSION__
    authz_session = requests.session()
    authorize_request = requests.post(keyrock_authz, headers={
    'Content-Type': 'application/x-www-form-urlencoded',
    }, data={
     'response_type':'code',
     'client_id': provider_client_id,
     'redirect_uri': keyrock_redirect_url,
     'scope': 'iSHARE',
     'request': make_jwt()
     })
    if authorize_request.status_code != 204:
        print(authorize_request.json())
        return render_template("registration_failed.html", app_url=app_url)
    else:
        __AUTHZ_SESSION__ = authz_session
        return render_template("registered.html", app_url=app_url)


@app.route("/openid_connect1.0/return", methods=['GET', 'POST'])
def authorized():
    request_access_token = requests.post(keyrock_token_url, data=
            {
                'grant_type': 'authorization_code',
                'client_id': provider_client_id,
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': make_jwt(),
                'redirect_uri': keyrock_redirect_url,
                'scope': 'iSHARE',
                'code': request.args.get('code')
            })

    request_access_token_m2m = requests.post(keyrock_token_url_m2m, data=
            {
                'grant_type': 'urn:ietf:params:oauth:grant-type:jwt-bearer',
                'scope': 'iSHARE',
                'client_id': provider_client_id_m2m,
                'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
                'client_assertion': make_jwt_m2m()
            })

    auth_token_m2m_json = request_access_token_m2m.json()
    access_token_m2m = str(auth_token_m2m_json['access_token'])

    if request_access_token.status_code != 200 and request_access_token_m2m.status_code != 200:
        return render_template('error_page.html', app_url=app_url)
    else:
        add_token(access_token_m2m)
        delete_old_tokens()
        access_token_m2m_payload = parse_token(access_token_m2m)
        return render_template('entities.html', access_token=access_token_m2m_payload)
    

@app.route("/request", methods=['GET', 'POST'])
def requestEntities():
    return render_template('entities.html')


@app.route("/entities/type", methods=['GET', 'POST'])
def fetchEntitiesType():
    scorpio_type = scorpio_url + '/ngsi-ld/v1/entities/?type='
    return fetchCommon(scorpio_type)


@app.route("/entities/attribute", methods=['GET', 'POST'])
def fetchEntitiesAttribute():
    scorpio_attribute = scorpio_url + '/ngsi-ld/v1/entities/?attrs='
    return fetchCommon(scorpio_attribute)

@app.route("/entities/id", methods=['GET', 'POST'])
def fetchEntitiesID():
    scorpio_id = scorpio_url + '/ngsi-ld/v1/entities/'
    return fetchCommon(scorpio_id)


## Custom error pages

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', app_url=app_url), 404

@app.errorhandler(500)
def page_internal_server_error(e):
    return render_template('500.html', app_url=app_url), 500


## Functions

## Fetch entities
def fetchCommon(scorpio_url):
    scorpio_type = request.form.get('entity')
    payload = request.form.get('token')
    checked_payload = check_token(payload)
    if checked_payload is None:
        return render_template('401.html', app_url=app_url), 401
    access_token = checked_payload['access_token']
    btoken = 'Bearer ' + str(access_token)


    request_session = requests.session()
    request_entities = request_session.get(scorpio_url+scorpio_type, headers={
        'Authorization': btoken,
        'Link': 'https://schema.lab.fiware.org/ld/context; rel=http://www.w3.org/ns/json-ld#context; type=application/ld+json',
        'Accept': 'application/ld+json'
    })

    if request_entities.status_code != 200:
        return render_template("error_page.html", app_url=app_url)
    else:
        scorpio_entities = json.dumps(request_entities.json(), sort_keys = True, indent = 2)
        print(scorpio_entities)
        return render_template('scorpio.html', scorpio_entities=scorpio_entities)

## JWT
def make_jwt():
        jwt_authz = jwt.encode(
        {
            "jti": str(uuid.uuid4()),
            "iss": provider_client_id,
            "sub": consumer_client_id,
            "aud": provider_client_id,
            "email": email,
            "iat": datetime.now(),
            "nbf": datetime.now(),
            "exp": datetime.now() + timedelta(seconds=30),
            "response_type": "code",
            "redirect_uri": keyrock_redirect_url,
            "callback_url": keyrock_redirect_url,
            "client_id": provider_client_id,
            "scope": "openid iSHARE",
            "state": "F3D3rat3DstAt3",
            "nonce": gen_random(),
            "acr_values": "urn:http://eidas.europa.eu/LoA/NotNotified/high",
            "language": "en"
        }, private_key, algorithm='RS256', headers={'x5c': authorize_x5c})
        return jwt_authz

## JWT M2M
def make_jwt_m2m():
        jwt_authz_m2m = jwt.encode(
        {
            "jti": str(uuid.uuid4()),
            "iss": provider_client_id_m2m,
            "sub": provider_client_id_m2m,
            "aud": [
                consumer_client_id_m2m,
                keyrock_token_url_m2m
            ],
            "iat": datetime.now(),
            "nbf": datetime.now(),
            "exp": datetime.now() + timedelta(seconds=30),
        }, private_key, algorithm='RS256', headers={'x5c': authorize_x5c})
        return jwt_authz_m2m


def gen_random():
    return(secrets.token_hex(16))

def add_token(access_token):
    access_tokens.append({'access_token': access_token, 'time_added': time.time()})

def delete_old_tokens():
    current_time = time.time()
    for access_token in access_tokens:
        if current_time - access_token['time_added'] >= 3600:  # 3600 seconds = 1 hour
            access_tokens.remove(access_token)

def parse_token(access_token):
    access_token_parts = access_token.split(".")
    payload = access_token_parts[1]
    return(payload)

def check_token(payload):
    for access_token in access_tokens:
        access_token_parts = access_token['access_token'].split(".")[1]
        if access_token_parts == payload:
            print("-----\nAccess token found!\n-----")
            return(access_token)
    return None
