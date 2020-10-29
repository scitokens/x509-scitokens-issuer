from __future__ import print_function
import os
import re
import glob
import json
import time
import urllib
import urlparse
import threading
import traceback
import platform
import requests

import scitokens
import utils as x509_utils

import cryptography.hazmat.primitives.asymmetric.ec as ec

from flask import Flask, request

# Load the application and configuration defaults.
ipath = '/usr/share/x509-scitokens-issuer'
if platform.system() == 'Darwin':
    ipath = '/usr/local/share/x509-scitokens-issuer'
instance_path = os.environ.get('X509_SCITOKENS_ISSUER_INSTANCE_PATH', ipath)
app = Flask(__name__, instance_path=instance_path, instance_relative_config=True)
app.updater_thread = None
app.issuer_key = None

def _load_default_config():
    conf = {
    "CONFIG_FILE_GLOB": "/etc/x509-scitokens-issuer/conf.d/*.cfg",
    "LIFETIME": 3600,
    "ISSUER_KEY": "/etc/x509-scitokens-issuer/issuer_key.jwks",
    "RULES": "/etc/x509-scitokens-issuer/rules.json",
    "DN_MAPPING": "/var/cache/httpd/x509-scitokens-issuer/dn_mapping.json",
    "CMS": False,
    "ENABLED": False
    }
    aconf = os.environ.get('X509_SCITOKENS_ISSUER_CONFIG', '')
    if aconf:
        print("Loading {} config".format(aconf))
        conf.update(json.load(open(aconf)))
    app.config.update(conf)
    app.config.from_pyfile("x509_scitokens_issuer.cfg")
    if os.environ.get('X509_SCITOKENS_ISSUER'):
        app.config.from_envvar("X509_SCITOKENS_ISSUER")
    config_glob = str(app.config['CONFIG_FILE_GLOB'])
    files = glob.glob(config_glob)
    files.sort()
    for fname in files:
        print("Loading configuration file %s" % fname)
        app.config.from_pyfile(fname)

_load_default_config()
print("Loading X509 SciTokens issuer with the following config: %s" % str(app.config))

class InvalidFQAN(Exception):
    pass


class FQANMatcher(object):
    """
    Match a "FQAN glob" to a Gridsite FQAN.
    """

    def __init__(self, fqan_glob):
        group, role = self.parse_fqan(fqan_glob)
        self.group = group
        self.role = role

    _GROUP_FILTER = re.compile("[A-Za-z\.0-9\-_]+$")
    _SLASH_FILTER = re.compile("/+")
    @staticmethod
    def parse_fqan(fqan):
        # Capabilities have always been deprecated; dump this.
        fqan = fqan.split("/Capability=")[0]
        info = fqan.split("/Role=", 1)
        group = info[0]
        role = None
        if len(info) > 1: # We have a role present.
            role = info[1].split("/")[0] # Grab everything up to '/' delim.
            if role == "NULL" or not role:
                role = None
        # some amount of parsing
        group_pieces = FQANMatcher._SLASH_FILTER.split(group)
        if group_pieces[0] != "":
            raise InvalidFQAN("FQAN must start with '/'")
        group_pieces = group_pieces[1:]
        for group_name in group_pieces:
            if not FQANMatcher._GROUP_FILTER.match(group_name):
                raise InvalidFQAN("FQAN contains invalid group name: %s" % group_name)
        group = "/" + "/".join(group_pieces)
        return group, role

    def matches(self, grst_fqan):
        if not grst_fqan.startswith("fqan:"):
            return False

        grst_fqan = urllib.unquote_plus(grst_fqan[5:])
        grst_group, grst_role = self.parse_fqan(grst_fqan)

        if not grst_group.startswith(self.group):
            return False
        if self.role and grst_role != self.role:
            return False
        return True


class DNMatcher(object):
    """
    See if a gridsite credential matches a specific DN.
    """

    def __init__(self, dn):
        self.dn = dn

    def matches(self, grst_dn):
        if not grst_dn.startswith("dn:"):
            return False

        grst_dn = urllib.unquote_plus(grst_dn[3:])
        return grst_dn == self.dn


def regenerate_mappings():
    """
    Generate the mappings.
    """
    rules_fname = app.config["RULES"]
    rule_list = []
    with open(rules_fname, "r") as fp:
        contents = json.load(fp)
        json_rules = contents.get("rules")
    for rule in json_rules:
        match = rule.get("match")
        scopes = rule.get("scopes", [])
        scope = rule.get("scope")
        if scope:
            scopes.append(scope)
        if match.startswith("dn:"):
            rule_list.append((DNMatcher(urllib.unquote_plus(match[3:])), scopes))
        elif match.startswith("fqan:"):
            rule_list.append((FQANMatcher(urllib.unquote_plus(match[5:])), scopes))

    users_fname = app.config.get("DN_MAPPING")
    if users_fname:
        users_mapping = {}
        with open(users_fname, "r") as fp:
            contents = json.load(fp)
            users_mapping = contents
    else:
        users_mapping = {}
    return rule_list, users_mapping


def update_app():
    rule_list, users_mapping = regenerate_mappings()

    app.users_mapping = users_mapping
    app.rules = rule_list
    print("Users mapping has %d rules" % len(app.users_mapping))
    print("App rules:", app.rules)

    with open(app.config['ISSUER_KEY'], 'r') as fd:
        json_obj = json.load(fd)
    if 'keys' not in json_obj:
        raise Exception("No JWKS key present!")
    # TODO: I would be OK with the configuration file passing the KID
    if len(json_obj['keys']) != 1:
        raise Exception("JWKS key file must contain precisely one key")
    app.issuer_kid = json_obj['keys'][0]['kid']
    app.issuer_key = x509_utils.load_jwks(json_obj['keys'][0])

def launch_updater_thread():
    if not app.config['ENABLED']:
        raise Exception("Application is not currently enabled.")
    def updater_target(repeat=True):
        try:
            update_app()
        except Exception as e:
            print("Failure occurred when trying to update the app config:", str(e))
            traceback.print_exc()
        if repeat:
            time.sleep(60)
    updater_target(repeat=False)
    if not app.updater_thread:
        app.updater_thread = threading.Thread(target=updater_target)
        app.updater_thread.daemon = True
        app.updater_thread.start()
# Initialize the application as part of the module loading.
launch_updater_thread()

def generate_formats(cred):
    info = {}
    if cred.startswith('username:'):
        info['username'] = urllib.unquote_plus(cred[9:])
        return info
    if cred.startswith("dn:"):
        dn = urllib.unquote_plus(cred[3:])
        username = app.users_mapping.get(urllib.unquote_plus(cred[3:]))
        if username:
            info["username"] = username
    return info

def generate_scopes_and_user(grst_creds):
    scopes = set()
    user = None
    format_info = None
    for cred in grst_creds:
        format_info = generate_formats(cred)
        if not user and ('username' in format_info):
            user = format_info['username']
            break
    for rule in app.rules:
        for cred in grst_creds:
           if rule[0].matches(cred):
               for scope in rule[1]:
                   try:
                      scopes.add(scope.format(**format_info))
                   except KeyError:
                      pass
    return scopes, user

def limit_scope(issued_scope, requested_scope):
    """
    Compare issued and requested scopes.

    - If they refer to different authorizations, returns None
    - If they are equivalent scopes, then return the issued_scope.
    - If the requested scope has the same authz and is for
      a sub-resource, then return the authz with the sub-resource.
    - If the requested scope has the same authz but is not a
      strict sub-resource, then return None.
    """
    issued_info = issued_scope.rsplit(":", 1)
    requested_info = requested_scope.rsplit(":", 1)
    issued_authz = issued_info[0]
    requested_authz = requested_info[0]
    if issued_authz != requested_authz:
        return None

    issued_resource = '/'
    if len(issued_info) > 1:
        issued_resource = scitokens.urltools.normalize_path(issued_info[1])
    requested_resource = '/'
    if len(requested_info) > 1:
        requested_resource = scitokens.urltools.normalize_path(requested_info[1])
    if issued_resource == requested_resource:
        return issued_scope

    if requested_resource.startswith(issued_resource):
        return "%s:%s" % (issued_authz, requested_resource)

def return_oauth_error_response(error):
    resp = app.response_class(response=json.dumps({"error": str(error)}), mimetype='application/json', status=requests.codes.bad_request)
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Pragma'] = 'no-cache'
    return resp


def return_internal_error_response(error):
    resp = app.response_class(response=json.dumps({"error": str(error)}), mimetype='application/json', status=requests.codes.internal_server_error)
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Pragma'] = 'no-cache'
    return resp


@app.route("/token", methods=["POST"])
def token_issuer():

    # Currently, we only support the client_credentials grant type.
    if request.form.get("grant_type") != "client_credentials":
        return return_oauth_error_response("Incorrect grant_type %s; 'client_credentials' must be used." % request.form.get("grant_type"))
    requested_scopes = set([i for i in request.form.get("scopes", "").split() if i])

    creds = {}
    dn_cred = None
    entry_num = 0
    pattern = "GRST_CRED_AURI_"
    if app.config.get("CMS", False):
        pattern = "HTTP_CMS_AUTH"
    for key, val in request.environ.items():
        if app.config.get('VERBOSE', False):
            print("### request {} {}".format(key, val))
        if key.startswith(pattern):
            if pattern == "HTTP_CMS_AUTH":
                if key.endswith("_DN"):
                    val = "dn:"+val
                elif key.endswith("_LOGIN"):
                    val = "username:"+val
                elif key.startswith("HTTP_CMS_AUTHZ"):
                    val = "fqan:/{}".format(val.split(':')[-1])
                else:
                    continue
                creds[entry_num] = val
                entry_num += 1
            else:
                entry_num = int(key[15:]) # 15 = len("GRST_CRED_AURI_")
    keys = creds.keys()
    keys.sort()
    entries = []
    for key in keys:
        if not dn_cred and creds[key].startswith("dn:"):
            dn_cred = creds[key][3:]
        entries.append(creds[key])

    if not dn_cred:
        return return_oauth_error_response("No client certificate or proxy used for TLS authentication.")
    dn_cred = urllib.unquote_plus(dn_cred)

    scopes, user = generate_scopes_and_user(entries)
    if app.config.get('VERBOSE', False):
        print("### creds  : {}".format(creds))
        print("### entries: {}".format(entries))
        print("### scopes : {}".format(scopes))
        print("### user   : {}".format(user))

    # Compare the generated scopes against the requested scopes (if given)
    # If we don't give the user everything they want, then we 
    return_updated_scopes = False
    if requested_scopes:
        updated_scopes = set()
        for issued_scope in scopes:
            for requested_scope in requested_scopes:
                new_scope = limit_scope(issued_scope, requested_scope)
                if new_scope:
                    updated_scopes.add(new_scope)
                    if new_scope != requested_scope:
                        changed_any_scope = True
        scopes = set(updated_scopes)
        if requested_scopes != updated_scopes:
            return_updated_scopes = True

    # Return a 405
    if not scopes:
        return return_oauth_error_response("No applicable scopes for this user.")

    if isinstance(app.issuer_key, ec.EllipticCurvePrivateKey):
        algorithm = "ES256"
    else:
        algorithm = "RS256"

    token = scitokens.SciToken(key=app.issuer_key, key_id=app.issuer_kid, algorithm=algorithm)
    token['scope'] = ' '.join(scopes)
    if user:
        token['sub'] = user
    else:
        token['sub'] = dn_cred
    if 'ISSUER' in app.config:
        issuer = app.config['ISSUER']
    else:
        split = urlparse.SplitResult(scheme="https", netloc=request.environ['HTTP_HOST'], path=request.environ['REQUEST_URI'], query="", fragment="")
        issuer = urlparse.urlunsplit(split)

    try:
        serialized_token = token.serialize(issuer = issuer, lifetime = app.config['LIFETIME'])
    except Exception as ex:
        return return_internal_error_response("Failure when serializing token: {}".format(ex))

    json_response = {"access_token": serialized_token,
                     "token_type": "bearer",
                     "expires_in": app.config['LIFETIME'],
                    }
    if return_updated_scopes:
        json_response["scope"] = " ".join(scopes)
    resp = app.response_class(response=json.dumps(json_response), mimetype='application/json', status=requests.codes.ok)
    resp.headers['Cache-Control'] = 'no-store'
    resp.headers['Pragma'] = 'no-cache'
    return resp

