
import re
import glob
import urllib

from flask import Flask, request

# Load the application and configuration defaults.
app = Flask(__name__, instance_path="/usr/share/x509-scitokens-issuer", instance_relative_config=True)
app.config.update({
    "config_file_glob": "/etc/x509-scitokens-issuer/*.cfg",
    "lifetime": 3600,
    "issuer_key": "/etc/x509-scitokens-issuer/issuer.json",
    "enabled": False
})
app.config.from_pyfile("x509_scitokens.cfg")
config_glob = glob.glob(app.config["config_file_glob"])
for fname in glob.glob(config_glob):
    app.config.from_pyfile(fname)


class InvalidFQAN(Exception):
    pass


class FQANMatcher(object):
    """
    Match a "FQAN glob" to a Gridsite FQAN.
    """

    def __init__(self, fqan_glob):
        group, role = parse_fqan(fqan_glob)
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
        for group_name in group_names:
            if not FQANMatcher._GROUP_FILTER.matches(group_name):
                raise InvalidFQAN("FQAN contains invalid group name: %s" % group_name)
        group = "/" + "/".join(group_pieces)
        return group, role

    def matches(self, grst_fqan):
        if not grst_fqan.startswith("fqan:"):
            return False

        grst_fqan = urllib.unquote_plus(grst_fqan[5:])
        grst_group, grst_role = parse_fqan(grst_fqan)

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
    rules_fname = app.config.get("rules_mapping")
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
        if match.startswith("dn:")
            rule_list.append((DNMatcher(match[3:]), scopes))
        elif match.startswith("fqan:")
            rule_list.append((FQANMatcher(match[5:]), scopes))

    users_fname = app.config.get("dn_mapping")
    users_mapping = {}
    with open(users_fname, "r") as fp:
        contents = json.load(fp)
        users_mapping = contents
    return rule_list, users_mapping


def update_app():
    try:
        rule_list, users_mapping = regenerate_mappings()
    except:
        # TODO: log
        return
    app.users_mapping = users_mapping
    app.rules = rule_list
    if app.config['enabled'] == False:
        raise Exception("Application is not currently enabled.")

# Initialize the application as part of the module loading.
update_app()

def generate_formats(cred):
    info = {}
    if cred.startswith("dn:"):
        username = app.users_mapping.get(cred[3:])
        if username:
            info["username"] = username
    return info

def generate_scopes(grst_creds):
    scopes = []
    user = None
    for rule in app.rules:
        for cred in grst_creds:
           if rule[0].matches(cred):
               for scope in rules[1]:
                   format_info = generate_formats(cred)
                   if not user and ('username' in format_info):
                       user = format_info['username']
                   scopes.append(scope.format(**format_info))
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

@app.route("/token", methods=["POST"])
def token_issuer():

    # Currently, we only support the client_credentials grant type.
    if request.form.get("grant_type") != "client_credentials":
        return "Incorrect grant_type; 'client_credentials' must be used."
    requested_scopes = set([i for i in request.form.get("scopes", "").split() if i])

    creds = {}
    for key, val in request.environ.items():
        if key.startswith("GRST_CRED_AURI_"):
            entry_num = int(key[15:]) # 15 = len("GRST_CRED_AURI_")
            creds[entry_num] = val
    keys = creds.keys()
    keys.sort()
    entries = []
    for key in keys:
        entries.append(creds[key])

    print entries
    scopes, user = generate_scope_and_user(entries)
    print scopes
    print user

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
        scopes = list(updated_scopes)
        if requested_scopes != updated_scopes:
            return_updated_scopes = True

    token = scitokens.SciToken(key=app.config['issuer_key'])
    token['scp'] = " ".join(scopes)
    serialized_token = token.serialize(issuer = app.config['issuer'], lifetime = app.config['lifetime']

    # TODO: Return JSON as requested.
    return serialized_token

