
#include "json.h"

#include <stdlib.h>
#include <cstring>
#include <sstream>
#include <davix.hpp>
#include <functional>

using namespace Davix;


// When this library included an embedded python interpretter, this
// function was not a NO-OP.  We keep it around for now, just in case.
extern"C" int
x509_scitokens_issuer_init(char **err)
{
    return 0;
}

static std::string
token_issuer_version()
{
    return "@devel@";
}


static bool
setup_params(RequestParams &req_params, const char *provided_cert, const char *provided_key, char **err)
{
    //setLogLevel(DAVIX_LOG_TRACE);
    req_params.setSSLCAcheck(true);

    if (provided_cert && provided_key)
    {
        X509Credential cred;
        DavixError *cred_err = NULL;
        if (cred.loadFromFilePEM(provided_key, provided_cert, "", &cred_err) <0)
        {   
            std::stringstream ss;
            ss << "Could not load the user credentials: " << cred_err->getErrMsg();
            *err = strdup(ss.str().c_str());
            return false;
        }
        req_params.setClientCertX509(cred);
    }
    req_params.setOperationRetry(0);

    std::stringstream user_agent;
    user_agent << "x509_token_issuer/" << token_issuer_version();
    req_params.setUserAgent(user_agent.str());

    return true;
}


static char *
handle_macaroon_request(PostRequest &req, DavixError *req_err, bool is_oauth, char **err)
{
    if (req.beginRequest(&req_err))
    {
        std::stringstream ss;
        ss << "Macaroon request failed: " << req_err->getErrMsg();
        *err = strdup(ss.str().c_str());
        return NULL;
    }

    static const dav_ssize_t max_size = 1024*1024;
    dav_ssize_t answer_size = req.getAnswerSize();
    if (answer_size >= max_size)
    {
        std::stringstream ss;
        ss << "Macaroon response is too large to process: " << answer_size << " bytes";
        *err = strdup(ss.str().c_str());
        return NULL;
    }

    std::vector<char> resultBuffer; resultBuffer.resize(max_size);
    // StoRM has an interesting bug where an unknown/unhandled POST is treated like a corresponding GET,
    // meaning it would respond to the macaroon request with the entire file itself.  To protect
    // against this, we read out at most 1MB.
    dav_ssize_t segment_result = req.readSegment(&resultBuffer[0], max_size, &req_err);
    if (segment_result < 0)
    {
        std::stringstream ss;
        ss << "Reading body of token request failed: " << req_err->getErrMsg();
        *err = strdup(ss.str().c_str());
        return NULL;
    }
    if (segment_result >= max_size)
    {
        *err = strdup("Token response was over 1MB");
        return NULL;
    }
    if (req.getRequestCode() != 200)
    {
        std::stringstream ss;
        ss << "Token request failed with status code " << req.getRequestCode();
        ss << "; body: " << &resultBuffer[0];
        *err = strdup(ss.str().c_str());
        return NULL;
    }

    json_object *macaroon_obj = json_tokener_parse(&resultBuffer[0]);
    if (!macaroon_obj)
    {
        *err = strdup("Response was not valid JSON.");
        return NULL;
    }
    json_object *macaroon_key;
    if (!json_object_object_get_ex(macaroon_obj, is_oauth ? "access_token" : "macaroon", &macaroon_key))
    {
        *err = strdup("Response did not include a token.");
        json_object_put(macaroon_obj);
        return NULL;
    }
    const char *macaroon_cstr = json_object_get_string(macaroon_key);
    if (!macaroon_cstr)
    {
        *err = strdup("Macaroon key was not a string.");
        json_object_put(macaroon_obj);
        return NULL;
    }
    char *result = strdup(macaroon_cstr);
    json_object_put(macaroon_obj);

    return result;
}

static char *
x509_macaroon_issuer_retrieve_direct(const char *url, const char *provided_cert, const char *provided_key,
                                     int validity, const char **activities, char **err)
{
    if (validity <= 0)
    {
        *err = strdup("Macaroon validity must be positive.");
        return NULL;
    }
    if (!activities || !activities[0])
    {
        *err = strdup("At least one macaroon activity must be specified.");
        return NULL;
    }

    RequestParams req_params;
    if (!setup_params(req_params, provided_cert, provided_key, err))
    {
        return NULL;
    }

    std::string mangled_url = url;
    if (!strncmp(mangled_url.c_str(), "davs://", 6))
    {
        std::string temp_url = mangled_url.substr(7);
        mangled_url = "https://";
        mangled_url += temp_url;
    }

    Context ctx;
    ctx.loadModule("grid");
    DavixError *req_err = NULL;
    PostRequest req(ctx, mangled_url, &req_err);
    req.setParameters(req_params);

    std::stringstream contents;
    contents << "{\"caveats\": [\"activity:";
    bool first_activity = true;
    bool has_upload = false;
    for (int idx=0; activities[idx]; idx++)
    {
        if (first_activity)
        {
            first_activity = false;
        }
        else
        {
            contents << ",";
        }
        contents << activities[idx];
        if (!strcasecmp(activities[idx], "upload") || strstr(activities[idx], "UPLOAD"))
        {
            has_upload = true;
        }
    }
    // WORKAROUND: Due to a mis-mapping in dCache, we need both the UPLOAD and MANAGE permission to upload successfully.
    if (has_upload)
    {
        contents << ",MANAGE";
    }
    contents << "\"], \"validity\": \"PT" << validity << "M\"}";

    req.addHeaderField("Content-Type", "application/macaroon-request");
    req.setRequestBody(contents.str());

    return handle_macaroon_request(req, req_err, false, err);
}


static bool
parse_url(const std::string &url, std::string &schema, std::string &netloc,
                std::string &path, char **err)
{
    const std::string prot_end("://");
    std::string::const_iterator prot_iter =
        std::search(url.begin(), url.end(),
                    prot_end.begin(), prot_end.end());
    schema.reserve(distance(url.begin(), prot_iter));
    std::transform(url.begin(), prot_iter,
                  std::back_inserter(schema),
                  std::ptr_fun<int,int>(tolower));
    if (prot_iter == url.end() )
    {
        *err = strdup("Issuer URL missing hostname.");
        return false;
    }
    std::advance(prot_iter, prot_end.length());
    std::string::const_iterator path_iter = std::find(prot_iter, url.end(), '/');
    netloc.reserve(std::distance(prot_iter, path_iter));
    std::transform(prot_iter, path_iter,
                   std::back_inserter(netloc),
                   std::ptr_fun<int,int>(tolower));
    std::string::const_iterator query_iter = std::find(path_iter, url.end(), '?');
    path.assign(path_iter, query_iter);

    return true;
}


static std::string
get_metadata_endpoint(const std::string &issuer, char **err)
{
    std::string schema, netloc, path;
    if (!parse_url(issuer, schema, netloc, path, err))
    {
        return "";
    }
    if (schema == "davs")
    {
        schema = "https";
    }
    if (schema != "https")
    {
        *err = strdup("URL schema must be HTTPS");
        return "";
    }
    if (path == "/")
    {
        path = "";
    }
    std::string new_path = "/.well-known/oauth-authorization-server" + path;
    return "https://" + netloc + new_path;
}


static std::string
try_token_endpoint_discovery(const std::string &metadata_url, RequestParams &req_params, Context &ctx, char **err)
{
    //printf("Trying token endpoint discovery with %s\n", metadata_url.c_str());
    DavixError *req_err = NULL;
    GetRequest req(ctx, metadata_url, &req_err);
    req.setParameters(req_params);

    if (req.executeRequest(&req_err))
    {
        std::stringstream ss;
        ss << "Token endpoint discovery request failed: " << req_err->getErrMsg();
        *err = strdup(ss.str().c_str());
        return "";
    }

    if (req.getRequestCode() != 200)
    {
        std::stringstream ss;
        ss << "Token endpoint discovery request failed with status code " << req.getRequestCode();
        *err = strdup(ss.str().c_str());
        return "";
    }

    const char *response_data = req.getAnswerContent();
    if (!response_data)
    {
        *err = strdup("Received response with empty content");
        return "";
    }

    json_object *config_obj = json_tokener_parse(response_data);
    if (!config_obj)
    {
        *err = strdup("Response was not valid JSON.");
        return "";
    }
    json_object *token_endpoint_key;
    if (!json_object_object_get_ex(config_obj, "token_endpoint", &token_endpoint_key))
    {
        *err = strdup("Response did not include a token_endpoint key.");
        json_object_put(config_obj);
        return "";
    }
    const char *token_endpoint_cstr = json_object_get_string(token_endpoint_key);
    if (!token_endpoint_cstr)
    {
        *err = strdup("token_endpoint key was not a string.");
        json_object_put(config_obj);
        return "";
    }
    std::string result(token_endpoint_cstr);
    json_object_put(config_obj);

    return result;
}


static std::string
get_token_endpoint(const char *orig_issuer, RequestParams &req_params, Context &ctx,
                   bool fallback, char **err)
{
    std::string oauth_endpoint = get_metadata_endpoint(orig_issuer, err);
    if (oauth_endpoint.empty()) {return "";}

    std::string token_endpoint = try_token_endpoint_discovery(oauth_endpoint, req_params, ctx, err);
    if (!fallback || !token_endpoint.empty())
    {
        return token_endpoint;
    }
    free(*err);
    *err = NULL;

    std::string config_url = orig_issuer;
    if (config_url[config_url.size()-1] != '/')
    {
        config_url += "/";
    }
    config_url += ".well-known/openid-configuration";

    return try_token_endpoint_discovery(config_url, req_params, ctx, err);
}


extern "C" char *
x509_macaroon_issuer_retrieve(const char *url, const char *provided_cert, const char *provided_key,
                              int validity, const char **activities, char **err)
{
    Context ctx;
    ctx.loadModule("grid");

    RequestParams req_params;
    if (!setup_params(req_params, provided_cert, provided_key, err))
    {
        return NULL;
    }
    std::string schema, netloc, path;
    if (!parse_url(url, schema, netloc, path, err))
    {
        return NULL;
    }
    if (schema == "davs") {schema = "https";}
    if (schema != "https")
    {
        *err = strdup("Macaroon requests must be done over HTTPS");
        return NULL;
    }
    std::string issuer = schema + "://" + netloc + "/";
    std::string token_endpoint = get_token_endpoint(issuer.c_str(), req_params, ctx, false, err);
    // If there is no token endpoint, then we assume we directly request a macaroon.
    if (token_endpoint.empty())
    {
        free(*err);
        return x509_macaroon_issuer_retrieve_direct(url, provided_cert, provided_key,
                                                    validity, activities, err);
    }

    std::string scopes;
    if (activities && activities[0])
    {
        std::stringstream ss;
        ss << activities[0] << ":" << path;
        for (int idx = 1; activities[idx]; idx++)
        {
            ss << " " << activities[idx] << ":" << path;
        }
        scopes = ss.str();
    }
    std::stringstream post_body_ss;
    post_body_ss << "grant_type=client_credentials&expire_in=" << (validity * 60);
    if (!scopes.empty())
    {
        post_body_ss << "&scope=" << Uri::queryParamEscape(scopes);
    }
    DavixError *req_err = NULL;
    PostRequest req(ctx, token_endpoint, &req_err);
    req.setParameters(req_params);
    req.addHeaderField("Content-Type", "application/x-www-form-urlencoded");
    req.addHeaderField("Accept", "application/json");
    req.setRequestBody(post_body_ss.str());

    return handle_macaroon_request(req, req_err, true, err) ;
}


extern "C" char *
x509_scitokens_issuer_retrieve(const char *issuer, const char *cert, const char *key,
                               char **err)
{
    Context ctx;
    ctx.loadModule("grid");

    RequestParams req_params;
    if (!setup_params(req_params, cert, key, err))
    {
        return NULL;
    }
    std::string token_endpoint = get_token_endpoint(issuer, req_params, ctx, true, err);
    if (token_endpoint.empty())
    {
        return NULL;
    }

    DavixError *req_err = NULL;
    PostRequest req(ctx, token_endpoint, &req_err);
    req.setParameters(req_params);

    req.addHeaderField("Accept", "application/json");
    req.addHeaderField("Content-Type", "application/x-www-form-urlencoded");
    req.setRequestBody("grant_type=client_credentials");

    if (req.executeRequest(&req_err))
    {   
        std::stringstream ss;
        ss << "SciToken endpoint discovery request failed: " << req_err->getErrMsg();
        *err = strdup(ss.str().c_str());
        return NULL;
    }
    
    const char *response_data = req.getAnswerContent();
    if (!response_data)
    {   
        *err = strdup("Received response with empty content");
        return NULL;
    }
    
    json_object *response_obj = json_tokener_parse(response_data);
    if (!response_obj)
    {   
        *err = strdup("Response was not valid JSON.");
        return NULL;
    }
    json_object *access_token_key;
    if (!json_object_object_get_ex(response_obj, "access_token", &access_token_key))
    {   
        *err = strdup("Response did not include a access_token key.");
        json_object_put(response_obj);
        return NULL;
    }
    const char *access_token_cstr = json_object_get_string(access_token_key);
    if (!access_token_cstr)
    {   
        *err = strdup("access_token key was not a string.");
        json_object_put(response_obj);
        return NULL;
    }
    char *result = strdup(access_token_cstr);
    json_object_put(response_obj);

    return result;
}
