
#include <boost/python.hpp>

#include <mutex>
#include <string>

#include <dlfcn.h>
#include <string.h>


static bool g_initialized = false;
static std::mutex g_mutex;
static boost::python::object g_module;


static std::string
handle_pyerror()
{
    PyObject *exc,*val,*tb;
    boost::python::object formatted_list, formatted;
    PyErr_Fetch(&exc,&val,&tb);
    boost::python::handle<> hexc(exc), hval(boost::python::allow_null(val)), htb(boost::python::allow_null(tb));
    boost::python::object traceback(boost::python::import("traceback"));
    boost::python::object format_exception(traceback.attr("format_exception"));
    formatted_list = format_exception(hexc,hval,htb);
    formatted = boost::python::str("\n").join(formatted_list);
    return boost::python::extract<std::string>(formatted);
}


extern"C" int
x509_scitokens_issuer_init(char **err)
{
    *err = NULL;

    std::lock_guard<std::mutex> guard(g_mutex);
    if (g_initialized)
    {
        return 0;
    }

    if (!Py_IsInitialized())
    {
#if PY_MAJOR_VERSION <= 2
        char pname[] = "x509_scitokens_issuer";
        Py_SetProgramName(pname);
#endif
        Py_InitializeEx(0);
    }

    // We need to reload the current shared library:
    //   - RTLD_GLOBAL instructs the loader to put everything into the global symbol
    //     table. Python requires this for several modules.
    //   - RTLD_NOLOAD instructs the loader to actually reload instead of doing an
    //     initial load.
    //   - RTLD_NODELETE instructs the loader to not unload this library -- we need
    //     python kept in memory!
    void *handle = dlopen("libX509SciTokensIssuer.so", RTLD_GLOBAL|RTLD_NODELETE|RTLD_NOLOAD|RTLD_LAZY);
    if (handle == NULL)
    {
        const char *dlopen_error = dlerror();
        if (dlopen_error == NULL) {dlopen_error = "(unknown)";}
        const char *error_prefix = "Failed to reload internal library: ";
        int full_length = strlen(error_prefix) + strlen(dlopen_error) + 1;
        *err = static_cast<char*>(malloc(full_length));
        strcat(*err, error_prefix);
        strcat(*err, dlopen_error);
        return 1;
    }
    dlclose(handle);

    try
    {
        g_module = boost::python::import("x509_scitokens_issuer_client");
    }
    catch (boost::python::error_already_set)
    {
        std::string errmsg = handle_pyerror();
        *err = strdup(errmsg.c_str());
        return 1;
    }
    return 0;
}


extern "C" char *
x509_scitokens_issuer_retrieve_orig(const char *issuer, const char *cert, const char *key,
                               char **err)
{
    *err = NULL;

    if (!issuer)
    {
        return NULL;
    }
    std::lock_guard<std::mutex> guard(g_mutex);

    boost::python::object py_cert;
    if (cert) {
        py_cert = boost::python::object(cert);
    }
    boost::python::object py_key;
    if (key) {
        py_key = boost::python::object(key);
    }
    boost::python::object py_issuer = boost::python::object(issuer);

    std::string token;
    try
    {
        boost::python::object retval = boost::python::str(
                g_module.attr("get_token")(py_issuer, py_cert, py_key)["access_token"]
            );
        token = boost::python::extract<std::string>(retval);
    }
    catch (boost::python::error_already_set)
    {
        std::string errmsg = handle_pyerror();
        *err = strdup(errmsg.c_str());
        return NULL;
    }
    return strdup(token.c_str());
}

extern "C" char *
x509_macaroon_issuer_retrieve_orig(const char *url, const char *cert, const char *key,
                              int validity, const char **activities, char **err)
{
    *err = NULL;
    if (!url)
    {
        *err = strdup("URL not specified.");
        return NULL;
    }
    if (!activities)
    {
        *err = strdup("Activities not provided.");
        return NULL;
    }
    if (validity <= 0)
    {
        *err = strdup("Validity must be a positive integer (in minutes)");
        return NULL;
    }

    // From here on out, we are invoking python, so grab the guard mutex.
    std::lock_guard<std::mutex> guard(g_mutex);

    boost::python::object py_cert;
    if (cert) {
        py_cert = boost::python::object(cert);
    }
    boost::python::object py_key;
    if (key) {
        py_key = boost::python::object(key);
    }
    boost::python::object py_url = boost::python::object(url);

    boost::python::list activities_list;
    for (int idx=0; activities[idx]; idx++)
    {
        boost::python::object activity_name =
            boost::python::object(activities[idx]);
        activities_list.append(activity_name);
    }

    std::string macaroon;
    try
    {
        boost::python::object retval = boost::python::str(
                g_module.attr("get_macaroon")(py_url,
                                              py_cert,
                                              py_key,
                                              validity,
                                              activities_list)["macaroon"]
            );
        macaroon = boost::python::extract<std::string>(retval);
    }
    catch (boost::python::error_already_set)
    {
        std::string errmsg = handle_pyerror();
        *err = strdup(errmsg.c_str());
        return NULL;
    }
    return strdup(macaroon.c_str());
}
