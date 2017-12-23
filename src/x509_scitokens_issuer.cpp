
#include <boost/python.hpp>

#include <mutex>
#include <string>

#include <dlfcn.h>
#include <string.h>

static bool g_initialized = false;
static std::mutex g_mutex;
static boost::python::object g_module;


extern"C" bool
x509_scitokens_issuer_init()
{
    std::lock_guard<std::mutex> guard(g_mutex);
    if (g_initialized) {return true;}

    if (!Py_IsInitialized())
    {
        char pname[] = "x509_scitokens_issuer";
        Py_SetProgramName(pname);
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
    if (handle == nullptr)
    {
        return false;
    }
    dlclose(handle);

    try
    {
        g_module = boost::python::import("x509_scitokens_issuer_client");
    }
    catch (boost::python::error_already_set)
    {
        return false;
    }
    return true;
}


extern "C" char *
x509_scitokens_issuer_retrieve(const char *issuer, const char *cert, const char *key)
{
    if (!issuer) {return nullptr;}
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
        boost::python::object retval =
            g_module.attr("get_token")(py_issuer, py_cert, py_key)["access_token"];
        token = boost::python::extract<std::string>(retval);
    }
    catch (boost::python::error_already_set)
    {
        return nullptr;
    }
    return strdup(token.c_str());
}
