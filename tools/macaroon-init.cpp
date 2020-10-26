/**
 * Example of using runtime loading to issue a token.
 */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

#include <string>
#include <vector>

int main(int argc, char *argv[])
{
    if (argc < 4)
    {
        fprintf(stderr, "Usage: %s URL validity_min ACTIVITY ...\n", argv[0]);
        return 1;
    }
    const char *url = argv[1];
    int validity = std::stoi(argv[2]);

    std::vector<const char *> activities_list(argc-2);

    for (int idx=0; idx<argc-3; idx++)
    {
        activities_list[idx] = argv[idx+3];
    }
    activities_list[argc-3] = NULL;

    int (*x509_scitokens_issuer_init_p)(char **);
    char *(*x509_macaroon_issuer_retrieve_p)(const char *,
                                             const char *,
                                             const char *,
                                             int,
                                             const char **,
                                             char**);

    void *handle = dlopen("libX509SciTokensIssuer.so", RTLD_NOW|RTLD_GLOBAL);
    if (!handle)
    {
        fprintf(stderr, "Failed to load the token issuer library: %s\n",
                dlerror());
        return 1;
    }
    dlerror();

    *(void **)(&x509_scitokens_issuer_init_p) = dlsym(handle,
        "x509_scitokens_issuer_init");
    char *error;
    if ((error = dlerror()) != NULL)
    {
        fprintf(stderr, "Failed to load the initializer handle: %s\n", error);
        dlclose(handle);
        return 1;
    } 
    dlerror();

    *(void **)(&x509_macaroon_issuer_retrieve_p) =
        dlsym(handle, "x509_macaroon_issuer_retrieve");
    if ((error = dlerror()) != NULL)
    {
        fprintf(stderr, "Failed to load the token retrieval handle: %s\n", error);
        dlclose(handle);
        return 1;
    }

    char *err = NULL;
    if ((*x509_scitokens_issuer_init_p)(&err))
    {
        fprintf(stderr, "Failed to initialize the client issuer library: %s\n", err);
        free(err);
        dlclose(handle);
        return 1;
    }

    char *token = (*x509_macaroon_issuer_retrieve_p)(url, NULL, NULL,
                                                     validity,
                                                     &activities_list[0],
                                                     &err);
    dlclose(handle);
    if (token)
    {
        printf("%s\n", token);
        free(token);
    }
    else
    {
        fprintf(stderr, "Failed to retrieve macaroon: %s\n", err);
        free(err);
        return 1;
    }

    return 0;
}
