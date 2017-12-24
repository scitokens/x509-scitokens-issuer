/**
 * Example of using runtime loading to issue a token.
 */

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>


const char *DEFAULT_ISSUER = "https://scitokens.org/cms";


int main(int argc, char *argv[])
{
    const char *issuer = DEFAULT_ISSUER;
    if (argc < 2)
    {
        fprintf(stderr, "No issuer name specified: using %s.\n", DEFAULT_ISSUER);
    }
    else
    {
        issuer = argv[1];
    }

    int (*x509_scitokens_issuer_init_p)(char **);
    char* (*x509_scitokens_issuer_get_token_p)(const char *, const char *, const char *,
                                               char**);

    void *handle = dlopen("libX509SciTokensIssuer.so", RTLD_NOW|RTLD_GLOBAL);
    if (!handle)
    {
        fprintf(stderr, "Failed to load the token issuer library: %s\n",
                dlerror());
        return 1;
    }
    dlerror();

    *(void **)(&x509_scitokens_issuer_init_p) = dlsym(handle, "x509_scitokens_issuer_init");
    char *error;
    if ((error = dlerror()) != NULL)
    {
        fprintf(stderr, "Failed to load the initializer handle: %s\n", error);
        dlclose(handle);
        return 1;
    } 
    dlerror();

    *(void **)(&x509_scitokens_issuer_get_token_p) =
        dlsym(handle, "x509_scitokens_issuer_retrieve");
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

    char *token = (*x509_scitokens_issuer_get_token_p)(issuer, NULL, NULL, &err);
    dlclose(handle);
    if (token)
    {
        printf("%s\n", token);
    }
    else
    {
        fprintf(stderr, "Failed to retrieve token: %s\n", err);
        free(err);
        return 1;
    }

    return 0;
}
