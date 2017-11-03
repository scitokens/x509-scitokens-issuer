Name:           x509-scitokens-issuer
Version:        0.1.0
Release:        0%{?dist}
Summary:        SciTokens issuer based on X509 authentication.

License:        Apache 2.0
URL:            https://scitokens.org
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch
 
%{?systemd_requires}

Requires:       python2-scitokens
Requires:       python-requests
Requires:       httpd
Requires:       gridsite

%description
%{summary}

%prep
%setup

%build

%install
python2 setup.py install

%post
%systemd_post

# Create the keyfiles if they don't already exist.
if [ ! -e /etc/x509-scitokens-issuer/issuer_key.pem ]; then
  scitokens-admin-create-key --create-keys --pem-private > /etc/x509-scitokens-issuer/issuer_key.pem || :
fi
if [ ! -e /etc/x509-scitokens-issuer/issuer_key.jwks ]; then
  scitokens-admin-create-key --private-keyfile /etc/x509-scitokens-issuer/issuer_key.pem --jwks-private > /etc/x509-scitokens-issuer/issuer_key.jwks || :
fi
if [ ! -e /etc/x509-scitokens-issuer/issuer_public.jwks ]; then
  scitokens-admin-create-key --private-keyfile /etc/x509-scitokens-issuer/issuer_key.jwks --jwks-public > /etc/x509-scitokens-issuer/issuer_public.jwks || :
fi

%postun
%systemd_postun

%files -n python2-%{pypi_name}
%doc README.rst
%{_bindir}/cms_update_mapping
%{python2_sitelib}/x509_scitokens_issuer.py*

%changelog
