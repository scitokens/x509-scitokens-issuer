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
%{py2_build}

%install
%{py2_install}

%post
%systemd_post httpd.service

# Create the keyfiles if they don't already exist.
if [ ! -e /etc/x509-scitokens-issuer/issuer_key.pem ]; then
  touch /etc/x509-scitokens-issuer/issuer_key.pem
  chmod 640 /etc/x509-scitokens-issuer/issuer_key.pem
  chown root:apache /etc/x509-scitokens-issuer/issuer_key.pem
  scitokens-admin-create-key --create-keys --pem-private > /etc/x509-scitokens-issuer/issuer_key.pem || :
fi
if [ ! -e /etc/x509-scitokens-issuer/issuer_key.jwks ]; then
  touch /etc/x509-scitokens-issuer/issuer_key.jwks
  chmod 640 /etc/x509-scitokens-issuer/issuer_key.jwks
  chown root:apache: /etc/x509-scitokens-issuer/issuer_key.jwks
  scitokens-admin-create-key --private-keyfile /etc/x509-scitokens-issuer/issuer_key.pem --jwks-private > /etc/x509-scitokens-issuer/issuer_key.jwks || :
fi
if [ ! -e /etc/x509-scitokens-issuer/issuer_public.jwks ]; then
  touch /etc/x509-scitokens-issuer/issuer_public.jwks
  chmod 640 /etc/x509-scitokens-issuer/issuer_public.jwks
  chown root:apache /etc/x509-scitokens-issuer/issuer_public.jwks
  scitokens-admin-create-key --private-keyfile /etc/x509-scitokens-issuer/issuer_key.pem --jwks-public > /etc/x509-scitokens-issuer/issuer_public.jwks || :
fi

%postun
%systemd_postun httpd.service

%files
%doc README.md
%dir %{_sysconfdir}/%{name}
%dir %{_sysconfdir}/%{name}/conf.d
%config(noreplace) %{_sysconfdir}/%{name}/conf.d/00-defaults.cfg
%config(noreplace) %{_sysconfdir}/%{name}/rules.json
%config(noreplace) %{_sysconfdir}/httpd/conf.d/x509_scitokens_issuer.conf
%{_bindir}/cms-update-mapping
%{python2_sitelib}/x509_scitokens_issuer*
%ghost %attr(0700, apache, apache) %dir %{_localstatedir}/cache/httpd/%{name}
%attr(-, apache, apache) %{_localstatedir}/cache/httpd/%{name}/dn_mapping.json
%{_unitdir}/cms-mapping-updater.service
%{_unitdir}/cms-mapping-updater.timer
%{_datarootdir}/%{name}/x509_scitokens_issuer.cfg
%{_localstatedir}/www/wsgi-scripts/%{name}.wsgi

%changelog
