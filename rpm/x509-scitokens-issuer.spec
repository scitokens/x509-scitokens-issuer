Name:           x509-scitokens-issuer
Version:        0.5.2
Release:        1%{?dist}
Summary:        SciTokens issuer based on X509 authentication.

License:        Apache 2.0
URL:            https://scitokens.org

# Detect builds on Darwin in the CMS environment.
%define isdarwin %(case %{cmsos} in (osx*) echo 1 ;; (*) echo 0 ;; esac)

# Generated from:
# git archive v%{version} --prefix=%{name}-%{version}/ | gzip -7 > ~/rpmbuild/SOURCES/x509-scitokens-issuer-%{version}.tar.gz
Source0:        %{name}-%{version}.tar.gz

%if 0%{?rhel} >= 7
%{?systemd_requires}
BuildRequires:  systemd
%else
# urllib3 on EPEL6 appears to have a missing dependency.  Pull it in
# to get a working system.
Requires: python-ndg_httpsclient
%endif

BuildRequires:  cmake
BuildRequires:  python2-devel
BuildRequires:  python2-setuptools
BuildRequires:  davix-devel
BuildRequires:  json-c-devel

Requires:       python2-scitokens
Requires:       python-requests
Requires:       httpd
Requires:       gridsite

%description
%{summary}

%package client
Summary:        Client for X509-based token issuer

Requires:       python-requests

%description client
A client library for the x509-scitokens-issuer.

%prep
%setup

%build
%{py2_build}
%cmake .

%install
make install DESTDIR=%{buildroot}
%{py2_install}
rm %{buildroot}%{_bindir}/cms-scitokens-init

%if %isdarwin
# we should use /usr/local to avoid SIP problem on OSX
rm -f %{buildroot}/usr/local/lib/systemd/system/cms-mapping-updater.service
rm -f %{buildroot}/usr/local/lib/systemd/system/cms-mapping-updater.timer

%else

%if 0%{?rhel} < 7
rm -f %{buildroot}/usr/lib/systemd/system/cms-mapping-updater.service
rm -f %{buildroot}/usr/lib/systemd/system/cms-mapping-updater.timer
%endif

%endif

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
  chown root:apache /etc/x509-scitokens-issuer/issuer_key.jwks
  scitokens-admin-create-key --private-keyfile /etc/x509-scitokens-issuer/issuer_key.pem --jwks-private > /etc/x509-scitokens-issuer/issuer_key.jwks || :
fi
if [ ! -e /etc/x509-scitokens-issuer/issuer_public.jwks ]; then
  touch /etc/x509-scitokens-issuer/issuer_public.jwks
  chmod 640 /etc/x509-scitokens-issuer/issuer_public.jwks
  chown root:apache /etc/x509-scitokens-issuer/issuer_public.jwks
  scitokens-admin-create-key --private-keyfile /etc/x509-scitokens-issuer/issuer_key.pem --jwks-public > /etc/x509-scitokens-issuer/issuer_public.jwks || :
fi

%post client
/sbin/ldconfig

%postun
%systemd_postun httpd.service

%postun client
/sbin/ldconfig

%files
%doc README.md
%dir %{_sysconfdir}/%{name}
%dir %{_sysconfdir}/%{name}/conf.d
%config(noreplace) %{_sysconfdir}/%{name}/conf.d/00-defaults.cfg
%config(noreplace) %{_sysconfdir}/%{name}/rules.json
%config(noreplace) %{_sysconfdir}/httpd/conf.d/x509_scitokens_issuer.conf
%{_bindir}/cms-update-mapping
%{_bindir}/cms-scitoken-init
%{python2_sitelib}/x509_scitokens_issuer*
%attr(0700, apache, apache) %dir %{_localstatedir}/cache/httpd/%{name}
%ghost %attr(-, apache, apache) %{_localstatedir}/cache/httpd/%{name}/dn_mapping.json

%if 0%{?rhel} >= 7
%{_unitdir}/cms-mapping-updater.service
%{_unitdir}/cms-mapping-updater.timer
%endif

%{_datarootdir}/%{name}/x509_scitokens_issuer.cfg
%{_localstatedir}/www/wsgi-scripts/%{name}.wsgi

%files client
%{_libdir}/libX509SciTokensIssuer.so
%{_bindir}/x509-scitoken-init
%{_bindir}/macaroon-init

%changelog
* Thu Jul 26 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.5.2-1
- Apply workaround whenever UPLOAD is found.

* Thu Jul 26 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.5.1-1
- Workaround permission mapping in dCache.

* Thu Jul 26 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.5.0-1
- Switch client library to pure C/C++.

* Tue Mar 27 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.4.2-1
- Patch CA bundle issue on RHEL6.

* Wed Mar 21 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.4.1-1
- Add initial support for RHEL6.

* Tue Feb 06 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.4.0-1
- Add new generic issuer CLI.

* Fri Dec 29 2017 Brian Bockelman <bbockelm@cse.unl.edu> - 0.3.0-1
- Add C library interface for the token retrieval.

* Mon Nov 06 2017 Brian Bockelman <bbockelm@cse.unl.edu> - 0.2.0-1
- Fix issuing of JSON-formatted scp.

* Mon Nov 06 2017 Brian Bockelman <bbockelm@cse.unl.edu> - 0.2.0-1
- Add tool for generating SciToken.
- Fix various small packaging errors.

