Name:           x509-scitokens-issuer
Version:        0.8.2
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
BuildRequires:  davix-devel
BuildRequires:  json-c-devel

%if 0%{?rhel} >= 8
%define __python /usr/bin/python3
%endif

%if 0%{?rhel} >= 8
BuildRequires:  python3-devel
BuildRequires:  python3-setuptools
Requires: python3-scitokens
Requires: python3-requests
Requires: python3-flask
Requires: python3-mod_wsgi
%else
BuildRequires:  python2-devel
BuildRequires:  python2-setuptools
Requires:       python2-scitokens
Requires:       python-requests
Requires:       python-flask
Requires:       mod_wsgi
%endif
Requires:       httpd
Requires:       gridsite


%description
%{summary}

%package client
Summary:        Client for X509-based token issuer

%if 0%{?rhel} >= 8
Requires:       python3-requests
%else
Requires:       python-requests
%endif

%description client
A client library for the x509-scitokens-issuer.

%prep
%setup

%build
%{py_build}
%cmake .

%install
make install DESTDIR=%{buildroot}
%{py_install}
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
%{python_sitelib}/x509_scitokens_issuer*
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
* Wed Oct 28 2020 Diego Davila <didavila@ucsd.edu> - 0.8.2-1
- Fix a syntax error for py3 that prevented to build with el8 (software-4257)

* Mon Oct 26 2020 Edgar Fajardo <emfajard@ucsd.edu> - 0.8.1-1
- Fix bug preventing macaroon-init for EL8

* Tue Aug 18 2020 Edgar Fajardo <emfajard@ucsd.edu> - 0.8.0-1
- Adding support for EL8

* Wed Dec 19 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.7.0-1
- Implement new OAuth 2.0-based request for 'macaroons' (or similar).

* Mon Oct 08 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.5.4-1
- Do not attempt to read Macaroon responses larger than 1MB.

* Tue Sep 4 2018 Edgar Fajardo <emfajard@ucsd.edu> - 0.5.3-1
- Adding the correct requirements
- Bug fixes

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

