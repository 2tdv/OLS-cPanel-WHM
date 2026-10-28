# Product package of OpenLiteSpeed built from the pinned upstream tag plus reviewed
# patches (see source.json). Plan section 12.1, OLS-01/02/07/08.
# No scriptlets: installing this package never creates accounts, generates secrets,
# enables or starts a service, or writes a server configuration.
%global debug_package %{nil}
%global __os_install_post %{nil}
%global serverroot /usr/local/lsws

Name:           ols-cpanel-openlitespeed
Version:        %{ols_version}
Release:        %{ols_release}%{?dist}
Summary:        OpenLiteSpeed server for the OLS-cPanel integration (product build)
License:        GPLv3
URL:            https://github.com/litespeedtech/openlitespeed
Source0:        payload.tar
Conflicts:      openlitespeed
Conflicts:      lsws
AutoReqProv:    no
# Runtime libraries from readelf NEEDED of the product binary (AutoReqProv is off).
Requires:       glibc
Requires:       libaio
Requires:       libxcrypt
Requires:       libstdc++
Requires:       libgcc

%description
OpenLiteSpeed %{ols_version} built from upstream commit %{ols_commit} with the
OLS-cPanel patch set. Ships no default virtual host, no WebAdmin interface, no
vendor PHP and no server configuration. The ols-cpanel.service unit is installed
but not enabled.

%prep
%setup -q -c -T
tar -xf %{SOURCE0}

%install
mkdir -p %{buildroot}
cp -a payload/. %{buildroot}/

%files
%license %{serverroot}/GPL.txt
%dir %attr(0755,root,root) %{serverroot}
%{serverroot}/VERSION
%dir %{serverroot}/bin
%{serverroot}/bin/openlitespeed
%{serverroot}/bin/lshttpd
%{serverroot}/bin/litespeed
%{serverroot}/bin/lswsctrl
%{serverroot}/modules
%{serverroot}/lsns
%{serverroot}/share
%{serverroot}/lsrecaptcha
%dir %attr(0750,root,root) %{serverroot}/conf
%dir %attr(0750,root,root) %{serverroot}/conf/vhosts
%attr(0644,root,root) %{serverroot}/conf/mime.properties
%dir %attr(0750,root,nobody) %{serverroot}/logs
%dir %attr(0755,root,root) %{serverroot}/tmp
%dir %attr(0755,root,root) %{serverroot}/cachedata
%dir %attr(0755,root,root) %{serverroot}/autoupdate
%dir %attr(0710,root,root) %{serverroot}/cgid
%dir %attr(0755,root,root) %{serverroot}/admin
%dir %attr(0700,root,root) %{serverroot}/admin/conf
%config(noreplace) %attr(0600,root,root) %{serverroot}/admin/conf/admin_config.conf
%dir %attr(0710,root,root) %{serverroot}/admin/tmp
%dir %attr(0750,root,root) %{serverroot}/admin/logs
%dir %attr(0710,root,root) %{serverroot}/admin/cgid
/usr/lib/systemd/system/ols-cpanel.service
/usr/lib/systemd/system/ols-cpanel-logs.service
%dir %attr(0755,root,root) /usr/libexec/ols-cpanel
%attr(0755,root,root) /usr/libexec/ols-cpanel/ols-cpanel-logship
%attr(0755,root,root) /usr/libexec/ols-cpanel/ols-cpanel-reload
%attr(0755,root,root) /usr/libexec/ols-cpanel/ols-cpanel-epoch-check
