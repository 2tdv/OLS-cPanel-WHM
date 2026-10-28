# Prebuilt phpredis for the EA4 PHP versions of the build (build/php-ext) and the pinned phpredis source for any other
# version. Files only: no scriptlets, nothing under /opt/cpanel, no service. `ols-cpanel php-ext install` (run by the
# object cache commands and the watcher) activates a build, or compiles one from the packaged source, by writing one
# INI file into an installed EA4 PHP after checking the PHP ABI.
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none
%global prefix_dir /usr/local/ols-cpanel/php-ext/redis

Name:           ols-cpanel-php-redis
Version:        %{ext_version}
Release:        %{ext_release}%{?dist}
Summary:        phpredis extension builds for cPanel EA4 PHP (OLS-cPanel object cache)
License:        PHP-3.01
URL:            https://github.com/phpredis/phpredis
Source0:        payload.tar
BuildArch:      x86_64
AutoReqProv:    no
# glibc is the only runtime library the extension needs (readelf NEEDED); the PHP itself is cPanel's EA4 PHP.
Requires:       glibc

%description
phpredis %{ext_version} compiled against the EA4 development packages of the supported PHP versions, with the
PHP API number and build id of each in index.json, and the checksum-pinned source tarball for building any other
EA4 PHP version on the server. The files are inert until ols-cpanel activates a build.

%prep
%setup -q -c -T
tar -xf %{SOURCE0}

%install
mkdir -p %{buildroot}
cp -a payload/. %{buildroot}/

%files
%defattr(-,root,root,-)
%dir %attr(0755,root,root) /usr/local/ols-cpanel
%dir %attr(0755,root,root) /usr/local/ols-cpanel/php-ext
%dir %attr(0755,root,root) %{prefix_dir}
%license %attr(0644,root,root) %{prefix_dir}/LICENSE
%attr(0644,root,root) %{prefix_dir}/index.json
%{prefix_dir}/src
%{prefix_dir}/ea-php*
