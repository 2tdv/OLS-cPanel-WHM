# Product package of the OLS-cPanel integration (docs/product-architecture.md, plan 18.2-18.3, 23.1).
# Files only. There are deliberately no %pre/%post/%preun/%postun/%posttrans/trigger scriptlets: installing,
# upgrading or removing this package never creates accounts, enables, starts, restarts or stops a service,
# registers a cPanel hook or plugin, or binds a port (plan 18.3). Every activation step is a journaled action
# of `ols-cpanel install --prepare` / cutover; removal is `ols-cpanel uninstall` before the package is erased.
%global debug_package %{nil}
%global __os_install_post %{nil}
%global prefix_dir /usr/local/ols-cpanel
%{!?with_activator: %global with_activator 0}

Name:           ols-cpanel
Version:        %{product_version}
Release:        %{product_release}%{?dist}
Summary:        OpenLiteSpeed integration for cPanel and WHM (engine, broker, plugins, installer)
License:        GPLv3
Source0:        payload.tar
BuildArch:      x86_64
AutoReqProv:    no
# The OLS server is a separate, equally scriptlet-free package; its directory /usr/local/lsws/conf must
# exist for the broker unit's ReadWritePaths.
Requires:       ols-cpanel-openlitespeed
# The prebuilt phpredis builds and the pinned source for the object cache's PHP extension (also scriptlet-free);
# the product activates them itself, without a download or a manual step.
Requires:       ols-cpanel-php-redis
Requires:       systemd
# The per-account object cache engine (AlmaLinux 9 AppStream). Installed with the product so enabling an account's
# object cache in WHM needs nothing else (fresh install 2026-10-28: the engine was missing); its service only runs
# per account when enabled.
Requires:       valkey
# ea-nginx takes 80/443 (cPanel moves Apache behind it): it cannot run beside OLS. EasyApache refuses the
# profile with this conflict instead of starting a second server on the same ports.
Conflicts:      ea-nginx
# cPanel's own PHP (/usr/local/cpanel/3rdparty/php/84) runs the CLI; it is not an RPM dependency and is
# checked by the CLI launcher and by the installer's platform detection.

%description
OLS-cPanel %{product_version}: the PHP configuration engine and CLI, the privileged broker (and activator when built),
the reconciler unit, the per-account object cache units, and the WHM and cPanel plugins with their built interface, staged under
%{prefix_dir}. Nothing is activated by the package manager; run `ols-cpanel install --prepare`.

%prep
%setup -q -c -T
tar -xf %{SOURCE0}

%install
mkdir -p %{buildroot}
cp -a payload/. %{buildroot}/

%files
%defattr(-,root,root,-)
%dir %attr(0755,root,root) %{prefix_dir}
%dir %attr(0755,root,root) %{prefix_dir}/bin
%attr(0755,root,root) %{prefix_dir}/bin/ols-cpanel
# Modes come from the payload (directories 0755, files 0644, executables 0755); package.py sets them.
%{prefix_dir}/lib
%dir %attr(0755,root,root) %{prefix_dir}/libexec
%attr(0644,root,root) %{prefix_dir}/libexec/ols-cpanel.php
%attr(0755,root,root) %{prefix_dir}/libexec/ols-cpanel-broker
%attr(0755,root,root) %{prefix_dir}/libexec/ols-cpanel-hook
%if %{with_activator}
%attr(0755,root,root) %{prefix_dir}/libexec/ols-cpanel-activator
%endif
%dir %attr(0755,root,root) %{prefix_dir}/share
%{prefix_dir}/share/ui
%{prefix_dir}/share/ols
# The release public key and its fingerprint: `ols-cpanel update install` (the WHM "Update now" button) trusts only this key.
%attr(0644,root,root) %{prefix_dir}/share/release-key.asc
%attr(0644,root,root) %{prefix_dir}/share/release-key.fingerprint
%{prefix_dir}/plugins
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-broker.service
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-reconciler.service
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-objcache@.service
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-objcache.service
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-objcache.timer
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-cache-clean.service
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-cache-clean.timer
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-notify.service
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-notify.timer
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-schedule.service
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-schedule.timer
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-php.path
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-php.service
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-php.timer
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-hybrid-firewall.service
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-hybrid-trust.service
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-hybrid-trust.timer
%attr(0644,root,root) /usr/lib/systemd/system/ols-cpanel-upgrade.service
%attr(0644,root,root) /usr/lib/sysusers.d/ols-cpanel.conf
