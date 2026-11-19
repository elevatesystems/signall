# Signall RPM. Build it with packaging/build-rpm.sh, which supplies the version and a source
# tarball that already contains pdf.js.
#
# Signall's Python dependencies (pyHanko, python-pkcs11, cryptography, lxml, ...) need newer
# versions than Fedora ships, so they are bundled in %%{_libdir}/signall and installed with pip
# at build time (which needs network access). PyGObject, GTK, WebKitGTK, and the smart card
# stack come from Fedora. Because the bundle is tied to the Python version, build once per
# Fedora release.

%global app_id io.github.elevatesystems.Signall
%global debug_package %{nil}
# The bundled libraries are private: don't export or require what they provide.
%global __provides_exclude_from ^%{_libdir}/signall/.*$
%global __requires_exclude_from ^%{_libdir}/signall/.*$
%global __brp_mangle_shebangs_exclude_from ^%{_libdir}/signall/.*$

Name:           signall
Version:        %{signall_version}
Release:        1%{?dist}
Summary:        Sign PDFs and PDF forms with a US DoD CAC
License:        MIT AND Apache-2.0 AND BSD-3-Clause AND PSF-2.0 AND CC-BY-SA-3.0
URL:            https://github.com/elevatesystems/signall
Source0:        signall-%{version}.tar.gz

BuildRequires:  python3-devel
BuildRequires:  python3-pip
BuildRequires:  gcc
BuildRequires:  desktop-file-utils
BuildRequires:  libappstream-glib

Requires:       python3
Requires:       python3-gobject
# The cairo typelib that WebKit needs; Fedora 45 stopped pulling it in with python3-gobject.
Requires:       gobject-introspection
Requires:       gtk4
Requires:       libadwaita
Requires:       webkitgtk6.0
Requires:       opensc
Requires:       pcsc-lite
Requires:       pcsc-lite-ccid
Requires:       hicolor-icon-theme

%description
Signall is a GNOME app for signing PDFs with a US DoD Common Access Card (CAC).
It signs plain PDFs (draw a box), PDF forms, and XFA forms such as DD Form 2875,
and its signatures validate in Adobe Acrobat. A signall command-line tool is
included.

%prep
%autosetup -n signall-%{version}

%build
# Nothing to compile here; pip builds the wheel during install.

%install
%{python3} -m pip install --no-warn-script-location --disable-pip-version-check \
    --root-user-action=ignore --target %{buildroot}%{_libdir}/signall .
rm -rf %{buildroot}%{_libdir}/signall/bin

for cmd in signall:signall signall-app:signall.app; do
    name=${cmd%%:*}; module=${cmd#*:}
    install -Dm755 /dev/stdin %{buildroot}%{_bindir}/$name <<EOF
#!/bin/sh
export PYTHONPATH=%{_libdir}/signall\${PYTHONPATH:+:\$PYTHONPATH}
exec %{python3} -s -m $module "\$@"
EOF
done

desktop-file-install --dir=%{buildroot}%{_datadir}/applications data/%{app_id}.desktop
install -Dm644 data/%{app_id}.metainfo.xml %{buildroot}%{_metainfodir}/%{app_id}.metainfo.xml
mkdir -p %{buildroot}%{_datadir}/icons
cp -r data/icons/hicolor %{buildroot}%{_datadir}/icons/

%check
desktop-file-validate %{buildroot}%{_datadir}/applications/%{app_id}.desktop
appstream-util validate-relax --nonet %{buildroot}%{_metainfodir}/%{app_id}.metainfo.xml
PYTHONPATH=%{buildroot}%{_libdir}/signall %{python3} -s -c "import signall.cli, signall.render, pyhanko, pkcs11"

%files
%license LICENSE
%doc README.md
%{_bindir}/signall
%{_bindir}/signall-app
%{_libdir}/signall/
%{_datadir}/applications/%{app_id}.desktop
%{_metainfodir}/%{app_id}.metainfo.xml
%{_datadir}/icons/hicolor/*/apps/signall*

%changelog
* Tue Nov 17 2026 The Signall contributors - %{version}-1
- See https://github.com/elevatesystems/signall/releases
