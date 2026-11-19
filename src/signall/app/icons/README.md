Fallback copies of the symbolic icons Signall's interface uses. GTK looks in the user's icon
theme first and uses these only when the theme lacks an icon: Adwaita 50 (Fedora 44) dropped
some, and themes such as KDE's Breeze don't have them all and don't fall back to Adwaita.

They come from GNOME's Adwaita icon theme 50.0
(<https://gitlab.gnome.org/GNOME/adwaita-icon-theme>), © the GNOME Project, and are licensed
under the Creative Commons Attribution-Share Alike 3.0 United States License
(<https://creativecommons.org/licenses/by-sa/3.0/us/>).

When the interface starts using another icon, add its SVG here; `tests/test_app.py` checks that
every icon name in the app has a file here.
