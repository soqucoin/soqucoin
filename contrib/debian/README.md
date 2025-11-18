
Debian
====================
This directory contains files used to package soqucoind/soqucoin-qt
for Debian-based Linux systems. If you compile soqucoind/soqucoin-qt yourself, there are some useful files here.

## soqucoin: URI support ##


soqucoin-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install soqucoin-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your soqucoin-qt binary to `/usr/bin`
and the `../../share/pixmaps/soqucoin128.png` to `/usr/share/pixmaps`

soqucoin-qt.protocol (KDE)

