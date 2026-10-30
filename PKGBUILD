# Maintainer: <you>
pkgname=cachy-security-scanner
pkgver=0.0.1
pkgrel=1
pkgdesc='Tray app that runs AUR malware checkers in the background and notifies on findings'
url='https://github.com/ruepp-jenkins/cachyos-security-scanner'
arch=('any')
license=('GPL-3.0-or-later')
depends=('python' 'git' 'openssh' 'pyside6' 'libnotify' 'pacman')
makedepends=('git' 'python-build' 'python-installer' 'python-setuptools' 'python-wheel')
optdepends=('rust: build aur-scan automatically if the aur-scanner package is not installed'
            'aur-scanner: PKGBUILD/installed AUR package analysis (aur-scan)'
            'clamui: on-request binary scans')
source=("$pkgname::git+$url.git#tag=v$pkgver")
sha256sums=('SKIP')  # git source pinned to a release tag

build() {
  cd "$srcdir/$pkgname"
  python -m build --wheel --no-isolation --outdir "$srcdir/dist"
}

package() {
  cd "$srcdir/$pkgname"
  python -m installer --destdir="$pkgdir" "$srcdir"/dist/*.whl
  install -Dm644 data/cachy-security-scanner.hook "$pkgdir/usr/share/libalpm/hooks/cachy-security-scanner.hook"
  install -Dm644 data/cachy-security-scanner.conf "$pkgdir/usr/lib/tmpfiles.d/cachy-security-scanner.conf"
  install -Dm644 data/cachy-security-scanner.desktop "$pkgdir/etc/xdg/autostart/cachy-security-scanner.desktop"
  install -Dm644 data/cachy-security-scanner.desktop "$pkgdir/usr/share/applications/cachy-security-scanner.desktop"
}
