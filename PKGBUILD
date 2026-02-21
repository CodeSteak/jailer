# Maintainer: your name <your@email.com>
pkgname=ja-jailer
pkgver=0.1.0
pkgrel=1
pkgdesc='Run commands inside a persistent Alpine Linux jail using Linux namespaces (no root, no Docker)'
arch=('x86_64' 'aarch64')
url='https://github.com/CodeSteak/jailer'
license=('MIT')
depends=()
makedepends=('cargo')
provides=('ja-jailer')
conflicts=()
source=()
sha256sums=()

build() {
    cd "$startdir"
    export RUSTUP_TOOLCHAIN=stable
    cargo build --release
}

package() {
    install -Dm755 "$startdir/target/release/ja" "$pkgdir/usr/bin/ja"
    install -Dm644 "$startdir/README.md" "$pkgdir/usr/share/doc/$pkgname/README.md"
}
