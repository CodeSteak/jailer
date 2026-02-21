# Maintainer: your name <your@email.com>
pkgname=jj-jailer
pkgver=0.1.0
pkgrel=1
pkgdesc='Run commands inside a persistent Alpine Linux jail using Linux namespaces (no root, no Docker)'
arch=('x86_64' 'aarch64')
url='https://github.com/youruser/jj'
license=('MIT')
depends=()
makedepends=('cargo')
provides=('jj-jailer')
conflicts=()
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')

prepare() {
    cd "jj-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    cargo fetch --locked --target "$CARCH-unknown-linux-gnu"
}

build() {
    cd "jj-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    export CARGO_TARGET_DIR=target
    cargo build --frozen --release --all-features
}

check() {
    cd "jj-$pkgver"
    export RUSTUP_TOOLCHAIN=stable
    cargo test --frozen --all-features
}

package() {
    cd "jj-$pkgver"
    install -Dm755 target/release/jj "$pkgdir/usr/bin/jj"
    install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
}
