# PKGBUILD for VibeCheat
pkgname=vibecheat
pkgver=0.1.0
pkgrel=1
pkgdesc="VibeCheat - Linux Process Memory Scanner & Speedhack"
arch=('x86_64')
license=('MIT')
depends=('polkit' 'gcc' 'lua')
options=('!debug')


prepare() {
  # Create a clean workspace inside the srcdir
  mkdir -p "$srcdir/$pkgname/src"
  for item in "$startdir/src"/*; do
    if [ "$(basename "$item")" != "$pkgname" ]; then
      cp -r "$item" "$srcdir/$pkgname/src/"
    fi
  done
  cp -r "$startdir/assets" "$srcdir/$pkgname/"
  cp "$startdir/Cargo.toml" "$srcdir/$pkgname/"
  cp "$startdir/Cargo.lock" "$srcdir/$pkgname/"
}

build() {
  cd "$srcdir/$pkgname"
  cargo build --release --locked
}

package() {
  cd "$srcdir/$pkgname"
  
  # Install the compiled binary
  install -Dm755 "target/release/vibecheat" "$pkgdir/usr/bin/vibecheat"
  
  # Install the application icon
  install -Dm644 "assets/icon.png" "$pkgdir/usr/share/pixmaps/vibecheat.png"
  install -Dm644 "assets/icon.png" "$pkgdir/usr/share/icons/hicolor/48x48/apps/vibecheat.png"
  install -Dm644 "assets/icon.png" "$pkgdir/usr/share/icons/hicolor/128x128/apps/vibecheat.png"
  install -Dm644 "assets/icon.png" "$pkgdir/usr/share/icons/hicolor/256x256/apps/vibecheat.png"
  install -Dm644 "assets/icon.png" "$pkgdir/usr/share/icons/hicolor/512x512/apps/vibecheat.png"
  install -Dm644 "assets/icon.png" "$pkgdir/usr/share/icons/hicolor/scalable/apps/vibecheat.png"
  
  # Install the desktop entry file
  install -Dm644 "$startdir/vibecheat.desktop" "$pkgdir/usr/share/applications/vibecheat.desktop"
}
