# Flatpak and Flathub

Proton IP Scanner is published on [Flathub](https://flathub.org) as `org.protonos.ProtonIpScanner`, so it
appears in KDE Discover, GNOME Software and the Flathub website on almost every Linux distribution.

The files are in [`packaging/flatpak/`](../packaging/flatpak):

| File | What it is |
|---|---|
| `org.protonos.ProtonIpScanner.yml` | The Flatpak manifest: runtime, permissions (each one explained) and build steps |
| `cargo-sources.json` | Every Rust crate in `Cargo.lock` with its checksum. Flathub builds without internet, so the build uses only these |

Flathub keeps its own copy of these two files in its repository
[`flathub/org.protonos.ProtonIpScanner`](https://github.com/flathub/org.protonos.ProtonIpScanner); that copy is
what Flathub builds. This folder is the source of truth: change files here, then copy them there.

## Permissions

| Permission | Why |
|---|---|
| `--share=network` | Scanning, ping, name lookups and the online CVE lookups. Also gives `/proc/net/arp` for MAC addresses |
| `--socket=wayland`, `--socket=fallback-x11`, `--share=ipc`, `--device=dri` | The window and OpenGL drawing |
| `--filesystem=xdg-documents` | Reports and exported CVE database files are saved in Documents |
| `--filesystem=xdg-download:ro` | Import an offline CVE database file from Downloads (read only) |

The app never needs root inside or outside the sandbox.

**Nmap (optional engine, 1.4+) is not available in the Flatpak.** The sandbox cannot see programs installed
on the computer, and reaching them would need `--talk-name=org.freedesktop.Flatpak` (`flatpak-spawn --host`),
which is a full sandbox escape — so the Flatpak deliberately does without. The app says so where the Nmap
features would be; everything else works the same. Use the .deb for Nmap features. Settings, the CVE database and the cache go to the
app's private folder `~/.var/app/org.protonos.ProtonIpScanner/`.

## After each release

1. Release as usual (bump `version` in `Cargo.toml`, push to `main`; CI publishes the tag `v<version>`).
2. In `org.protonos.ProtonIpScanner.yml`, set `tag:` to the new tag and `commit:` to its commit
   (`git rev-parse v<version>^{commit}`).
3. If `Cargo.lock` changed, regenerate `cargo-sources.json`:

   ```bash
   git clone --depth 1 https://github.com/flatpak/flatpak-builder-tools.git /tmp/fbt
   python3 -m venv /tmp/fbt-venv
   /tmp/fbt-venv/bin/pip install 'aiohttp>=3.9.5,<4' 'PyYAML>=6,<7' 'tomlkit>=0.13.3,<1'
   /tmp/fbt-venv/bin/python /tmp/fbt/cargo/flatpak-cargo-generator.py Cargo.lock \
       -o packaging/flatpak/cargo-sources.json
   ```

4. Copy both files into the Flathub repository and open a pull request there. Flathub builds it, posts a
   test build link on the pull request, and publishes after you merge.

CI checks on every push that `cargo-sources.json` matches `Cargo.lock`, builds the Flatpak from the pushed
code exactly as Flathub does, runs Flathub's linter, and starts the app inside the sandbox. Each run also
uploads a `.flatpak` file (Actions → the run → Artifacts) that you can install for testing:

```bash
flatpak install --user proton-ip-scanner.flatpak
flatpak run org.protonos.ProtonIpScanner
```

## Build it yourself

```bash
flatpak remote-add --user --if-not-exists flathub https://dl.flathub.org/repo/flathub.flatpakrepo
flatpak install --user flathub org.flatpak.Builder
flatpak run org.flatpak.Builder --user --install --force-clean --install-deps-from=flathub \
    builddir packaging/flatpak/org.protonos.ProtonIpScanner.yml
```

This builds the tagged release named in the manifest.
