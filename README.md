# OpenForti Manager

A native Fortinet SSL-VPN client for Linux with a GTK4 + libadwaita GUI.

Unlike a thin front-end, OpenForti Manager speaks the Fortinet SSL-VPN protocol
**directly** — TLS handshake, HTTP/SAML authentication, tunnel allocation, and a
pure-Rust **PPP state machine** (LCP + IPCP) over a TUN device. There is **no
external `openfortivpn` binary and no `pppd`** — the entire data path is
implemented in Rust.

## Features

- **Fully native VPN engine** — TLS, auth, PPP/IPCP negotiation, and TUN data
  relay implemented in Rust; no `openfortivpn` or `pppd` processes
- **VPN profile management** — create, edit, and save multiple connection profiles
- **SAML login support** — auto-opens the authentication URL in your browser and
  captures the callback locally
- **Certificate trust management** — configure CA bundles, user certificates, and
  trusted SHA256 digests (`--trusted-cert`)
- **Split tunneling & split DNS** — installs the gateway's routes and routes the
  gateway's DNS domains (`*.corp.example`) to the VPN resolvers automatically
- **System tray integration** — background mode with a status indicator icon
- **Quick Connect / Disconnect** from the tray menu
- **Minimize after connect** — window auto-hides to tray when the tunnel comes up

## Screenshot

```
┌──────────────────────────────────────────────┐
│ 🟢 Connected    [Disconnect]                 │  ← Header bar
├──────────────────────────────────────────────┤
│ Connection │ Profiles │ Certificates │ Settings│  ← Tabs
├──────────────────────────────────────────────┤
│ Profile: [My Corp VPN ▾]                     │
│                                              │
│ ┌─ Log ────────────────────────────────────┐ │
│ │ [engine] PPP: NETWORK phase reached —    │ │
│ │          tunnel is fully established!    │ │
│ └──────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
```

## How it works

On **Connect**, the native engine:

1. Opens a TLS connection to the gateway (with optional trusted-cert pinning).
2. Authenticates — password or **SAML** (opens the browser, waits for the
   callback on a local port, exchanges the session ID for the `SVPNCOOKIE`).
3. Allocates a tunnel slot and fetches the VPN config (assigned IP, DNS servers,
   split routes, split-DNS domains).
4. Creates a **TUN** interface and runs a pure-Rust **PPP** negotiation
   (LCP → IPCP) until the link reaches the **network** phase.
5. Configures the interface IP, installs split-tunnel routes, sets the VPN DNS
   servers and routes the split-DNS domains to them.
6. Relays IP packets between the TUN device and the gateway over TLS.

The system tray icon shows the connection state:
- **Gray** — disconnected
- **Orange** — connecting
- **Green** — connected
- **Red** — error

### Privileges

Creating and configuring the TUN interface requires the **`CAP_NET_ADMIN`**
capability. You do **not** need to run the whole GUI as root:

- The **`.deb` package sets this automatically** on install (see below).
- For a **source build**, grant it once after building:

  ```bash
  sudo setcap cap_net_admin+eip target/release/open-forti-manager
  ```

Route and DNS setup additionally need root (`ip route`, `resolvectl`). The app
elevates with the least privilege available, in order:

1. run directly if already root;
2. **passwordless `sudo`** for the exact `ip route` / `resolvectl` commands, if a
   sudoers rule allows it (no prompt);
3. otherwise a single **`pkexec`** prompt per connect.

The **`.deb` installs the narrow sudoers rule automatically** (validated with
`visudo` first, and removed on uninstall), so connecting is prompt-free out of
the box. For a **source build**, add it yourself if you want no prompt — note it
is scoped to the route-table / resolved commands only, *not* a root shell:

```
# /etc/sudoers.d/open-forti-manager  (mode 0440)
%sudo ALL=(root) NOPASSWD: /usr/sbin/ip route *, /usr/sbin/ip -6 route *, /usr/bin/resolvectl *
```

Without any such rule, everything still works — you just get one `pkexec`
prompt each time you connect.

## Dependencies

| Package | Purpose |
|----------|---------|
| `libgtk-4-1` | GTK4 GUI toolkit |
| `libadwaita-1-0` | Modern GNOME widgets |
| `libayatana-appindicator3-1` | System tray support |
| `libcap2-bin` | Provides `setcap` for granting `CAP_NET_ADMIN` |
| `pkexec` (from `polkit`) | Privilege escalation for teardown helpers |

> Note: `openfortivpn` is **no longer required** — the VPN engine is native.

**Ubuntu / Debian (build):**
```bash
sudo apt install libgtk-4-dev libadwaita-1-dev \
  libayatana-appindicator3-dev libx11-dev libglib2.0-dev \
  libcap2-bin gcc pkg-config
```

**Fedora (build):**
```bash
sudo dnf install gtk4-devel libadwaita-devel \
  libayatana-appindicator3-devel libX11-devel glib2-devel \
  libcap gcc pkg-config
```

**Arch Linux (build):**
```bash
sudo pacman -S gtk4 libadwaita libayatana-appindicator \
  libcap gcc pkgconf
```

## Build from source

```bash
git clone https://github.com/kowalk/open-forti-manager.git
cd open-forti-manager
cargo build --release

# Grant the network capability (needed to create the TUN device):
sudo setcap cap_net_admin+eip target/release/open-forti-manager
```

Run it:

```bash
./target/release/open-forti-manager
```

## Install the .deb package (Ubuntu / Debian)

Download the latest `.deb` from the [Releases](https://github.com/kowalk/open-forti-manager/releases) page, then install:

```bash
# Ubuntu's apt sandbox requires the .deb in a world-readable location.
# Move it to /tmp first to avoid "Permission denied" errors:
sudo cp ~/Downloads/open-forti-manager_*.deb /tmp/
sudo apt install /tmp/open-forti-manager_*.deb
```

Alternatively, use `dpkg` directly:

```bash
sudo dpkg -i ~/Downloads/open-forti-manager_*.deb
sudo apt install -f  # Fix any missing dependencies
```

The package's post-install script automatically runs
`setcap cap_net_admin+eip /usr/bin/open-forti-manager`, so the app can create the
TUN interface without being run as root.

## Configuration

Profiles and settings are stored in:

```
~/.config/open-forti-manager/config.json
```

## Versioning

This project follows [Semantic Versioning](https://semver.org/). Version tags
(`vMAJOR.MINOR.PATCH`) trigger the GitHub Actions release workflow, which builds
and publishes a `.deb` package (with the capability-granting post-install script).

## License

MIT
