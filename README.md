# OpenForti Manager

A native GTK4 + libadwaita GUI front-end for [openfortivpn](https://github.com/adrienverge/openfortivpn), the Fortinet SSL-VPN client.

## Features

- **VPN profile management** — create, edit, and save multiple connection profiles
- **System tray integration** — background mode with status indicator icon (green/orange/red)
- **SAML login support** — auto-opens the authentication URL in your browser
- **Certificate trust management** — configure CA bundles, user certificates, and trusted SHA256 digests
- **Quick Connect** — reconnect to the last used profile from the tray menu
- **Minimize after connect** — window auto-hides to tray when the tunnel comes up
- **Auto-detection** — recognizes manually-started openfortivpn sessions and shows their status

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
│ │ [out] INFO:   Tunnel is up.              │ │
│ │ [out] INFO:   Connected to gateway.      │ │
│ └──────────────────────────────────────────┘ │
└──────────────────────────────────────────────┘
```

## Dependencies

| Package | Purpose |
|----------|---------|
| `openfortivpn` | The VPN client itself |
| `libgtk-4-dev` | GTK4 GUI toolkit |
| `libadwaita-1-dev` | Modern GNOME widgets |
| `libayatana-appindicator3-dev` | System tray support |
| `pkexec` (from `polkit`) | Privilege escalation for the VPN process |

**Ubuntu / Debian:**
```bash
sudo apt install openfortivpn libgtk-4-dev libadwaita-1-dev \
  libayatana-appindicator3-dev libx11-dev libglib2.0-dev \
  gcc pkg-config
```

**Fedora:**
```bash
sudo dnf install openfortivpn gtk4-devel libadwaita-devel \
  libayatana-appindicator3-devel libX11-devel glib2-devel \
  gcc pkg-config
```

**Arch Linux:**
```bash
sudo pacman -S openfortivpn gtk4 libadwaita \
  libayatana-appindicator gcc pkgconf
```

## Build from source

```bash
git clone https://github.com/kowalk/open-forti-manager.git
cd open-forti-manager
cargo build --release
```

The binary will be at `target/release/open-forti-manager`.  Run it:

```bash
./target/release/open-forti-manager
```

## Install the .deb package (Ubuntu / Debian)

Download the latest `.deb` from the [Releases](https://github.com/kowalk/open-forti-manager/releases) page, then:

```bash
sudo apt install ./open-forti-manager_*.deb
```

This installs the binary, desktop entry, and all required system dependencies.

## How it works

OpenForti Manager spawns `openfortivpn` via `pkexec` for privilege escalation.  A Polkit password dialog appears when you click **Connect**.  Log output from the openfortivpn process is captured and displayed in the **Connection** tab.

The system tray icon shows the connection state:
- **Gray** — disconnected
- **Orange** — connecting
- **Green** — connected
- **Red** — error

## Configuration

Profiles and settings are stored in:

```
~/.config/open-forti-manager/config.json
```

## Versioning

This project follows [Semantic Versioning](https://semver.org/).  Version tags (`vMAJOR.MINOR.PATCH`) trigger the GitHub Actions release workflow, which builds and publishes a `.deb` package.

## License

MIT
