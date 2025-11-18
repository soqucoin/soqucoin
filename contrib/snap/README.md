# Soqucoin Snap Packaging

Commands for building and uploading a Soqucoin Core Snap to the Snap Store. Anyone on amd64 (x86_64), arm64 (aarch64), or i386 (i686) should be able to build it themselves with these instructions. This would pull the official Soqucoin binaries from the releases page, verify them, and install them on a user's machine.

## Building Locally
```
sudo apt install snapd
sudo snap install --classic snapcraft
sudo snapcraft
```

### Installing Locally
```
snap install \*.snap --devmode
```

### To Upload to the Snap Store
```
snapcraft login
snapcraft register soqucoin-core
snapcraft upload \*.snap
sudo snap install soqucoin-core
```

### Usage
```
soqucoin-unofficial.cli # for soqucoin-cli
soqucoin-unofficial.d # for soqucoind
soqucoin-unofficial.qt # for soqucoin-qt
soqucoin-unofficial.test # for test_soqucoin
soqucoin-unofficial.tx # for soqucoin-tx
```

### Uninstalling
```
sudo snap remove soqucoin-unofficial
```