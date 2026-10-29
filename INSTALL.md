# Installing Soqucoin Core

If you're setting up a node for the first time, start with the
[node operators guide](doc/node-operators.md). It walks through download, first
start and the checks that tell you the node is on the right chain. This page is
the reference behind it: which release file fits your system, how to check it,
and how to build from source.

## Release downloads

The current release, 2.6.1, on the [release page](https://github.com/soqucoin/soqucoin/releases)
ships five archives and a `SHA256SUMS` file. Each archive holds two programs at
the top level: `soqucoind`, the node, and `soqucoin-cli`, the command line tool
you use to talk to it (`.exe` on Windows). There's no graphical wallet app and
no 32-bit build. Older releases carried other archives as well, so check the
asset list on the release you download.

| Archive | System | Node wallet |
| :--- | :--- | :--- |
| `linux-x64.tar.gz` | 64-bit Linux, x86-64: Ubuntu 22.04 or newer, Debian 12 or newer, Fedora | Included |
| `linux-arm64.tar.gz` | 64-bit Linux, ARM64: the same distributions, Raspberry Pi OS (Trixie) | Included |
| `macos-arm64.tar.gz` | macOS 15 or later, Apple silicon | Built without it |
| `macos-x64.tar.gz` | macOS 15 or later, Intel | Built without it |
| `windows-x64.zip` | 64-bit Windows | Included |

**Linux.** Both Linux builds carry their libraries and need nothing installed.
They run on any 64-bit Linux with glibc 2.35 or newer: Ubuntu 22.04, Debian 12,
Fedora 36 and anything newer. On an older distribution, build from source. The
2.5.1 Linux builds loaded shared libraries from Ubuntu 22.04 and did not start
elsewhere; 2.5.2 and later replace them.

**macOS.** The macOS builds need macOS 15 (Sequoia) or later. They aren't
notarized by Apple, so if you downloaded them with a browser, macOS blocks the
first run. Clear that from the folder you unpacked into:

```bash
xattr -d com.apple.quarantine soqucoind soqucoin-cli
```

**Windows.** Unzip anywhere, for example `C:\soqucoin`, and run the programs
from PowerShell in that folder.

If you need the node wallet on a Mac, build from source.
The wallet is part of a source build unless you configure with
`--disable-wallet`.

### Checking your download

`SHA256SUMS` lists the SHA-256 hash of every archive in the release. Check the
archive you downloaded against it before you run anything.

On Linux:

```bash
sha256sum --ignore-missing -c SHA256SUMS
```

On macOS:

```bash
shasum -a 256 --ignore-missing -c SHA256SUMS
```

Both print `OK` next to each archive that matches. On Windows, in PowerShell:

```powershell
Get-FileHash .\soqucoin-v2.6.1-windows-x64.zip
Select-String windows SHA256SUMS
```

The two hashes have to match. PowerShell prints its hash in capitals, which
doesn't matter. Use the version number of the release you downloaded in place
of `v2.6.1`.

`SHA256SUMS` isn't signed. A match tells you the archive arrived intact and is
the same file that's on the release page. The archives and `SHA256SUMS` are
built from the tagged commit by the [release workflow](.github/workflows/release.yml)
on GitHub Actions, and the run for each tag is public in the repository's
Actions tab. If you'd rather not trust a prebuilt binary at all, build from
source.

## The node wallet

Soqucoin keys are ML-DSA-44 (Dilithium). ECDSA keys and wallets from other
chains aren't supported.

The wallet RPC surface dates from Bitcoin Core 0.13: there's no `createwallet`
and no `-rpcwallet` argument. The node loads one wallet from its data
directory, and `-disablewallet` turns it off.

To get an address:

```bash
soqucoin-cli getnewaddress
```

Mainnet addresses start with `sq1`. Stagenet addresses start with `ssq1`.

`generatetoaddress` mines blocks on the node's own CPU. It's meant for regtest,
where blocks solve instantly, and isn't a way to mine on mainnet.

## Building from source

Configure checks for these minimums:

- Boost 1.60.0 or later
- OpenSSL
- A C++14 compiler. C++17 is optional, with `--enable-c++17`.

### Ubuntu 24.04

These steps are tested on a fresh Ubuntu 24.04:

```bash
sudo apt install git build-essential libtool autotools-dev automake pkg-config bsdmainutils python3 \
  libssl-dev libevent-dev libboost-all-dev libminiupnpc-dev libzmq3-dev libsqlite3-dev libdb++-dev
git clone https://github.com/soqucoin/soqucoin.git
cd soqucoin
git checkout v2.6.1
./autogen.sh
./configure --without-gui --disable-tests --disable-bench
make -j"$(nproc)"
```

Use the tag of the current release in place of `v2.6.1`. The build takes a few
minutes on a modern machine. On a machine with less than 4 GB of memory, use
`make -j1` so it doesn't run out. The programs end up in `src/`.

Leave out `--disable-tests` if you plan to run the unit tests. Add
`--enable-fuzz` only to build the fuzz targets.

### Other systems

The release workflow, [`.github/workflows/release.yml`](.github/workflows/release.yml),
holds working build steps for Ubuntu 22.04 (x86-64, and cross-compiled for
64-bit ARM), macOS with Homebrew, and Windows cross-compiled from Linux with
MinGW-w64. Those are the steps every release archive is built with.

To build with the exact dependency versions the depends system pins, see
[depends/README.md](depends/README.md) and
[depends/description.md](depends/description.md).

Before building on any system, bring it up to date with its security patches.
An outdated library can leave the whole system open, Soqucoin Core included.

## Data directory

| System | Default data directory |
| :--- | :--- |
| Linux | `~/.soqucoin` |
| macOS | `~/Library/Application Support/Soqucoin` |
| Windows | `%APPDATA%\Soqucoin` |

The node writes `debug.log` there. Stagenet and regtest data go in subfolders
named `stagenet` and `regtest`.

## Testing

Build with tests enabled, then run the unit tests with `make check`. More on
running and extending them is in [src/test/README.md](src/test/README.md).

The Python regression and integration tests are in [qa/rpc-tests](qa/rpc-tests).
With their dependencies installed, run them with `qa/pull-tester/rpc-tests.py`.

## Tips

**Debug builds.** Run `configure` with `--enable-debug`, then `make`. Or pass
your own flags, for example `CXXFLAGS="-g -ggdb -O0"`.

**debug.log.** If the node behaves strangely, look in `debug.log` in the data
directory. Errors and debug messages go there. The `-debug=<category>` option
turns on a category. `-debug` on its own turns on all of them, and the log gets
very large.

**Stagenet and regtest.** `-stagenet` joins the stagenet chain, a rehearsal of
mainnet. `-regtest` starts a private chain on your machine where you create
blocks on demand. The tests in `qa/rpc-tests` run in regtest.

**DEBUG_LOCKORDER.** Soqucoin Core is multithreaded, and deadlocks are hard to
track down. Configuring with `CXXFLAGS="-DDEBUG_LOCKORDER -g"` adds run-time
checks on the order locks are taken in, and writes a warning to `debug.log` when
it finds an inconsistency. `--enable-debug` turns it on as well.
