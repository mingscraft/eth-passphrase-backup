# 🔐 Ethereum HD wallet passphase backup utilities 🔥
Commandline tool to keep your Ethereume HD wallet passphrase safe and secure.

The tool make use of [Shamir Secret Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
to create backup of your hardware wallet in a secure way. The backup consits of multiple shares, so they can be stored in separate
locations. The goal to the tool is to mitigate risk of store the HD wallet passphrase in a single locations,
and lost of HD wallet passphrase.

## Important notes
- ✅ The tool should run in an offline machine, clean the trace after shares were generate.
- 🚨 Use at your own risk.

## Install

### Install from homebrew
```
brew tap codeandplay/tap
brew install sss
```

### Install from source
```
cargo install --path .
```

## Usage
### Create backup shares
```
sss backup -p "piano season cat siege sibling convince melt lonely appear crunch few admit"
```

### Restore from shares
```
sss restore -s "absurd ticket pistol woman glass bleak tree observe express winner nephew cash track" \
    "admit pulse salon boat spin bring history virtual future gadget fresh tone fox" \
    "air case arch month sight tray wool flag chat thunder coast matter camp"
```

