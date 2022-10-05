# zip-dict-attack
Program to determine the password of an encrypted ZIP file via dictionary attack.
Inspired by this [article](https://agourlay.github.io/brute-forcing-protected-zip-rust/).

## Usage
> [Cargo](https://doc.rust-lang.org/cargo/getting-started/installation.html) is used to build the program

Clone the repository and determine the password of example ZIP file.
```shell
git clone https://github.com/raui100/zip_dict_attack
cd zip_dict_attack
# Run the program
RUSTFLAGS='-C target-cpu=native' cargo run --release -- examples/dictionary.txt examples/archive.zip
# Compile the program to "target/release/zip_dict_attack(.exe)"
cargo build --release
```
<details>
  <summary>Help information</summary>

```
./zip_dict_attack --help
Tries to determine the password of a ZIP file via dictionary attack

Usage: zip_dict_attack [OPTIONS] <DICT> <ZIP>

Arguments:
  <DICT>  Path to the dictionary file
  <ZIP>   Path to the ZIP file

Options:
  -p, --progress  Display a progressbar
  -h, --help      Print help information
  -V, --version   Print version information
```

</details>

A proper password dictionary which works on `examples/archive.zip` can be downloaded here:
```shell
wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/xato-net-10-million-passwords.txt
```