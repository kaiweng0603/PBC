# PBC BLS Signature Demo

National Taiwan Ocean University Security Project

## Features

- BLS Signature
- Pairing-Based Cryptography
- Signature Compression
- Signature Decompression
- Simulated Network Transfer

## Environment

Ubuntu 24.04 LTS

## Required Libraries

### GMP

```bash
sudo apt update
sudo apt install libgmp-dev -y
```

### PBC

```bash
wget http
s://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz

tar -zxvf pbc-0.5.14.tar.gz

cd pbc-0.5.14

./configure

make

sudo make install

sudo ldconfig
```

## Project Structure

```text
PBC/
├── BLS.c
├── Makefile
├── README.md
├── .gitignore
└── param
    └── a.param
```

## Build

```bash
make
```

## Run

```bash
make run
```

## Clean

```bash
make clean
```

## Author

Andy Chen# -
資工系專題 PBC
