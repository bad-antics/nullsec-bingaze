# NullSec BinGaze

**Hardened Binary Analysis Toolkit**

A security-focused ELF binary analyzer written in modern C++20 with defense-in-depth principles.

## Features

- **ELF Header Analysis** - Parse and display comprehensive ELF header information
- **Section Analysis** - Enumerate sections with entropy calculation
- **Security Assessment** - Automated security posture evaluation
- **Memory Safety** - RAII, smart pointers, bounds-checked containers

## Security Features

- Bounds-checked operations using `std::span`
- RAII resource management with `SecureBuffer`
- Secure memory zeroing to prevent data leakage
- Input validation on all operations
- Compiled with battle-tested security flags

## Build

```bash
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
make
```

## Build with Sanitizers (Debug)

```bash
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
```

## Usage

```bash
# Full analysis
./bingaze -a /bin/ls

# Security assessment only
./bingaze -S /usr/bin/ssh

# Section listing
./bingaze -s ./my_binary
```

## Security Assessment Checks

- ✓ NX Stack (Non-Executable Stack)
- ✓ PIE (Position Independent Executable)
- ✓ RELRO (Read-Only Relocations)
- ✓ Stack Canary Detection
- ✓ RWX Segment Detection

## Compiler Hardening

Built with:
- `-fstack-protector-strong`
- `-D_FORTIFY_SOURCE=2`
- `-fPIE -pie`
- `-Wl,-z,relro,-z,now`
- `-Wl,-z,noexecstack`

## License

NullSec Proprietary - For authorized security research only.

## Author

bad-antics


## 👤 Author

**bad-antics**
- GitHub: [@bad-antics](https://github.com/bad-antics)
- Website: [bad-antics.github.io](https://bad-antics.github.io)
- Discord: [discord.gg/killers](https://discord.gg/killers)

---

<div align="center">

**Part of the NullSec Security Framework**

</div>
