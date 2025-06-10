# SHA-256 Implementation (FIPS 180-4)

This project is a clean and testable C++ implementation of the [SHA-256 cryptographic hash algorithm](https://www.simplilearn.com/tutorials/cyber-security-tutorial/sha-256-algorithm), as specified in [FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf) by NIST.

It includes:
- A standalone SHA-256 implementation in C++
- A test suite with official NIST test vectors (including Monte Carlo tests)
- Integration with Python for cross-verification
- Support for Valgrind memory analysis

---

## 🛠️ Build Instructions

### Prerequisites
- C++ compiler supporting C++17 (e.g., `g++`)
- Python 3
- [doctest](https://github.com/doctest/doctest) (header-only, included in the repo or in test files)

### To Build Everything:
```bash
make
```

This builds:
- `main`: A simple CLI program that can hash strings or files.
- `test`: A test binary using NIST vectors and unit tests.

---

## 🚀 Run the Programs

### Run the Main Program:
```bash
./main
```

You can modify `main.cpp` to hash strings or files based on your needs.

**Usage:**  
The `main` program accepts the following arguments, only one at a time:
- `-s "string"`: Hash the provided string.
- `-f filename.txt`: Hash the contents of the specified file.

If no arguments are given, the program will prompt you to enter a string via standard input and then display its SHA-256 hash.

### Run the Tests:
```bash
make run
```

This will:
- Generate test vectors via Python (`run_sha256_tests.py`)
- Build the test binary
- Clear the terminal and execute the test suite

---

## 📦 Makefile Targets

| Target        | Description |
|---------------|-------------|
| `make`        | Build all binaries (`main`, `test`) |
| `make run`    | Build and run tests (clears screen) |
| `make python_test` | Run Python SHA-256 test suite |
| `make generate` | Generate `test_vectors.json` via Python |
| `make valgrind` | Build and run binaries under Valgrind |
| `make clean` | Remove all build artifacts |

---

## 📄 File Structure

```
.
├── include/
│   └── sha256.hpp            # Header for SHA-256 implementation
│   └── doctest.hpp           # Header for DOCTEST
│   └── json.hpp              # Header for json parser
├── src/
│   └── sha256.cpp            # SHA-256 logic
├── NIST_Test_vectors/
│   └── SHA256LongMsg.rsp     # The NIST long message test vectors for SHA-256
│   └── SHA256ShortMsg.rsp    # The NIST short message test vectors for SHA-256
│   └── SHA256MonteCarlo.rsp  # The NIST Monte Carlo test vectors for SHA-256
├── tests/
│   └── test_sha256.cpp       # Unit tests + NIST vector validation
├── run_sha256_tests.py       # Python validator using hashlib
├── main.cpp                  # Simple interface for SHA-256
├── Makefile
└── README.md
```

---

## ✅ Test Coverage

The test suite verifies the implementation using:
- Short known-answer tests
- Edge cases (empty string, long input, etc.)
- NIST [Monte Carlo test vectors](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing)

Example Monte Carlo test logic:
- Uses `Seed` as initial state
- Computes SHA-256 iteratively 1000 times
- Validates the final hash

---

## 🧪 Python Test Vector Generator

We use Python's `hashlib` to cross-check the C++ implementation. The Python script:
- Generates test vectors
- Saves results in `test_vectors.json`
- Is used as ground truth for validating `sha256.cpp`

Run with:
```bash
make python_test
```

---

## 🔐 FIPS 180-4 Reference

This SHA-256 implementation follows the official specification:

> FIPS PUB 180-4: [Secure Hash Standard (SHS)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)

---

## 🧹 Cleaning Up

To remove all build files and artifacts:
```bash
make clean
```

---

## 📋 License

You may adapt and use this code for academic or educational purposes. For production or cryptographic-grade systems, always rely on verified libraries such as OpenSSL or libsodium.