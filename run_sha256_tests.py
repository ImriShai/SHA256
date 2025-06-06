import subprocess
import hashlib
import random
import string
import json
import os
import argparse 

def random_string(length):
    return ''.join(random.choices(string.printable, k=length))

def generate_vectors(filename="test_vectors.json", count=100):
    test_vectors = []
    for _ in range(count):
        msg = random_string(random.randint(0, 512))
        digest = hashlib.sha256(msg.encode()).hexdigest()
        test_vectors.append({"input": msg, "hash": digest})

    with open(filename, "w") as f:
        json.dump(test_vectors, f, indent=2)

    print(f"✅ Generated {count} test vectors to {filename}")

def build_tests():
    print("🔧 Building test suite with make...")
    result = subprocess.run(["make", "test"], capture_output=True, text=True)
    if result.returncode != 0:
        print("❌ Build failed:\n", result.stderr)
        return False
    print("✅ Build complete.")
    return True

def run_tests():
    print("🚀 Running test suite...")
    result = subprocess.run(["./test"])
    if result.returncode == 0:
        print("✅ All tests passed!")
    else:
        print("❌ Some tests failed!")

def main():
    parser = argparse.ArgumentParser(description="SHA256 test runner")
    parser.add_argument("--generate-only", action="store_true", help="Only generate test vectors JSON and exit")
    args = parser.parse_args()

    generate_vectors()
    if args.generate_only:
        return
    if build_tests():
        run_tests()

if __name__ == "__main__":
    main()
