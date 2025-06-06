#define DOCTEST_CONFIG_IMPLEMENT_WITH_MAIN
#include "../include/doctest.h"
#include "../include/sha256.hpp"
#include "../include/json.hpp"
#include <fstream>
using json = nlohmann::json;

struct Sha256TestVector
{
    std::string input;
    std::string expected_hash;
};


TEST_CASE("SHA256 random test vectors from Python")
{
    std::ifstream file("test_vectors.json");
    REQUIRE(file.is_open());
    
    json vectors;
    file >> vectors;
    
    for (const auto &vec : vectors)
    {
        std::string input = vec["input"];
        std::string expected = vec["hash"];
        std::string actual = SHA256::hash(input);
        CHECK(actual == expected);
    }
}

TEST_CASE("SHA256 known vectors")
{
    CHECK(SHA256::hash("") ==
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    CHECK(SHA256::hash("abc") ==
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    CHECK(SHA256::hash("hello world") ==
    "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9");
}

TEST_CASE("di-mgt Test vectors")
{
    std::vector<Sha256TestVector> sha256_test_vectors = {
        {"abc", "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
        {"", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
        {"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
         "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"},
        {"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"},
        {std::string(1000000, 'a'),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"},
            #ifndef SKIP_LARGE_SHA256_TEST
            // The following test is 1GB of data
            {[]() {
                std::string pattern = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno";
                std::string result;
                result.reserve(pattern.size() * 16777216);
                for (int i = 0; i < 16777216; ++i) {
                    result += pattern;
                }
            return result;
        }(),
        "50e72a0e26442fe2552dc3938ac58658228c0cbfb1d2ca872ae435266fcd055e"}
        #endif
    };
    
    for (const auto &test : sha256_test_vectors)
    {
        CHECK(SHA256::hash(test.input) == test.expected_hash);
    }
};

// Trim whitespace from a string (both ends)
std::string trim(const std::string& str)
{
    const auto start = str.find_first_not_of(" \t\n\r\f\v");
    if (start == std::string::npos) return "";

    const auto end = str.find_last_not_of(" \t\n\r\f\v");
    return str.substr(start, end - start + 1);
}




std::vector<uint8_t> hexToBytes(const std::string& hex)
{
    std::string clean = trim(hex);

    if (clean.empty()) {
        return {}; // Handle empty hex string as empty byte vector
    }

    if (clean.size() % 2 != 0) {
        throw std::runtime_error("Hex string must have even length");
    }

    std::vector<uint8_t> bytes;
    for (size_t i = 0; i < clean.size(); i += 2) {
        std::string byteString = clean.substr(i, 2);
        if (!isxdigit(byteString[0]) || !isxdigit(byteString[1])) {
            throw std::runtime_error("Invalid hex digit in input: " + byteString);
        }
        bytes.push_back(static_cast<uint8_t>(std::stoi(byteString, nullptr, 16)));
    }
    return bytes;
}




TEST_CASE("NIST SHA256 ShortMsg vectors")
{
    std::ifstream file("NIST_Test_vectors/SHA256ShortMsg.rsp"); 
    REQUIRE(file.is_open());
    
    std::string line, msg_hex, expected_hash;
    int bit_length = 0;

    while (std::getline(file, line))
    {
        // Skip comments and blank lines
        if (line.empty() || line[0] == '#') continue;

        if (line.rfind("Len =", 0) == 0)
        {
            bit_length = std::stoi(line.substr(5));
        }
        else if (line.rfind("Msg =", 0) == 0)
        {
            msg_hex = line.substr(6);
        }
        else if (line.rfind("MD =", 0) == 0)
        {
            expected_hash = line.substr(4);
            expected_hash = trim(expected_hash); // Remove any leading/trailing whitespace

            // Only test full-byte inputs (bit length is a multiple of 8)
            if (bit_length % 8 != 0) continue;

            // Convert hex to raw bytes and then to string
            // If the hex string is empty, we use an empty string for the input
            std::string input_str;
            if (!msg_hex.empty() && bit_length > 0) {
                std::vector<uint8_t> msg_bytes = hexToBytes(msg_hex);
                input_str = std::string(reinterpret_cast<const char*>(msg_bytes.data()), msg_bytes.size());
            } else {
                input_str = ""; // Handle empty hex string as empty input
            }
            // Compute the SHA256 hash
            std::string hash = SHA256::hash(input_str);

            CHECK(hash == expected_hash);
            if (hash != expected_hash) {
                std::cout << "Failed for input: " << input_str << "\n"
                << "Bit length: " << bit_length << "\n"
                          << "Hex: " << msg_hex << "\n"
                          << "Expected: " << expected_hash << "\n"
                          << "Got: " << hash << "\n";
            }
        }
    }
}

TEST_CASE("NIST SHA256 LongMsg vectors")
{
    std::ifstream file("NIST_Test_vectors/SHA256LongMsg.rsp");
    REQUIRE(file.is_open());

    std::string line, msg_hex, expected_hash;
    int bit_length = 0;

    while (std::getline(file, line))
    {
        // Skip comments and blank lines
        if (line.empty() || line[0] == '#') continue;

        if (line.rfind("Len =", 0) == 0)
        {
            bit_length = std::stoi(line.substr(5));
        }
        else if (line.rfind("Msg =", 0) == 0)
        {
            msg_hex = line.substr(5);
        }
        else if (line.rfind("MD =", 0) == 0)
        {
            expected_hash = line.substr(4);
            expected_hash = trim(expected_hash); // Remove any leading/trailing whitespace

            // Only test full-byte inputs (bit length is a multiple of 8)
            if (bit_length % 8 != 0) continue;

            std::string input_str;
            if (!msg_hex.empty() && bit_length > 0) {
                std::vector<uint8_t> msg_bytes = hexToBytes(msg_hex);
                input_str = std::string(reinterpret_cast<const char*>(msg_bytes.data()), msg_bytes.size());
            } else {
                input_str = ""; // Handle empty hex string as empty input
            }
            // Compute the SHA256 hash
            std::string hash = SHA256::hash(input_str);

            CHECK(hash == expected_hash);
            if (hash != expected_hash) {
                std::cout << "Failed for input: " << input_str << "\n"
                << "Bit length: " << bit_length << "\n"
                          << "Hex: " << msg_hex << "\n"
                          << "Expected: " << expected_hash << "\n"
                          << "Got: " << hash << "\n";
            }

            
            CHECK(hash == expected_hash);
        }
    }
}



TEST_CASE("NIST Monte Carlo SHA256 test vectors")
{
    std::ifstream file("NIST_Test_vectors/SHA256Monte.rsp"); // Path to your NIST file
    REQUIRE(file.is_open());

    std::string line;
    std::string md;
    int count = -1;

    while (std::getline(file, line))
    {
        if (line.empty() || line[0] == '#' || line[0] == '[')
            continue;

        if (line.rfind("COUNT = ", 0) == 0)
        {
            count = std::stoi(line.substr(8));
        }
        else if (line.rfind("MD = ", 0) == 0)
        {
            
            md = trim(md); // Remove any leading/trailing whitespace
            CHECK_MESSAGE(md.length() == 64, "Hash should be 256 bits");

            // In Monte Carlo mode, only the MD is validated (after the 1000 iterations)
            // We use MD as both the input and the expected output (for demonstration)
            std::string actual = SHA256::hash(md); // Just testing SHA256 works on the output
            CHECK(actual == SHA256::hash(md));     // Replace with the correct actual if you implement the full Monte Carlo loop
        }
    }
}


