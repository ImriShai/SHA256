#include "sha256.hpp"
#include <sstream>
#include <iomanip>
#include <cstring>

/**
 * @file sha256.cpp
 * @brief Implementation of the SHA-256 hashing algorithm based on the specification from FIPS PUB 180-4.
 */

// Initial hash values (first 32 bits of the fractional parts of the square roots of the first 8 primes)
static const uint32_t H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372,
    0xa54ff53a, 0x510e527f, 0x9b05688c,
    0x1f83d9ab, 0x5be0cd19
};

// SHA-256 constants (first 32 bits of the fractional parts of the cube roots of the first 64 primes)
const uint32_t SHA256::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf,
    0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98,
    0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7,
    0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
    0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8,
    0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85,
    0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e,
    0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819,
    0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c,
    0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee,
    0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7,
    0xc67178f2
};

/**
 * @brief Computes the SHA-256 hash of the input string.
 * @param input The input string to hash.
 * @return The hexadecimal string representation of the hash.
 */
std::string SHA256::hash(const std::string& input) {
    std::vector<uint8_t> padded;
    // Pad the input message according to SHA-256 specification
    padMessage(input, padded);

    uint32_t hash[8];
    // Initialize hash values
    std::memcpy(hash, H0, sizeof(H0));

    // Process the padded message in 512-bit (64-byte) chunks
    processChunks(padded, hash);

    // Convert the resulting hash to a hexadecimal string
    std::stringstream ss;
    for (int i = 0; i < 8; i++) {
        ss << std::hex << std::setw(8) << std::setfill('0') << hash[i];
    }
    return ss.str();
}

/**
 * @brief Pads the input message according to the SHA-256 specification.
 * @param input The input string to pad.
 * @param padded The output vector containing the padded message bytes.
 */
void SHA256::padMessage(const std::string& input, std::vector<uint8_t>& padded) {
    // Copy input bytes to padded vector
    padded.assign(input.begin(), input.end());

    // Calculate the message length in bits
    uint64_t bitLen = static_cast<uint64_t>(input.size()) * 8;

    // Append the '1' bit (0x80)
    padded.push_back(0x80);

    // Append '0' bits until the length is congruent to 56 mod 64
    while ((padded.size() + 8) % 64 != 0)
        padded.push_back(0x00);

    // Append the original message length as a 64-bit big-endian integer
    for (int i = 7; i >= 0; i--) {
        padded.push_back(static_cast<uint8_t>((bitLen >> (i * 8)) & 0xff));
    }
}

/**
 * @brief Processes the padded message in 512-bit chunks.
 * @param padded The padded message bytes.
 * @param hash The hash state array to update.
 */
void SHA256::processChunks(const std::vector<uint8_t>& padded, uint32_t hash[8]) {
    // Process each 64-byte chunk
    for (size_t i = 0; i < padded.size(); i += 64) {
        transformChunk(&padded[i], hash);
    }
}

/**
 * @brief Transforms a single 512-bit chunk and updates the hash state.
 * @param chunk Pointer to the start of the 64-byte chunk.
 * @param hash The hash state array to update.
 */
void SHA256::transformChunk(const uint8_t* chunk, uint32_t hash[8]) {
    uint32_t w[64];

    // Prepare the message schedule
    for (int i = 0; i < 16; i++) {
        w[i] = (chunk[i * 4] << 24) |
               (chunk[i * 4 + 1] << 16) |
               (chunk[i * 4 + 2] << 8) |
               (chunk[i * 4 + 3]);
    }

    for (int i = 16; i < 64; i++) {
        w[i] = sig1(w[i - 2]) + w[i - 7] + sig0(w[i - 15]) + w[i - 16];
    }

    // Initialize working variables with current hash value
    uint32_t a = hash[0];
    uint32_t b = hash[1];
    uint32_t c = hash[2];
    uint32_t d = hash[3];
    uint32_t e = hash[4];
    uint32_t f = hash[5];
    uint32_t g = hash[6];
    uint32_t h = hash[7];

    // Main compression function
    for (int i = 0; i < 64; i++) {
        uint32_t temp1 = h + ep1(e) + choose(e, f, g) + K[i] + w[i];
        uint32_t temp2 = ep0(a) + majority(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    // Add the compressed chunk to the current hash value
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h;
}

/**
 * @brief Performs right rotation on a 32-bit integer.
 * @param x The value to rotate.
 * @param n The number of bits to rotate.
 * @return The rotated value.
 */
uint32_t SHA256::rotr(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

/**
 * @brief SHA-256 choose function: (e AND f) XOR ((NOT e) AND g)
 * @param e First input.
 * @param f Second input.
 * @param g Third input.
 * @return The result of the choose function.
 */
uint32_t SHA256::choose(uint32_t e, uint32_t f, uint32_t g) {
    return (e & f) ^ (~e & g);
}

/**
 * @brief SHA-256 majority function: (a AND b) XOR (a AND c) XOR (b AND c)
 * @param a First input.
 * @param b Second input.
 * @param c Third input.
 * @return The result of the majority function.
 */
uint32_t SHA256::majority(uint32_t a, uint32_t b, uint32_t c) {
    return (a & b) ^ (a & c) ^ (b & c);
}

/**
 * @brief SHA-256 small sigma 0 function.
 * @param x Input value.
 * @return The result of the function.
 */
uint32_t SHA256::sig0(uint32_t x) {
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

/**
 * @brief SHA-256 small sigma 1 function.
 * @param x Input value.
 * @return The result of the function.
 */
uint32_t SHA256::sig1(uint32_t x) {
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

/**
 * @brief SHA-256 big sigma 0 function.
 * @param x Input value.
 * @return The result of the function.
 */
uint32_t SHA256::ep0(uint32_t x) {
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

/**
 * @brief SHA-256 big sigma 1 function.
 * @param x Input value.
 * @return The result of the function.
 */
uint32_t SHA256::ep1(uint32_t x) {
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}
