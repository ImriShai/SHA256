#ifndef SHA256_H
#define SHA256_H

#include <string>
#include <vector>

/**
 * @brief A class that implements the SHA-256 hashing algorithm based on FIPS PUB 180-4.
 */
class SHA256 {
public:
    /**
     * @brief Compute the SHA-256 hash of a string.
     * @param input The input string.
     * @return The 64-character hexadecimal hash.
     */
    static std::string hash(const std::string& input);

private:
    static const uint32_t K[64];  // Constants used in the SHA-256 algorithm as described in section 4.2.2 of the SHA-256 specification.
    static const uint32_t H0[8];  // Initial hash values as specified in section 5.3.3 of the SHA-256 specification.

    static void padMessage(const std::string& input, std::vector<uint8_t>& padded);
    static void processChunks(const std::vector<uint8_t>& padded, uint32_t hash[8]);
    static void transformChunk(const uint8_t* chunk, uint32_t hash[8]);
    static uint32_t rotr(uint32_t x, uint32_t n);
    static uint32_t choose(uint32_t x, uint32_t y, uint32_t z);
    static uint32_t majority(uint32_t x, uint32_t y, uint32_t z);
    static uint32_t sig0(uint32_t x);
    static uint32_t sig1(uint32_t x);
    static uint32_t ep0(uint32_t x);
    static uint32_t ep1(uint32_t x);
};

#endif // SHA256_H
