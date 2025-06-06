#include <iostream>
#include <fstream>
#include <sstream>
#include "sha256.hpp"

void printUsage(const std::string& prog) {
    std::cerr << "Usage:\n"
              << "  " << prog << " -s \"string to hash\"\n"
              << "  " << prog << " -f filename.txt\n";
}

std::string readFile(const std::string& filename) {
    std::ifstream file(filename);
    if (!file) throw std::runtime_error("Cannot open file: " + filename);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int main(int argc, char* argv[]) {
    try {
        std::string input;

        if (argc == 3) {
            std::string option = argv[1];
            if (option == "-s") {
                input = argv[2];
            } else if (option == "-f") {
                input = readFile(argv[2]);
            } else {
                printUsage(argv[0]);
                return 1;
            }
        } else {
            std::cout << "Enter string to hash: ";
            std::getline(std::cin, input);
        }

        std::string hash = SHA256::hash(input);
        std::cout << "SHA-256: " << hash << std::endl;

    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}
