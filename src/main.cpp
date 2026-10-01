#include "Poc.hpp"

#include <iostream>
#include <stdexcept>
#include <string>

namespace {

void PrintUsage(const char* program) {
    std::cout
        << "usage:\n"
        << "  " << program << " scan\n"
        << "  " << program << " prove <index> --authorized\n"
        << "  " << program << " restore\n";
}

}

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string(argv[1]) == "scan") {
        return RunScan();
    }

    if (argc == 4 && std::string(argv[1]) == "prove" &&
        std::string(argv[3]) == "--authorized") {
        try {
            std::size_t consumed = 0;
            const std::string value = argv[2];
            const auto index = std::stoull(value, &consumed);
            if (consumed != value.size()) {
                throw std::invalid_argument("index");
            }
            return RunProof(static_cast<std::size_t>(index));
        } catch (const std::exception&) {
            std::cerr << "invalid target index\n";
            return 1;
        }
    }

    if (argc == 2 && std::string(argv[1]) == "restore") {
        return RunRestore();
    }

    if (argc >= 2 && std::string(argv[1]) == "prove") {
        std::cerr << "proof execution requires --authorized\n";
        return 1;
    }

    PrintUsage(argc > 0 ? argv[0] : "discord-lpe-poc.exe");
    return argc == 1 ? 0 : 1;
}
