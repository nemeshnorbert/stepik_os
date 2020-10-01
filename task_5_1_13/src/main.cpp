#define ELF_NIDENT    16

#include <iostream>
#include <fstream>
#include <bitset>


// Эта структура описывает формат заголовока ELF файла
struct elf_hdr {
    std::uint8_t e_ident[ELF_NIDENT];
    std::uint16_t e_type;
    std::uint16_t e_machine;
    std::uint32_t e_version;
    std::uint64_t e_entry;
    std::uint64_t e_phoff;
    std::uint64_t e_shoff;
    std::uint32_t e_flags;
    std::uint16_t e_ehsize;
    std::uint16_t e_phentsize;
    std::uint16_t e_phnum;
    std::uint16_t e_shentsize;
    std::uint16_t e_shnum;
    std::uint16_t e_shstrndx;
} __attribute__((packed));


std::uintptr_t entry_point(const char *name)
{
    std::ifstream elf_file;
    elf_file.open(name, std::ios::binary);
    constexpr size_t E_ENTRY_POSITION = 1 * ELF_NIDENT + 2 + 2 + 4;
    constexpr size_t E_ENTRY_SIZE = 8;

    elf_file.seekg(E_ENTRY_POSITION);
    char e_entry_buffer[E_ENTRY_SIZE];
    elf_file.read(e_entry_buffer, E_ENTRY_SIZE);

    return *reinterpret_cast<std::uint64_t*>(e_entry_buffer);
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Please provide path to the elf file\n";
    }
    std::cout << entry_point(argv[1]) << '\n';
    return 0;
}
