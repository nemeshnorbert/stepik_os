#include <iostream>
#include <fstream>
#include <vector>

#define PT_LOAD        1
#define ELF_NIDENT    16

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

struct elf_phdr {
    std::uint32_t p_type;
    std::uint32_t p_flags;
    std::uint64_t p_offset;
    std::uint64_t p_vaddr;
    std::uint64_t p_paddr;
    std::uint64_t p_filesz;
    std::uint64_t p_memsz;
    std::uint64_t p_align;
} __attribute__((packed));

template <typename T>
T read_value_from_file(std::ifstream& file) {
    constexpr std::size_t BUFFER_SIZE = sizeof(T);
    char buffer[BUFFER_SIZE];
    file.read(buffer, BUFFER_SIZE);
    return *reinterpret_cast<T*>(buffer);
}

template <typename T>
T read_value_from_file_at(std::ifstream& file, std::streamsize pos) {
    return read_value_from_file<T>(file);
}

elf_hdr read_elf_header_impl(std::ifstream& elf_file) {
    elf_hdr header;
    for (std::size_t idx = 0; idx < ELF_NIDENT; ++idx) {
        header.e_ident[idx] = read_value_from_file<std::uint8_t>(elf_file);
    }
    header.e_type      = read_value_from_file<std::uint16_t>(elf_file);
    header.e_machine   = read_value_from_file<std::uint16_t>(elf_file);
    header.e_version   = read_value_from_file<std::uint32_t>(elf_file);
    header.e_entry     = read_value_from_file<std::uint64_t>(elf_file);
    header.e_phoff     = read_value_from_file<std::uint64_t>(elf_file);
    header.e_shoff     = read_value_from_file<std::uint64_t>(elf_file);
    header.e_flags     = read_value_from_file<std::uint32_t>(elf_file);
    header.e_ehsize    = read_value_from_file<std::uint16_t>(elf_file);
    header.e_phentsize = read_value_from_file<std::uint16_t>(elf_file);
    header.e_phnum     = read_value_from_file<std::uint16_t>(elf_file);
    header.e_shentsize = read_value_from_file<std::uint16_t>(elf_file);
    header.e_shnum     = read_value_from_file<std::uint16_t>(elf_file);
    header.e_shstrndx  = read_value_from_file<std::uint16_t>(elf_file);
    return header;
}

elf_hdr read_elf_header(const char* name) {
    std::ifstream elf_file;
    elf_file.open(name, std::ios::binary);
    elf_hdr header = read_elf_header_impl(elf_file);
    elf_file.close();
    return header;
}

elf_phdr read_elf_program_header(std::ifstream& elf_file) {
    elf_phdr program_header;
    program_header.p_type   = read_value_from_file<std::uint32_t>(elf_file);
    program_header.p_flags  = read_value_from_file<std::uint32_t>(elf_file);
    program_header.p_offset = read_value_from_file<std::uint64_t>(elf_file);
    program_header.p_vaddr  = read_value_from_file<std::uint64_t>(elf_file);
    program_header.p_paddr  = read_value_from_file<std::uint64_t>(elf_file);
    program_header.p_filesz = read_value_from_file<std::uint64_t>(elf_file);
    program_header.p_memsz  = read_value_from_file<std::uint64_t>(elf_file);
    program_header.p_align  = read_value_from_file<std::uint64_t>(elf_file);
    return program_header;
}

std::vector<elf_phdr> read_elf_program_headers_impl(std::ifstream& elf_file) {
    elf_hdr header = read_elf_header_impl(elf_file);
    std::vector<elf_phdr> program_headers;
    program_headers.reserve(header.e_phnum);
    elf_file.seekg(header.e_phoff);
    for (std::size_t idx = 0; idx < header.e_phnum; ++idx) {
        program_headers.emplace_back(read_elf_program_header(elf_file));
    }
    return program_headers;
}

std::vector<elf_phdr> read_elf_program_headers(const char* name) {
    std::ifstream elf_file;
    elf_file.open(name, std::ios::binary);
    std::vector<elf_phdr> program_headers = read_elf_program_headers_impl(elf_file);
    elf_file.close();
    return program_headers;
}

std::size_t space(const char *name)
{
    std::vector<elf_phdr> program_headers = read_elf_program_headers(name);
    std::size_t memory_size = 0;
    for (std::size_t idx = 0; idx < program_headers.size(); ++idx) {
        const auto& program_header = program_headers[idx];
        if (program_header.p_type == PT_LOAD) {
            memory_size += program_headers[idx].p_memsz;
        }
    }
    return memory_size;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cout << "Please provide path to the elf file\n";
    }
    std::cout << space(argv[1]) << '\n';
    return 0;
}
