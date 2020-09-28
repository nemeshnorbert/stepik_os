#include <iostream>
#include <fstream>
#include <vector>
#include <unordered_map>

template <typename T>
T read_value(std::istream& in) {
    auto value = T{};
    in >> value;
    return value;
}

template <typename T>
void write_value(std::ostream& out, T&& value) {
    out << value;
}

using MemoryRecords = std::unordered_map<std::uint64_t, std::uint64_t>;

struct AddressRemappingData {
    std::uint64_t pml4_table_address;
    std::vector<std::uint64_t> logical_addresses;
    MemoryRecords memory_records;
};

AddressRemappingData read_address_remapping_data(std::istream& in) {
    auto remapping_data = AddressRemappingData{} ;
    auto physical_addresses_count = read_value<std::uint64_t>(in);
    auto logical_addresses_count = read_value<std::uint64_t>(in);
    auto pml4_table_address = read_value<std::uint64_t>(in);

    remapping_data.pml4_table_address = pml4_table_address;

    for (auto address_id = std::uint64_t{0}; address_id < physical_addresses_count; ++address_id) {
        const auto physical_address = read_value<std::uint64_t>(in);
        const auto value = read_value<std::uint64_t>(in);
        remapping_data.memory_records[physical_address] = value;
    }

    remapping_data.logical_addresses = std::vector<std::uint64_t>(logical_addresses_count);
    for (auto address_id = std::uint64_t{0}; address_id < logical_addresses_count; ++address_id) {
        remapping_data.logical_addresses[address_id] = read_value<std::uint64_t>(in);
    }

    return remapping_data;
}

void write_address_remapping_data(
        std::ostream& out,
        const AddressRemappingData& remapping_data) {
    out << remapping_data.memory_records.size() << ' '
        << remapping_data.logical_addresses.size() << ' '
        << remapping_data.pml4_table_address << '\n';
    for (const auto& [address, value] : remapping_data.memory_records) {
        out << address << ' ' << value << '\n';
    }
    for (const auto& logical_address : remapping_data.logical_addresses) {
        out << logical_address << '\n';
    }
}

struct RemappedAddress {
    std::uint64_t address = 0;
    bool is_fault = false;
};


void write_remapped_addresses(std::ostream& out, const std::vector<RemappedAddress>& addresses) {
    for (const auto& remapped_address : addresses) {
        if (remapped_address.is_fault) {
            out << "fault\n";
        } else {
            out << remapped_address.address << '\n';
        }
    }
}

std::uint64_t get_paging_table_entry_address(
        std::uint64_t table_address, std::uint64_t entry_index) {
    const auto ENTRY_SIZE = std::uint64_t{8};
    return table_address + ENTRY_SIZE * entry_index;
}

bool get_value_from_address(
        const MemoryRecords& memory_records, std::uint64_t address, std::uint64_t& value) {
    const auto address_it = memory_records.find(address);
    if (address_it == memory_records.end()) {
        return false;
    }
    value = address_it->second;
    return true;
}

bool get_p_bit_from_paging_entry(std::uint64_t entry) {
    return entry & 1 ? true : false;
}

std::uint64_t get_physical_address_from_paging_entry(std::uint64_t entry) {
    const auto PHYSICAL_ADDRESS_MASK = std::uint64_t{0x000FFFFFFFFFF000};
    return entry & PHYSICAL_ADDRESS_MASK;
}

bool get_remapped_address_from_table(
        const MemoryRecords& memory_records,
        std::uint64_t table_address, std::uint64_t entry_index, std::uint64_t& physical_address) {
    const auto entry_address = get_paging_table_entry_address(table_address, entry_index);
    auto entry = std::uint64_t{0};
    if (!get_value_from_address(memory_records, entry_address, entry)) {
        physical_address = 0;
        return false;
    }
    if (!get_p_bit_from_paging_entry(entry)) {
        physical_address = 0;
        return false;
    }
    physical_address = get_physical_address_from_paging_entry(entry);
    return true;
}

RemappedAddress get_remapped_address(
        std::uint64_t address,
        std::uint64_t pml4_table_address,
        const MemoryRecords& memory_records) {
    const auto TABLE_INDEX_MASK = std::uint64_t{0x00000000000001FF};

    const auto PML4_INDEX_SHIFT = std::uint64_t{39};
    const auto pml4_index = std::uint64_t{(address >> PML4_INDEX_SHIFT) & TABLE_INDEX_MASK};

    const auto DIR_PTR_INDEX_SHIFT = std::uint64_t{30};
    const auto dir_ptr_index = std::uint64_t{(address >> DIR_PTR_INDEX_SHIFT) & TABLE_INDEX_MASK};

    const auto DIR_SHIFT = std::uint64_t{21};
    const auto dir_index = std::uint64_t{(address >> DIR_SHIFT) & TABLE_INDEX_MASK};

    const auto TABLE_SHIFT = std::uint64_t{12};
    const auto table_index = std::uint64_t{(address >> TABLE_SHIFT) & TABLE_INDEX_MASK};

    const auto OFFSET_MASK = std::uint64_t{0x0000000000000FFF};
    const auto offset = std::uint64_t(address & OFFSET_MASK);
    auto dir_ptr_table_address = std::uint64_t{0};
    if (!get_remapped_address_from_table(
            memory_records, pml4_table_address, pml4_index, dir_ptr_table_address)) {
        return RemappedAddress{dir_ptr_table_address, true};
    }
    auto dir_table_address = std::uint64_t{0};
    if (!get_remapped_address_from_table(
            memory_records, dir_ptr_table_address, dir_ptr_index, dir_table_address)) {
        return RemappedAddress{dir_table_address, true};
    }
    auto table_address = std::uint64_t{0};
    if (!get_remapped_address_from_table(
            memory_records, dir_table_address, dir_index, table_address)) {
        return RemappedAddress{table_address, true};
    }
    auto page_address = std::uint64_t{0};
    if (!get_remapped_address_from_table(
            memory_records, table_address, table_index, page_address)) {
        return RemappedAddress{page_address, true};
    }
    return RemappedAddress{page_address + offset, false};
}

std::vector<RemappedAddress> process_remapping_data(const AddressRemappingData& remapping_data) {
    const auto& logical_addresses = remapping_data.logical_addresses;
    const auto& pml4_table_address = remapping_data.pml4_table_address;
    const auto& memory_records = remapping_data.memory_records;
    auto addresses = std::vector<RemappedAddress>{};
    for (const auto& logical_address : logical_addresses) {
        addresses.emplace_back(
            get_remapped_address(logical_address, pml4_table_address, memory_records));
    }
    return addresses;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Please give path to the input and ouput file";
        return 1;
    }
    auto input_file = std::ifstream{};
    input_file.open(argv[1]);
    auto remapping_data = read_address_remapping_data(input_file);
    input_file.close();
    /* write_address_remapping_data(std::cout, remapping_data); */
    const auto remapped_addresses = process_remapping_data(remapping_data);
    auto output_file = std::ofstream{};
    output_file.open(argv[2]);
    write_remapped_addresses(output_file, remapped_addresses);
    output_file.close();
    return 0;
}
