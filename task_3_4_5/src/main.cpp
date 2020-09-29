#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <numeric>

template <typename T>
T read_value(std::istream& in) {
    auto value = T{};
    in >> value;
    return value;
}

std::vector<std::size_t> read_durations(std::istream& in) {
    const auto tasks_count = read_value<std::size_t>(in);
    auto durations = std::vector<std::size_t>{};
    for (auto task_id = std::size_t{0}; task_id < tasks_count; ++task_id) {
        const auto duration = read_value<std::size_t>(in);
        durations.push_back(duration);
    }
    return durations;
}

void write_ordering(std::ostream& out, const std::vector<std::size_t>& ordering) {
    for (const auto& position : ordering) {
        out << position << ' ';
    }
}

std::vector<std::size_t> compute_ordering(const std::vector<std::size_t>& durations) {
    auto ordering = std::vector<std::size_t>(durations.size());
    std::iota(std::begin(ordering), std::end(ordering), 0);
    std::sort(
        std::begin(ordering), std::end(ordering),
        [&] (const size_t& lhs, const size_t& rhs) -> bool
        { return durations[lhs] < durations[rhs]; });
    return ordering;
}

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cout << "Please give path to the input and ouput file\n";
        return 1;
    }
    auto input_file = std::ifstream{};
    input_file.open(argv[1]);
    auto durations = read_durations(input_file);
    input_file.close();
    const auto ordering = compute_ordering(durations);
    auto output_file = std::ofstream{};
    output_file.open(argv[2]);
    write_ordering(output_file, ordering);
    output_file.close();
    return 0;
}
