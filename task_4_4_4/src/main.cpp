struct atomic_int;

int load_linked(atomic_int *x);

bool store_conditional(atomic_int *x, int new_value);

int atomic_fetch_add(atomic_int *x, int arg)
{
    int new_value = 0;
    int x_value = 0;
    do {
        x_value = load_linked(x);
        new_value = x_value + arg;
    } while (!store_conditional(x, new_value));
    return x_value;
}

bool atomic_compare_exchange(atomic_int *x, int *expected_value, int new_value)
{
    while (true) {
        int x_value = load_linked(x);
        if (x_value == *expected_value) {
            if (store_conditional(x, new_value)) {
                return true;
            }
        } else {
            *expected_value = x_value;
            return false;
        }
    }
    return false;
}

int main() {
    // This code is not compilable since we
    // don't have definition of atomic_int, load_linked and store_conditional
    return 0;
}
