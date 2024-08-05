#include <stdio.h>

int main() {
    unsigned long long a = 100000000000000000ULL;
    unsigned long long b = 123456789ULL;
    unsigned long long c = 987654321ULL;

    unsigned long long result1 = (a / 10000) * (b + c);
    unsigned long long result2 = (a / 10000) * b + (a / 10000) * c;

    printf("Result1: %llu\n", result1);
    printf("Result2: %llu\n", result2);

    if (result1 == result2) {
        printf("The results are the same.\n");
    } else {
        printf("The results are different.\n");
    }

    return 0;
}