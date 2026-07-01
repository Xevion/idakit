#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int accumulate(const int *xs, int n) {
    int total = 0;
    for (int i = 0; i < n; i++) {
        if (xs[i] > 0) total += xs[i];
        else total -= xs[i];
    }
    return total;
}

int fib(int n) {
    if (n < 2) return n;
    return fib(n - 1) + fib(n - 2);
}

char *greet(const char *who) {
    char *buf = malloc(64);
    snprintf(buf, 64, "hello, %s", who);
    return buf;
}

int main(int argc, char **argv) {
    int data[] = {3, -4, 5, -6, 7};
    int s = accumulate(data, 5);
    int f = fib(argc < 10 ? argc : 9);
    char *g = greet(argc > 1 ? argv[1] : "world");
    printf("%s sum=%d fib=%d\n", g, s, f);
    free(g);
    return s + f;
}
