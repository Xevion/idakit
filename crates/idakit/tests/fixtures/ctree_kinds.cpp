// Fixture for the ctree extraction node-by-node test (see tests/ctree_nodes.rs).
//
// Its functions are shaped to make the decompiler emit every statement and expression kind the
// extraction sink models, plus struct / enum / typedef / array / function-pointer / opaque /
// anonymous types, so the walk drives each sink callback. Compiled -O0 so control flow and
// member accesses survive as distinct ctree nodes rather than being folded away.

#include <cstdio>
#include <cstring>

struct Point {
    int x;
    int y;
};

struct Vec2 {
    int x;
    int y;
};

// A polymorphic class: its RTTI/vtable lets the decompiler type `this`, so member accesses
// survive as MemberPtr / MemberRef nodes even without debug info.
struct Widget {
    int count;
    Vec2 pos;
    virtual int tick();
    virtual ~Widget() {}
};

__attribute__((noinline)) int Widget::tick() {
    count++;             // this->count : MemberPtr
    Vec2 local = pos;    // this->pos   : MemberPtr on a sub-struct value
    int sum = local.x;   // local.x     : MemberRef (member of a value)
    sum += local.y;
    return sum + count;
}

// A while loop and a continue that the decompiler keeps as such: a pointer-walk whose
// condition is not a simple counter resists rewriting into a for/do.
__attribute__((noinline)) int walk(char *p, char *end) {
    int seen = 0;
    while (p < end) {
        char c = *p++;
        if (c == ' ')
            continue;
        seen++;
    }
    return seen;
}

enum Color { RED = 1, GREEN = 2, BLUE = 4 };

typedef unsigned long size_alias;

typedef int (*binop)(int, int);

struct Opaque;

struct HasAnon {
    int tag;
    union {
        int i;
        float f;
    };
};

// if / else, for, while, do-while, break, continue, goto, return
__attribute__((noinline)) int control_flow(int n, int seed) {
    int total = seed;
    for (int i = 0; i < n; i++) {
        if (i == 3)
            continue;
        if (i == 7)
            break;
        total += i;
    }
    int k = 0;
    while (k < n) {
        total += k * 2;
        if (total > 1000)
            goto done;
        k++;
    }
    do {
        total -= 1;
    } while (total > 500);
done:
    return total;
}

// a dense switch with distinct case bodies, kept as a jump table (so the walk drives the
// switch value-pool slicing) rather than being rewritten into if-chains
__attribute__((noinline)) int classify(int x) {
    int r;
    switch (x) {
    case 0:
        r = 100;
        break;
    case 1:
        r = 111;
        break;
    case 2:
        r = 122;
        break;
    case 3:
        r = 133;
        break;
    case 4:
        r = 144;
        break;
    case 5:
        r = 155;
        break;
    default:
        r = -1;
        break;
    }
    return r;
}

// ternary, unary (neg / bitnot / pre- and post- inc/dec), cast, float literal, string, call,
// and the rotate idiom the decompiler recognizes as a helper intrinsic
__attribute__((noinline)) double expressions(int a, int b, double d) {
    int m = a > b ? a : b;
    m = -m;
    m = ~m;
    m++;
    ++m;
    m--;
    unsigned int u = (unsigned) m;
    unsigned int r = (u << 5) | (u >> 27);
    double v = d + (double) m + (double) r;
    printf("val=%f\n", v);
    return v;
}

// a struct returned by value so a member access reads it as an rvalue (member-of-value)
__attribute__((noinline)) struct Point origin(int a, int b) {
    struct Point p = {a, b};
    return p;
}

// struct-pointer member store, member-of-value read, array index, enum, typedef, function pointer
__attribute__((noinline)) int use_types(struct Point *p, int *arr, enum Color c, size_alias n,
                                         binop f) {
    p->x = 5;
    int viax = origin(p->y, 9).x;
    int e = arr[n];
    int r = f(viax, e);
    return p->y + viax + e + (int) c + (int) n + r;
}

// pointer to an incomplete (opaque) type, plus an anonymous-union member access
__attribute__((noinline)) long use_opaque(struct Opaque *o, struct HasAnon *h) {
    h->tag = 7;
    h->i = 9;
    return (long) o + h->tag + h->i;
}

// inline assembly -> an asm statement
__attribute__((noinline)) int with_asm(int x) {
    int r = x;
    __asm__ volatile("nop");
    return r + 1;
}

// throw, and a try/catch guarding it
__attribute__((noinline)) int may_throw(int x) {
    if (x < 0)
        throw x;
    return x * 2;
}

__attribute__((noinline)) int guarded(int x) {
    int r;
    try {
        r = may_throw(x);
    } catch (int e) {
        r = -e;
    }
    return r;
}

int main(int argc, char **argv) {
    struct Point pt = {argc, argc + 1};
    int arr[4] = {1, 2, 3, 4};
    int cf = control_flow(argc, 10);
    int cl = classify(argc);
    double ex = expressions(argc, argc + 1, 2.5);
    int ut = use_types(&pt, arr, GREEN, (size_alias) argc, 0);
    struct HasAnon ha;
    memset(&ha, 0, sizeof ha);
    long uo = use_opaque((struct Opaque *) argv, &ha);
    int wa = with_asm(argc);
    int gd = guarded(argc - 2);
    Widget w;
    w.count = argc;
    w.pos.x = argc;
    w.pos.y = argc + 1;
    int tk = w.tick();
    int wk = walk(argv[0], argv[0] + argc);
    printf("%d %d %f %d %ld %d %d %d %d\n", cf, cl, ex, ut, uo, wa, gd, tk, wk);
    return cf + cl + ut + wa + gd + tk + wk + (int) ex + (int) uo;
}
