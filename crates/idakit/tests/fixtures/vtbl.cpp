// Fixture for the constructor-analysis matchers (see tests/ctor.rs).
//
// Multiple inheritance forces the Derived constructor to install two vtables: the primary
// at [this+0] and the Other subobject at [this+offset]. It then calls both base
// constructors with the matching this-relative arguments. That is exactly the shape
// query::vtable_installs / query::this_arg_calls recover from the decompiled ctree.

struct Base {
    virtual int foo() { return b; }
    int b;
    Base() : b(1) {}
};

struct Other {
    virtual int bar() { return o; }
    int o;
    Other() : o(2) {}
};

struct Derived : Base, Other {
    virtual int foo() { return 3; }
    virtual int baz() { return d; }
    int d;
    Derived() : d(4) {}
};

__attribute__((noinline)) Base* make() { return new Derived(); }

int main() {
    Base* b = make();
    return b->foo();
}
