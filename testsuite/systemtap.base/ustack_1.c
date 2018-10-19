int foo(void) {
    return 3;
}

int bar(void) {
    return foo();
}

int main(void) {
    bar();
    return 0;
}
