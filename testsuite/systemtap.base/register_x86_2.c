void foo(void) {
    asm("movl $0xbeefdead, %edx");
    return;
}

int main(void) {
    foo();
    return 0;
}
