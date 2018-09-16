void foo(void) {
    asm("movl $0xbeefdead, %ebx");
    return;
}

int main(void) {
    foo();
    return 0;
}
