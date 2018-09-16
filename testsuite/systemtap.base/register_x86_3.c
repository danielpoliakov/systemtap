void foo(void) {
    asm("movl $0xbeefdead, %ecx");
    return;
}

int main(void) {
    foo();
    return 0;
}
