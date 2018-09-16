void foo(void) {
    asm("movl $0xbeefdead, %eax");
    return;
}

int main(void) {
    foo();
    return 0;
}
