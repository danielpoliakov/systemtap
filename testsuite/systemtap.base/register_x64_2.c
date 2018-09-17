void foo(void) {
    asm("movq $0x56781234beefdead, %rbx");
    return;
}

int main(void) {
    foo();
    return 0;
}
