typedef struct {
    char   arr[3];
    char   sz;
} foo;

foo a;

int main(void) {
    a.sz = 2;
    a.arr[2] = 78;
    return 0;
}
