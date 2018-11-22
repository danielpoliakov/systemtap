typedef struct {
    char   arr[5];
    char   sz;
} foo;

foo a;

int main(void) {
    a.sz = 2;
    a.arr[2] = 78;
    a.arr[4] = 91;
    return 0;
}
