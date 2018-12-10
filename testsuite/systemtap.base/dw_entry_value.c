int foo(int a)
{
    return 0;
}

int bar(int b, int c)
{
    int d = foo(c);
    return d;
}

int main()
{
    int e = bar(3, 2);
    return e;
}

