/* COVERAGE: pkey_alloc pkey_mprotect pkey_free */

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/mman.h>

int main()
{
    int *buffer;
    int pkey;

    /* Allocate a page of memory */
    buffer = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE, -1, 0);

    pkey = pkey_alloc(0, PKEY_DISABLE_ACCESS);
    //staptest// pkey_alloc (0, PKEY_DISABLE_ACCESS) = NNNN
    
    pkey_mprotect(buffer, 4096, PROT_READ|PROT_WRITE, pkey);
    //staptest// [[[[mprotect!!!!pkey_mprotect]]]] (XXXX, 4096, PROT_READ|PROT_WRITE[[[[, NNNN]]]]?) = 0

    pkey_free(pkey);
    //staptest// pkey_free (NNNN) = NNNN

    pkey_alloc((unsigned int)-1, 0);
    //staptest// pkey_alloc (4294967295, 0x0) = NNNN (EINVAL)

    pkey_alloc(0, (unsigned int)-1);
    //staptest// pkey_alloc (0, PKEY_DISABLE_[^ ]+|XXXX) = NNNN (EINVAL)

    pkey_mprotect((void *)-1, 4096, PROT_READ|PROT_WRITE, pkey);
    //staptest// [[[[mprotect!!!!pkey_mprotect]]]] (0x[f]+, 4096, PROT_READ|PROT_WRITE[[[[, NNNN]]]]?) = -NNNN (EINVAL)

    pkey_mprotect(buffer, (size_t)-1, PROT_READ|PROT_WRITE, pkey);
#if __WORDSIZE == 64
    //staptest// [[[[mprotect!!!!pkey_mprotect]]]] (XXXX, 18446744073709551615, PROT_READ|PROT_WRITE[[[[, NNNN]]]]?) = -NNNN
#else
    //staptest// [[[[mprotect!!!!pkey_mprotect]]]] (XXXX, 4294967295, PROT_READ|PROT_WRITE[[[[, NNNN]]]]?) = -NNNN
#endif

    pkey_mprotect(buffer, 4096, -1, pkey);
    //staptest// [[[[mprotect!!!!pkey_mprotect]]]] (XXXX, 4096, PROT_[^ ]+|XXXX[[[[, NNNN]]]]?) = -NNNN (EINVAL)

    pkey_mprotect(buffer, 4096, PROT_READ|PROT_WRITE, 16);
    //staptest// pkey_mprotect (XXXX, 4096, PROT_READ|PROT_WRITE, 16) = -NNNN (EINVAL)

    pkey_free(-1);
    //staptest// pkey_free (-1) = -NNNN (EINVAL)

    return 0;
}
