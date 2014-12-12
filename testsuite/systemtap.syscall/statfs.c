/* COVERAGE: fstatfs statfs ustat fstatfs64 statfs64 */
#include <sys/types.h>
#include <unistd.h>
#include <ustat.h>
#include <sys/vfs.h>
#include <sys/syscall.h>

int main()
{
#ifdef __NR_ustat
  ustat(42, (struct ustat *)0x12345678);
  //staptest// ustat (42, 0x0*12345678) = 
#endif

  statfs("abc", (struct statfs *)0x12345678);
  //staptest// statfs ("abc", 0x0*12345678) =

  fstatfs(77, (struct statfs *)0x12345678);
  //staptest// fstatfs (77, 0x0*12345678) =

  return 0;
}
