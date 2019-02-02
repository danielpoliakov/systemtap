#include <linux/uaccess.h>

int __something(void)
{
   return access_ok ((void*) 0, 4);
}
