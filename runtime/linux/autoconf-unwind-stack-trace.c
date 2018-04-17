#include <linux/sched.h>
#include <asm/unwind.h>

void unwind_stack_trace (void)
{
  struct unwind_state state;
  unwind_start (&state, current, 0, 0);
  while (! unwind_done (&state))
    {
      unsigned long addr = unwind_get_return_address (&state);
      if (addr == 0)
	break;
      unwind_next_frame (&state);
    }
}

