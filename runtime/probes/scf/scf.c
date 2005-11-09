#define STP_NUM_STRINGS 1
#include "runtime.h"

#define MAP_STRING_LENGTH 512

#define VALUE_TYPE INT64
#define KEY1_TYPE STRING
#include "map-gen.c"

#include "map.c"
#include "sym.c"
#include "current.c"
#include "stack.c"
#include "probes.c"

MODULE_DESCRIPTION("SystemTap probe: scf");
MODULE_AUTHOR("Martin Hunt <hunt@redhat.com>");

MAP map1;

int inst_smp_call_function (struct kprobe *p, struct pt_regs *regs)
{
  String str = _stp_string_init (0);
  _stp_stack_sprint (str, regs, 1);
  _stp_map_add_si (map1, _stp_string_ptr(str), 1);
  return 0;
}

static struct kprobe stp_probes[] = {
  {
    .addr = (kprobe_opcode_t *)"smp_call_function",
    .pre_handler = inst_smp_call_function
  },
};

#define MAX_STP_ROUTINE (sizeof(stp_probes)/sizeof(struct kprobe))

int probe_start(void)
{
  map1 = _stp_map_new_si (100);
  return _stp_register_kprobes (stp_probes, MAX_STP_ROUTINE);
}

void probe_exit (void)
{
  _stp_unregister_kprobes (stp_probes, MAX_STP_ROUTINE);
  _stp_map_print (map1, "trace[%1s] = %d\n");
  _stp_map_del (map1);
}

