// The following kernel commits created new kernel header files for
// parts of <linux/sched.h>. Instead of testing for them individually,
// we're just going to treat them as one change, since they happened
// over such a short timeframe (Feb 1, 2017 - Feb 8, 2017).

// commit ae7e81c077d60507dcec139e40a6d10cf932cf4b
// Author: Ingo Molnar <mingo@kernel.org>
// Date:   Wed Feb 1 18:07:51 2017 +0100
// 
//     sched/headers: Prepare for new header dependencies before moving code to <uapi/linux/sched/types.h>
// 
// commit 4f17722c7256af8e17c2c4f29f170247264bdf48
// Author: Ingo Molnar <mingo@kernel.org>
// Date:   Wed Feb 8 08:45:17 2017 +0100
// 
//     sched/headers: Prepare for new header dependencies before moving code to <linux/sched/loadavg.h>
//
// commit e601757102cfd3eeae068f53b3bc1234f3a2b2e9
// Author: Ingo Molnar <mingo@kernel.org>
// Date:   Wed Feb 1 16:36:40 2017 +0100
//
//     sched/headers: Prepare for new header dependencies before moving code to <linux/sched/clock.h>
//
// commit 6e84f31522f931027bf695752087ece278c10d3f
// Author: Ingo Molnar <mingo@kernel.org>
// Date:   Wed Feb 8 18:51:29 2017 +0100
//
//    sched/headers: Prepare for new header dependencies before moving code to <linux/sched/mm.h>
//
// commit 68db0cf10678630d286f4bbbbdfa102951a35faa
// Author: Ingo Molnar <mingo@kernel.org>
// Date:   Wed Feb 8 18:51:37 2017 +0100
// 
//     sched/headers: Prepare for new header dependencies before moving code to <linux/sched/task_stack.h>

#include <linux/sched.h>
#include <uapi/linux/sched/types.h>
#include <linux/sched/clock.h>
#include <linux/sched/loadavg.h>
#include <linux/sched/mm.h>
#include <linux/sched/task_stack.h>
