/* bpfinterp.h - SystemTap BPF interpreter
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright (C) 2016 Red Hat, Inc.
 *
 */

#ifndef BPFINTERP_H
#define BPFINTERP_H 1

#include <sys/types.h>
#include <inttypes.h>
#include <linux/bpf.h>

extern "C" {
#include "libbpf.h"
}

// Required constants such as BPF_MAXFORMATLEN:
#include "../bpf-internal.h"

// Used by the transport layer and interpreter:
struct bpf_transport_context {
  unsigned cpu;
  int pmu_fd;
  // TODOXXX: If pmu_fd == -1, this is a userspace context. Be sure to reflect this in diagnostics.

  // References to global state:
  std::vector<int> *map_fds;
  FILE *output_f;

  // Data for an in-progress printf request:
  bool in_printf;
  int format_no;          // -- index into table of interned strings
  unsigned expected_args; // -- expected number of printf_args
  char printf_format[BPF_MAXFORMATLEN]; // TODOXXX replace with global table of interned strings
  std::vector<void *> printf_args;
  std::vector<bpf::globals::perf_event_type> printf_arg_types; // either ..ARG_LONG or ..ARG_STR

  bpf_transport_context(unsigned cpu, int pmu_fd,
                        std::vector<int> *map_fds, FILE *output_f)
    : cpu(cpu), pmu_fd(pmu_fd),
      map_fds(map_fds), output_f(output_f),
      in_printf(false), format_no(-1), expected_args(0) {}
};

enum bpf_perf_event_ret bpf_handle_transport_msg(void *buf, size_t size,
                                                 bpf_transport_context *ctx);
  
uint64_t bpf_interpret(size_t ninsns,
                       const struct bpf_insn insns[],
                       bpf_transport_context *ctx);

#endif /* STAPRUNBPF_H */
