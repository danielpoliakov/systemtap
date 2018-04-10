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

uint64_t bpf_interpret(size_t ninsns,
		       const struct bpf_insn insns[],
		       std::vector<int> &map_fds, FILE *output_f);

#endif /* STAPRUNBPF_H */

