/* bpfinterp.c - SystemTap BPF interpreter
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
 * Copyright (C) 2016-2018 Red Hat, Inc.
 *
 */

#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <cerrno>
#include <vector>
#include <inttypes.h>
#include <map>
#include "bpfinterp.h"
#include "libbpf.h"
#include "../bpf-internal.h"

inline uintptr_t
as_int(void *ptr)
{
  return reinterpret_cast<uintptr_t>(ptr);
}

inline uintptr_t
as_int(uint64_t *ptr)
{
  return reinterpret_cast<uintptr_t>(ptr);
}

inline void *
as_ptr(uintptr_t ptr)
{
  return reinterpret_cast<void *>(ptr);
}

inline void *
as_ptr(uint64_t *ptr)
{
  return reinterpret_cast<void *>(ptr);
}

inline char *
as_str(uintptr_t ptr)
{
  return reinterpret_cast<char *>(ptr);
}

const std::string
remove_tag(const char *fstr)
{
  while (*(++fstr) != '>' && *fstr != '\0');
  if (*fstr == '\0') return ""; // avoid segfault
  ++fstr;
  const char *end = fstr + strlen(fstr);
  while (*(--end) != '<' && end >= fstr);
  assert(end >= fstr);
  return std::string(fstr, end - fstr);
}

// Used with map_get_next_key. Need signed type so that
// negative values are properly sorted
typedef std::vector<std::set<int64_t>> map_keys;

// Wrapper for bpf_get_next_key that includes logic for accessing
// keys in ascending or decending order
int
map_get_next_key(int fd_idx, int64_t key, int64_t next_key, int sort_direction,
                 int64_t limit, std::vector<int> &map_fds, map_keys &keys)
{
  int fd = map_fds[fd_idx];

  // Final iteration, therefore keys back is no longer needed
  if (limit == 0)
    goto empty;

  if (!sort_direction)
    return bpf_get_next_key(fd, as_ptr(key), as_ptr(next_key));

  if (!key)
    {
      // Beginning of iteration; populate a new set of keys for
      // the map specified by fd. Multiple sets can be associated
      // with a single map during execution of nested foreach loops
      uint64_t k, n;
      std::set<int64_t> s;

      int ret = bpf_get_next_key(fd, 0, as_ptr(&n));

      while (!ret)
        {
          s.insert(n);
          k = n;
          ret = bpf_get_next_key(fd, as_ptr(&k), as_ptr(&n));
        }

      if (s.empty())
        return -1;

      keys.push_back(s);
    }

  {
  std::set<int64_t> &s = keys.back();
  uint64_t *nptr = reinterpret_cast<uint64_t *>(next_key);

  if (sort_direction > 0)
    {
      auto it = s.begin();

      if (it == s.end())
        goto empty;

      *nptr = *it;
    }
  else
    {
      auto it = s.rbegin();

      if (it == s.rend())
        goto empty;

      *nptr = *it;
    }

  s.erase(*nptr);
  }

  return 0;

empty:
  keys.pop_back();
  return -1;
}

uint64_t
bpf_sprintf(std::vector<std::string> &strings, char *fstr,
            uint64_t arg1, uint64_t arg2, uint64_t arg3)
{
  char s[256]; // TODO: configure maximum length setting e.g. BPF_MAXSPRINTFLEN
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
  snprintf(s, 256, fstr, arg1, arg2, arg3);
#pragma GCC diagnostic pop
  std::string str(s, 256);
  strings.push_back(str);

  // Elements of "strings" should not be mutated to avoid
  // invalidating c_str() pointers.
  return reinterpret_cast<uint64_t>(strings.back().c_str());
}

uint64_t
bpf_interpret(size_t ninsns, const struct bpf_insn insns[],
              std::vector<int> &map_fds, FILE *output_f)
{
  uint64_t stack[512 / 8];
  uint64_t regs[MAX_BPF_REG];
  uint64_t lookup_tmp = 0xdeadbeef;
  const struct bpf_insn *i = insns;
  static std::vector<std::string> strings;
  map_keys keys[map_fds.size()];

  regs[BPF_REG_10] = (uintptr_t)stack + sizeof(stack);

  while ((size_t)(i - insns) < ninsns)
    {
      uint64_t dr, sr, si, s1;

      dr = regs[i->dst_reg];
      sr = regs[i->src_reg];
      si = i->imm;
      s1 = i->code & BPF_X ? sr : si;

      switch (i->code)
	{
	case BPF_LDX | BPF_MEM | BPF_B:
	  dr = *(uint8_t *)((uintptr_t)sr + i->off);
	  break;
	case BPF_LDX | BPF_MEM | BPF_H:
	  dr = *(uint16_t *)((uintptr_t)sr + i->off);
	  break;
	case BPF_LDX | BPF_MEM | BPF_W:
	  dr = *(uint32_t *)((uintptr_t)sr + i->off);
	  break;
	case BPF_LDX | BPF_MEM | BPF_DW:
	  dr = *(uint64_t *)((uintptr_t)sr + i->off);
	  break;

	case BPF_ST | BPF_MEM | BPF_B:
	  sr = si;
	  /* Fallthrough */
	case BPF_STX | BPF_MEM | BPF_B:
	  *(uint8_t *)((uintptr_t)dr + i->off) = sr;
	  goto nowrite;
	case BPF_ST | BPF_MEM | BPF_H:
	  sr = si;
	  /* Fallthrough */
	case BPF_STX | BPF_MEM | BPF_H:
	  *(uint16_t *)((uintptr_t)dr + i->off) = sr;
	  goto nowrite;
	case BPF_ST | BPF_MEM | BPF_W:
	  sr = si;
	  /* Fallthrough */
	case BPF_STX | BPF_MEM | BPF_W:
	  *(uint32_t *)((uintptr_t)dr + i->off) = sr;
	  goto nowrite;
	case BPF_ST | BPF_MEM | BPF_DW:
	  sr = si;
	  /* Fallthrough */
	case BPF_STX | BPF_MEM | BPF_DW:
	  *(uint64_t *)((uintptr_t)dr + i->off) = sr;
	  goto nowrite;

	case BPF_ALU64 | BPF_ADD | BPF_X:
	case BPF_ALU64 | BPF_ADD | BPF_K:  dr += s1; break;
	case BPF_ALU64 | BPF_SUB | BPF_X:
	case BPF_ALU64 | BPF_SUB | BPF_K:  dr -= s1; break;
	case BPF_ALU64 | BPF_AND | BPF_X:
	case BPF_ALU64 | BPF_AND | BPF_K:  dr &= s1; break;
	case BPF_ALU64 | BPF_OR  | BPF_X:
	case BPF_ALU64 | BPF_OR  | BPF_K:  dr |= s1; break;
	case BPF_ALU64 | BPF_LSH | BPF_X:
	case BPF_ALU64 | BPF_LSH | BPF_K:  dr <<= s1; break;
	case BPF_ALU64 | BPF_RSH | BPF_X:
	case BPF_ALU64 | BPF_RSH | BPF_K:  dr >>= s1; break;
	case BPF_ALU64 | BPF_XOR | BPF_X:
	case BPF_ALU64 | BPF_XOR | BPF_K:  dr ^= s1; break;
	case BPF_ALU64 | BPF_MUL | BPF_X:
	case BPF_ALU64 | BPF_MUL | BPF_K:  dr *= s1; break;
	case BPF_ALU64 | BPF_MOV | BPF_X:
	case BPF_ALU64 | BPF_MOV | BPF_K:  dr = s1; break;
	case BPF_ALU64 | BPF_ARSH | BPF_X:
	case BPF_ALU64 | BPF_ARSH | BPF_K: dr = (int64_t)dr >> s1; break;
	case BPF_ALU64 | BPF_NEG:	   dr = -sr;
					   /* Fallthrough */
	case BPF_ALU64 | BPF_DIV | BPF_X:
	case BPF_ALU64 | BPF_DIV | BPF_K:
	  if (s1 == 0)
	    return 0;
	  dr /= s1;
	  break;
	case BPF_ALU64 | BPF_MOD | BPF_X:
	case BPF_ALU64 | BPF_MOD | BPF_K:
	  if (s1 == 0)
	    return 0;
	  dr %= s1;
	  break;

	case BPF_ALU | BPF_ADD | BPF_X:
	case BPF_ALU | BPF_ADD | BPF_K:  dr = (uint32_t)(dr + s1); break;
	case BPF_ALU | BPF_SUB | BPF_X:
	case BPF_ALU | BPF_SUB | BPF_K:  dr = (uint32_t)(dr - s1); break;
	case BPF_ALU | BPF_AND | BPF_X:
	case BPF_ALU | BPF_AND | BPF_K:  dr = (uint32_t)(dr & s1); break;
	case BPF_ALU | BPF_OR  | BPF_X:
	case BPF_ALU | BPF_OR  | BPF_K:  dr = (uint32_t)(dr | s1); break;
	case BPF_ALU | BPF_LSH | BPF_X:
	case BPF_ALU | BPF_LSH | BPF_K:  dr = (uint32_t)dr << s1; break;
	case BPF_ALU | BPF_RSH | BPF_X:
	case BPF_ALU | BPF_RSH | BPF_K:  dr = (uint32_t)dr >> s1; break;
	case BPF_ALU | BPF_XOR | BPF_X:
	case BPF_ALU | BPF_XOR | BPF_K:  dr = (uint32_t)(dr ^ s1); break;
	case BPF_ALU | BPF_MUL | BPF_X:
	case BPF_ALU | BPF_MUL | BPF_K:  dr = (uint32_t)(dr * s1); break;
	case BPF_ALU | BPF_MOV | BPF_X:
	case BPF_ALU | BPF_MOV | BPF_K:  dr = (uint32_t)s1; break;
	case BPF_ALU | BPF_ARSH | BPF_X:
	case BPF_ALU | BPF_ARSH | BPF_K: dr = (int32_t)dr >> s1; break;
	case BPF_ALU | BPF_NEG:		 dr = -(uint32_t)sr;
					 /* Fallthrough */
	case BPF_ALU | BPF_DIV | BPF_X:
	case BPF_ALU | BPF_DIV | BPF_K:
	  if ((uint32_t)s1 == 0)
	    return 0;
	  dr = (uint32_t)dr / (uint32_t)s1;
	  break;
	case BPF_ALU | BPF_MOD | BPF_X:
	case BPF_ALU | BPF_MOD | BPF_K:
	  if ((uint32_t)s1 == 0)
	    return 0;
	  dr = (uint32_t)dr % (uint32_t)s1;
	  break;

	case BPF_LD | BPF_IMM | BPF_DW:
	  switch (i->src_reg)
	    {
	    case 0:
	      dr = (uint32_t)si | ((uint64_t)i[1].imm << 32);
	      break;
	    case BPF_PSEUDO_MAP_FD:
	      if (si >= map_fds.size())
		return 0;
	      dr = si;
	      break;
	    default:
	      abort();
	    }
	  regs[i->dst_reg] = dr;
	  i += 2;
	  continue;

	case BPF_JMP | BPF_JEQ | BPF_X:
	case BPF_JMP | BPF_JEQ | BPF_K:
	  if (dr == s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JNE | BPF_X:
	case BPF_JMP | BPF_JNE | BPF_K:
	  if (dr != s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JGT | BPF_X:
	case BPF_JMP | BPF_JGT | BPF_K:
	  if (dr > s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JGE | BPF_X:
	case BPF_JMP | BPF_JGE | BPF_K:
	  if (dr >= s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JSGT | BPF_X:
	case BPF_JMP | BPF_JSGT | BPF_K:
	  if ((int64_t)dr > (int64_t)s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JSGE | BPF_X:
	case BPF_JMP | BPF_JSGE | BPF_K:
	  if ((int64_t)dr >= (int64_t)s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JSET | BPF_X:
	case BPF_JMP | BPF_JSET | BPF_K:
	  if (dr & s1)
	    goto dojmp;
	  goto nowrite;
	case BPF_JMP | BPF_JA:
	dojmp:
	  i += 1 + i->off;
	  continue;

	case BPF_JMP | BPF_CALL:
	  switch (si)
	    {
	    case BPF_FUNC_map_lookup_elem:
	      {
	        int res = bpf_lookup_elem(map_fds[regs[1]], as_ptr(regs[2]),
			                  as_ptr(&lookup_tmp));

	        if (res)
		  // element could not be found
	          dr = 0;
	        else
	          dr = as_int(&lookup_tmp);
	      }
	      break;
	    case BPF_FUNC_map_update_elem:
	      dr = bpf_update_elem(map_fds[regs[1]], as_ptr(regs[2]),
			           as_ptr(regs[3]), regs[4]);
	      break;
	    case BPF_FUNC_map_delete_elem:
	      dr = bpf_delete_elem(map_fds[regs[1]], as_ptr(regs[2]));
	      break;
	    case BPF_FUNC_trace_printk:
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
              // regs[2] is the strlen(regs[1]) - not used by printf(3);
              // instead we assume regs[1] string is \0 terminated
	      dr = fprintf(output_f, remove_tag(as_str(regs[1])).c_str(),
                           /*regs[2],*/ regs[3], regs[4], regs[5]);
              fflush(output_f);
#pragma GCC diagnostic pop
	      break;
            case bpf::BPF_FUNC_sprintf:
              dr = bpf_sprintf(strings, as_str(regs[1]),
                               regs[3], regs[4], regs[5]);
              break;
            case bpf::BPF_FUNC_map_get_next_key:
              dr = map_get_next_key(regs[1], regs[2], regs[3], regs[4],
                                    regs[5],  map_fds, keys[regs[1]]);
              break;
	    default:
	      abort();
	    }
	  regs[0] = dr;
	  regs[1] = 0xdeadbeef;
	  regs[2] = 0xdeadbeef;
	  regs[3] = 0xdeadbeef;
	  regs[4] = 0xdeadbeef;
          regs[5] = 0xdeadbeef;
	  goto nowrite;

	case BPF_JMP | BPF_EXIT:
	  return regs[0];

	default:
	  abort();
	}

      regs[i->dst_reg] = dr;
    nowrite:
      i++;
    }
  return 0;
}
