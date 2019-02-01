#include <linux/mm.h>

//
// The following kernel commit changed the get_user_pages() function signature
// on linux-4.4.y:
//
// commit 8e50b8b07f462ab4b91bc1491b1c91bd75e4ad40
// Author: Lorenzo Stoakes <lstoakes@gmail.com>
// Date:   Thu Oct 13 01:20:16 2016 +0100
//
//     mm: replace get_user_pages() write/force parameters with gup_flags
//
//     commit 768ae309a96103ed02eb1e111e838c87854d8b51 upstream.
//
//     This removes the 'write' and 'force' from get_user_pages() and replaces
//     them with 'gup_flags' to make the use of FOLL_FORCE explicit in callers
//     as use of this flag can result in surprising behaviour (and hence bugs)
//     within the mm subsystem.
//
// This changed the function signature from:
//
// long get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
//                     unsigned long start, unsigned long nr_pages,
//                     int write, int force, struct page **pages,
//                     struct vm_area_struct **vmas);
//
// to:
//
// long get_user_pages(struct task_struct *tsk, struct mm_struct *mm,
//                     unsigned long start, unsigned long nr_pages,
//                     unsigned int gup_flags, struct page **pages,
//                     struct vm_area_struct **vmas);
//

long gupr_wrapper(struct task_struct *tsk, struct mm_struct *mm,
		  unsigned long start, unsigned long nr_pages,
		  unsigned int gup_flags, struct page **pages,
		  struct vm_area_struct **vmas)
{
    return get_user_pages(tsk, mm, start, nr_pages, gup_flags, pages, vmas);
}
