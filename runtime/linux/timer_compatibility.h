/*
 * linux/timer.h compatibility defines and inlines
 * Copyright (C) 2017 Red Hat Inc.
 *
 * This file is part of systemtap, and is free software.  You can
 * redistribute it and/or modify it under the terms of the GNU General
 * Public License (GPL); either version 2, or (at your option) any
 * later version.
 */

#ifndef _TIMER_COMPATIBILITY_H_
#define _TIMER_COMPATIBILITY_H_

#include <linux/timer.h>

/*
 * Starting with the 4.15 kernel, the timer interface
 * changed. Originally, you'd do something like:
 *
 *   static void timer_func(unsigned long val);
 *
 *   init_timer(&timer);
 *   timer.expires = jiffies + STP_RELAY_TIMER_INTERVAL;
 *   timer.function = timer_func;
 *   timer.data = 0;
 *   add_timer(&timer);
 *
 * The 'data' parameter would get passed to the callback
 * function. Starting with 4.15, you'd do something like this:
 *
 *   static void timer_func(struct timer_list *val);
 *
 *   timer_setup(&timer, timer_func, 0);
 *   timer.expires = jiffies + STP_RELAY_TIMER_INTERVAL;
 *   add_timer(&timer);
 *   
 * With the new code, the timer that caused the callback gets passed
 * to the timer callback function. The 'data' field has been removed.
 *
 * So, we're going to use the new interface. To hide the differences
 * between the callback function parameter type, we'll define a new
 * type, 'stp_timer_callback_parameter_t'.
 *
 * If code needs to figure out the difference between the old and new
 * interface, it should test the init_timer define (which only exists
 * in the old new interface).
 */

#if !defined(init_timer) 
/* This is the >= 4.15 kernel interface. */

typedef struct timer_list * stp_timer_callback_parameter_t;

#else
/* This is the < 4.15 kernel interface. */

typedef unsigned long stp_timer_callback_parameter_t;

/**
 * timer_setup - prepare a timer for first use
 * @timer: the timer in question
 * @callback: the function to call when timer expires
 * @flags: any TIMER_* flags (note that anything other than 0 is an
 * 	   error, since this compatibility function can't support any
 *	   of the TIMER_* flags)
 */
#define timer_setup(timer, callback, flags)			\
	{							\
		init_timer((timer));				\
		(timer)->function = callback;			\
		(timer)->data = 0;				\
		BUILD_BUG_ON_ZERO((flags) != 0);		\
	}
#endif

#endif /* _TIMER_COMPATIBILITY_H_ */
