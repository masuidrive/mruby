/*
** tools/mrbc/dump.h - mruby binary dumper (Rite binary format)
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_DUMP_H
#define MRUBY_DUMP_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "mruby.h"

int
mrb_dump_irep(mrb_state *mrb, int start_index, int debug_info, uint8_t **bin, uint32_t *bin_size);

#if defined(__cplusplus)
}  /* extern "C" { */
#endif

#endif  /* MRUBY_DUMP_H */
