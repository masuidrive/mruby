/*
** load.c - mruby binary loader
**
** See Copyright Notice in mruby.h
*/

#include <string.h>
#include "mruby/dump.h"

#include "mruby/string.h"
#include "mruby/proc.h"
#include "mruby/irep.h"

static int
read_rite_irep_record(mrb_state *mrb, unsigned char *bin, uint32_t *len)
{
  int i, ret = MRB_DUMP_OK;
  char *buf;
  unsigned char *src = bin;
  uint16_t crc, tt, pdl, snl, offset, buf_size = MRB_DUMP_DEFAULT_STR_LEN;
  mrb_int fix_num;
  mrb_float f;
  int plen;
  int ai = mrb_gc_arena_save(mrb);
  mrb_irep *irep = mrb_add_irep(mrb);

  buf = (char *)mrb_malloc(mrb, buf_size);
  if (buf == NULL) {
    ret = MRB_DUMP_GENERAL_FAILURE;
    goto error_exit;
  }

  //Header Section
  if (*src++ != RITE_IREP_IDENTIFIER)
    return MRB_DUMP_INVALID_IREP;

  //number of local variable
  irep->nlocals = bin_to_uint16(src);
  src += sizeof(uint16_t);

  //number of register variable
  irep->nregs = bin_to_uint16(src);         
  src += sizeof(uint16_t);

  //offset of isec block
  offset = bin_to_uint16(src);
  src += sizeof(uint16_t);
  src += offset;

  //Binary Data Section
  //ISEQ BLOCK
  irep->ilen = bin_to_uint32(src);
  src += sizeof(uint32_t);
  if (irep->ilen > 0) {
    irep->iseq = (mrb_code *)mrb_malloc(mrb, sizeof(mrb_code) * irep->ilen);
    if (irep->iseq == NULL) {
      ret = MRB_DUMP_GENERAL_FAILURE;
      goto error_exit;
    }
    for (i = 0; i < irep->ilen; i++) {
      irep->iseq[i] = bin_to_uint32(src);     //iseq
      src += sizeof(uint32_t);
    }
  }

  //POOL BLOCK
  plen = bin_to_uint32(src); //pool length
  src += sizeof(uint32_t);
  if (plen > 0) {
    irep->pool = (mrb_value *)mrb_malloc(mrb, sizeof(mrb_value) * plen);
    if (irep->pool == NULL) {
      ret = MRB_DUMP_GENERAL_FAILURE;
      goto error_exit;
    }

    for (i = 0; i < plen; i++) {
      tt = *src;                              //pool TT
      src += sizeof(unsigned char);
      pdl = bin_to_uint16(src);               //pool data length
      src += sizeof(uint16_t);
      if (pdl > buf_size - 1) {
        mrb_free(mrb, buf);
        buf_size = pdl + 1;
        buf = (char *)mrb_malloc(mrb, buf_size);
        if (buf == NULL) {
          ret = MRB_DUMP_GENERAL_FAILURE;
          goto error_exit;
        }
      }
      memcpy(buf, src, pdl);
      src += pdl;
      buf[pdl] = '\0';

      switch (tt) {                           //pool data
      case MRB_TT_FIXNUM:
        fix_num = str_to_mrb_int(buf);
        irep->pool[i] = mrb_fixnum_value(fix_num);
        break;

      case MRB_TT_FLOAT:
        f = str_to_mrb_float(buf);
        irep->pool[i] = mrb_float_value(f);
        break;

      case MRB_TT_STRING:
        irep->pool[i] = mrb_str_new(mrb, buf, pdl);
        break;

      default:
        irep->pool[i] = mrb_nil_value();
        break;
      }
      irep->plen++;
      mrb_gc_arena_restore(mrb, ai);
    }
  }

  //SYMS BLOCK
  irep->slen = bin_to_uint32(src);  //syms length
  src += sizeof(uint32_t);
  if (irep->slen > 0) {
    irep->syms = (mrb_sym *)mrb_malloc(mrb, sizeof(mrb_sym) * irep->slen);
    if (irep->syms == NULL) {
      ret = MRB_DUMP_GENERAL_FAILURE;
      goto error_exit;
    }

    for (i = 0; i < irep->slen; i++) {
      static const mrb_sym mrb_sym_zero = { 0 };
      *irep->syms = mrb_sym_zero;
    }
    for (i = 0; i < irep->slen; i++) {
      snl = bin_to_uint16(src);               //symbol name length
      src += sizeof(uint16_t);

      if (snl == MRB_DUMP_NULL_SYM_LEN) {
        irep->syms[i] = 0;
        continue;
      }

      if (snl > buf_size - 1) {
        mrb_free(mrb, buf);
        buf_size = snl + 1;
        buf = (char *)mrb_malloc(mrb, buf_size);
        if (buf == NULL) {
          ret = MRB_DUMP_GENERAL_FAILURE;
          goto error_exit;
        }
      }
      memcpy(buf, src, snl);                  //symbol name
      src += snl;
      buf[snl] = '\0';
      irep->syms[i] = mrb_intern2(mrb, buf, snl);
    }
  }

  *len = src - bin;

error_exit:
  mrb_free(mrb, buf);
  return ret;
}

static int
read_rite_section_irep(mrb_state *mrb, const struct rite_section_irep_header *header)
{
  int n, i, result = MRB_DUMP_OK;
  size_t sirep;
  uint16_t nirep;
  uint32_t len;
  const char *bin = header + sizeof(struct rite_section_irep_header);

  sirep = mrb->irep_len;
  nirep = bin_to_uint16(header->nirep);

  //Read Binary Data Section
  for (n = 0, i = sirep; n < nirep; n++, i++) {
    result = read_rite_irep_record(mrb, bin, &len);
    if (result != MRB_DUMP_OK)
      goto error_exit;
    bin += len;
  }

error_exit:
  if (result != MRB_DUMP_OK) {
    for (n = 0, i = sirep; i < mrb->irep_len; n++, i++) {
      if (mrb->irep[i]) {
        if (mrb->irep[i]->iseq)
          mrb_free(mrb, mrb->irep[i]->iseq);

        if (mrb->irep[i]->pool)
          mrb_free(mrb, mrb->irep[i]->pool);

        if (mrb->irep[i]->syms)
          mrb_free(mrb, mrb->irep[i]->syms);

        mrb_free(mrb, mrb->irep[i]);
      }
    }
    return result;
  }
  return sirep + bin_to_uint16(header->sirep);
}

static int
read_rite_binary_header(const char *bin, uint32_t *bin_size)
{
  const struct rite_binary_header *header = (const struct rite_binary_header *)bin;

  if(memcmp(header->binary_identify, RITE_BINARY_IDENFIFIER, sizeof(header->binary_identify)) != 0) {
    return MRB_DUMP_INVALID_FILE_HEADER;
  }
  
  if(memcmp(header->binary_version, RITE_BINARY_FORMAT_VER, sizeof(header->binary_version)) != 0) {
    return MRB_DUMP_INVALID_FILE_HEADER;
  }

  *bin_size = bin_to_uint32(header->binary_size);

  // TODO: check crc
  return MRB_DUMP_OK;
}

int
mrb_read_irep(mrb_state *mrb, const unsigned char *bin)
{
  int i, n, nirep, sirep, result = MRB_DUMP_OK;
  uint32_t len = 0;
  unsigned char *src;
  const struct rite_section_header *section_header;
  uint32_t bin_size = 0, section_size = 0;

  if ((mrb == NULL) || (bin == NULL)) {
    return MRB_DUMP_INVALID_ARGUMENT;
  }

  result = read_rite_binary_header(bin, &bin_size);
  if(result != MRB_DUMP_OK) {
    return result;
  }
  bin += sizeof(struct rite_binary_header);

  do {
    section_header = bin;
    if(memcmp(section_header->section_identify, RITE_SECTION_IREP_IDENTIFIER, sizeof(section_header->section_identify)) == 0) {
      read_rite_section_irep(mrb, bin);
    }
    bin += bin_to_uint32(section_header->section_size);
  } while(memcmp(section_header->section_identify, RITE_BINARY_EOF, sizeof(section_header->section_identify)) != 0);

  return MRB_DUMP_OK;
}

static void
irep_error(mrb_state *mrb, const char *msg)
{
  mrb->exc = (struct RObject*)mrb_object(mrb_exc_new(mrb, E_SCRIPT_ERROR, msg, sizeof(msg) - 1));
}

mrb_value
mrb_load_irep_file(mrb_state *mrb, FILE* fp)
{
  return mrb_nil_value();
}

mrb_value
mrb_load_irep(mrb_state *mrb, const unsigned char *bin)
{
  int result, n;
  uint32_t bin_size;

  n = mrb_read_irep(mrb, bin);
  if (n < 0) {
    irep_error(mrb, "irep load error");
    return mrb_nil_value();
  }
  return mrb_run(mrb, mrb_proc_new(mrb, mrb->irep[n]), mrb_top_self(mrb));
}
