/*
** dump.c - mruby binary dumper (Rite binary format)
**
** See Copyright Notice in mruby.h
*/

#include <string.h>
#include "mruby/dump.h"
#include <ctype.h>

#include "mruby/string.h"
#include "mruby/irep.h"
#include "mruby/numeric.h"


static uint32_t
get_irep_record_size(mrb_state *mrb, mrb_irep *irep);

#ifdef ENABLE_STDIO

static uint32_t
get_irep_header_size(mrb_state *mrb)
{
  uint32_t size = 0;

  size += 1; // identifier
  size += sizeof(uint32_t) * 1;
  size += sizeof(uint16_t) * 3;

  return size;
}

static int
write_irep_header(mrb_state *mrb, mrb_irep *irep, unsigned char *buf)
{
  unsigned char *buf_top = buf;

  *buf++ = RITE_IREP_IDENTIFIER; /* record identifier */
  buf += uint32_to_bin(get_irep_record_size(mrb, irep), buf);  /* number of register variable */
  buf += uint16_to_bin((uint16_t)irep->nlocals, buf);  /* number of local variable */
  buf += uint16_to_bin((uint16_t)irep->nregs, buf);  /* number of register variable */
  buf += uint16_to_bin(0, buf); /* offset of isec block */

  return (int)(buf - buf_top);
}


static uint32_t
get_iseq_block_size(mrb_state *mrb, mrb_irep *irep)
{
  uint32_t size = 0;

  size += sizeof(uint32_t); /* ilen */
  size += irep->ilen * sizeof(mrb_code); /* iseq(n) */

  return size;
}

static int
write_iseq_block(mrb_state *mrb, mrb_irep *irep, unsigned char *buf)
{
  unsigned char *buf_top = buf;
  int iseq_no;

  buf += uint32_to_bin((uint32_t)irep->ilen, buf); /* number of opcode */

  for (iseq_no = 0; iseq_no < irep->ilen; iseq_no++) {
    buf += uint32_to_bin((uint32_t)irep->iseq[iseq_no], buf); /* opcode */
  }

  return (int)(buf - buf_top);
}


static uint32_t
get_pool_block_size(mrb_state *mrb, mrb_irep *irep)
{
  uint32_t size = 0;
  int pool_no;
  mrb_value str;
  char buf[32];

  size += sizeof(uint32_t); /* plen */
  size += irep->plen * (sizeof(uint8_t) + sizeof(uint16_t)); /* len(n) */

  for (pool_no = 0; pool_no < irep->plen; pool_no++) {
    int len;
    switch (mrb_type(irep->pool[pool_no])) {
    case MRB_TT_FIXNUM:
      str = mrb_fix2str(mrb, irep->pool[pool_no], 10);
      size += (uint32_t)RSTRING_LEN(str);
      break;

    case MRB_TT_FLOAT:
      len = mrb_float_to_str(buf, mrb_float(irep->pool[pool_no]));
      size += (uint32_t)len;
      break;

    case MRB_TT_STRING:
      str = mrb_string_value(mrb, &irep->pool[pool_no]);
      size += RSTRING_LEN(str);
      break;

    default:
      break;
    }
  }

  return size;
}

static int
write_pool_block(mrb_state *mrb, mrb_irep *irep, unsigned char *buf)
{
  int pool_no;
  mrb_value str;
  unsigned char *buf_top = buf;
  char *char_buf;
  uint16_t buf_size = 0;
  uint16_t len = 0;
  int result;

  buf_size = MRB_DUMP_DEFAULT_STR_LEN;
  char_buf = (char *)mrb_malloc(mrb, buf_size);
  if (char_buf == NULL) {
    result = MRB_DUMP_GENERAL_FAILURE;
    goto error_exit;
  }

  buf += uint32_to_bin((uint32_t)irep->plen, buf); /* number of pool */

  for (pool_no = 0; pool_no < irep->plen; pool_no++) {
    buf += uint8_to_bin(mrb_type(irep->pool[pool_no]), buf); /* data type */
    memset(char_buf, 0, buf_size);

    switch (mrb_type(irep->pool[pool_no])) {
    case MRB_TT_FIXNUM:
      str = mrb_fix2str(mrb, irep->pool[pool_no], 10);
      memcpy(char_buf, RSTRING_PTR(str), RSTRING_LEN(str));
      len = RSTRING_LEN(str);
      break;

    case MRB_TT_FLOAT:
      len = mrb_float_to_str(char_buf, mrb_float(irep->pool[pool_no]));
      break;

    case MRB_TT_STRING:
      str = irep->pool[pool_no];
      len = RSTRING_LEN(str);
      if (len > buf_size - 1) {
        buf_size = len + 1;
        char_buf = (char *)mrb_realloc(mrb, char_buf, buf_size);
        if (char_buf == NULL) {
          result = MRB_DUMP_GENERAL_FAILURE;
          goto error_exit;
        }
        memset(char_buf, 0, buf_size);
      }
      memcpy(char_buf, RSTRING_PTR(str), RSTRING_LEN(str));
      break;

    default:
      len = 0;
      continue;
    }

    buf += uint16_to_bin(len, buf); /* data length */
    memcpy(buf, char_buf, len);
    buf += len;
  }

  result = (int)(buf - buf_top);

error_exit:
  mrb_free(mrb, char_buf);
  return result;
}


static uint32_t
get_syms_block_size(mrb_state *mrb, mrb_irep *irep)
{
  uint32_t size = 0;
  int sym_no;

  size += sizeof(uint32_t); /* slen */
  for (sym_no = 0; sym_no < irep->slen; sym_no++) {
    size += sizeof(uint16_t); /* snl(n) */
    if (irep->syms[sym_no] != 0) {
      int len;
      mrb_sym2name_len(mrb, irep->syms[sym_no], &len);
      size += len; /* sn(n) */
    }
  }

  return size;
}

static int
write_syms_block(mrb_state *mrb, mrb_irep *irep, unsigned char *buf)
{
  int sym_no;
  unsigned char *buf_top = buf;
  char *char_buf;
  uint16_t buf_size =0;

  buf_size = MRB_DUMP_DEFAULT_STR_LEN;
  char_buf = (char *)mrb_malloc(mrb, buf_size);
  if (char_buf == NULL)
    goto error_exit;

  buf += uint32_to_bin((uint32_t)irep->slen, buf); /* number of symbol */

  for (sym_no = 0; sym_no < irep->slen; sym_no++) {
    const char *name;
    uint16_t nlen =0;

    if (irep->syms[sym_no] != 0) {
      int len;

      name = mrb_sym2name_len(mrb, irep->syms[sym_no], &len);
      nlen = len;
      if ( nlen > buf_size - 1) {
        buf_size = nlen + 1;
        char_buf = (char *)mrb_realloc(mrb, char_buf, buf_size);
        if (char_buf == NULL)
          goto error_exit;
      }
      memset(char_buf, 0, buf_size);
      memcpy(char_buf, name, len);

      buf += uint16_to_bin(nlen, buf); /* length of symbol name */
      memcpy(buf, char_buf, nlen); /* symbol name */
      buf += nlen;
    }
    else {
      buf += uint16_to_bin(MRB_DUMP_NULL_SYM_LEN, buf); /* length of symbol name */
    }
  }

error_exit:
  mrb_free(mrb, char_buf);
  return (int)(buf - buf_top);
}



static uint32_t
get_irep_record_size(mrb_state *mrb, mrb_irep *irep)
{
  uint32_t size = 0;

  //size += sizeof(uint16_t); /* rlen */
  size += get_irep_header_size(mrb);
  size += get_iseq_block_size(mrb, irep);
  size += get_pool_block_size(mrb, irep);
  size += get_syms_block_size(mrb, irep);

  return size;
}
static int
write_irep_record(mrb_state *mrb, mrb_irep *irep, unsigned char* bin, uint32_t *irep_record_size)
{
  if (irep == NULL) {
    return MRB_DUMP_INVALID_IREP;
  }

  *irep_record_size = get_irep_record_size(mrb, irep);
  if (*irep_record_size == 0) {
    return MRB_DUMP_GENERAL_FAILURE;
  }

  memset(bin, 0, *irep_record_size);

  //bin += uint16_to_bin(*irep_record_size, bin);
  bin += write_irep_header(mrb, irep, bin);
  bin += write_iseq_block(mrb, irep, bin);
  bin += write_pool_block(mrb, irep, bin);
  bin += write_syms_block(mrb, irep, bin);

  return MRB_DUMP_OK;
}

static size_t
mrb_write_eof(mrb_state *mrb, unsigned char *bin)
{
  struct rite_binary_footer footer;

  memcpy(footer.section_identify, RITE_BINARY_EOF, sizeof(footer.section_identify));
  uint32_to_bin(sizeof(struct rite_binary_footer), footer.section_size);
  memcpy(bin, &footer, sizeof(struct rite_binary_footer));

  return sizeof(struct rite_binary_footer);
}


static int
mrb_write_section_irep_header(mrb_state *mrb, uint32_t section_size, uint16_t nirep, uint16_t sirep, unsigned char *bin)
{ 
  struct rite_section_irep_header *header = (struct rite_section_irep_header*)bin;

  memcpy(header->section_identify, RITE_SECTION_IREP_IDENTIFIER, sizeof(header->section_identify));
  uint32_to_bin(section_size, header->section_size);
  memcpy(header->rite_version, RITE_VM_VER, sizeof(header->rite_version));
  memcpy(header->compiler_name, RITE_COMPILER_NAME, sizeof(header->compiler_name));
  memcpy(header->compiler_version, RITE_COMPILER_VERSION, sizeof(header->compiler_version));
  header->endianness = RITE_SECTION_IREP_BIG_ENDIAN;
  uint16_to_bin(nirep, header->nirep);
  uint16_to_bin(sirep, header->sirep);

  return MRB_DUMP_OK;
}

static int
mrb_write_section_irep(mrb_state *mrb, int start_index, unsigned char *bin)
{
  int result;
  uint32_t section_size = 0, rlen = 0; /* size of irep record */
  int irep_no;
  unsigned char *bin_cur = bin;

  if (mrb == NULL || start_index < 0 || start_index >= mrb->irep_len || bin == NULL) {
    return MRB_DUMP_INVALID_ARGUMENT;
  }

  bin_cur += sizeof(struct rite_section_irep_header);
  section_size += sizeof(struct rite_section_irep_header);

  for (irep_no = start_index; irep_no < mrb->irep_len; irep_no++) {
    result = write_irep_record(mrb, mrb->irep[irep_no], bin_cur, &rlen);
    if (result != MRB_DUMP_OK) {
      return result;
    }
    bin_cur += rlen;
    section_size += rlen;
  }

  mrb_write_section_irep_header(mrb, section_size, mrb->irep_len - start_index, start_index, bin);

  return MRB_DUMP_OK;
}

static int
write_rite_binary_header(mrb_state *mrb, uint32_t binary_size, unsigned char* bin)
{ 
  struct rite_binary_header *header = (struct rite_binary_header*)bin;

  memcpy(header->binary_identify, RITE_BINARY_IDENFIFIER, sizeof(header->binary_identify));
  memcpy(header->binary_version, RITE_BINARY_FORMAT_VER, sizeof(header->binary_version));
  uint32_to_bin(binary_size, header->binary_size);
  // TODO: CRC

  return MRB_DUMP_OK;
}

static int
mrb_dump_irep(mrb_state *mrb, int start_index, unsigned char **bin, uint32_t *bin_size)
{
  int result = MRB_DUMP_OK, irep_no, section_irep_size;
  unsigned char *bin_cur;

  if (mrb == NULL || start_index < 0 || start_index >= mrb->irep_len) {
    *bin = NULL;
    goto error_exit;
  }

  section_irep_size = sizeof(struct rite_section_irep_header);
  for (irep_no = start_index; irep_no < mrb->irep_len; irep_no++) {
    section_irep_size += get_irep_record_size(mrb, mrb->irep[irep_no]);
  }

  *bin_size += sizeof(struct rite_binary_header) + section_irep_size + sizeof(struct rite_binary_footer);
  *bin = bin_cur = (unsigned char *)mrb_malloc(mrb, *bin_size);
  if(*bin == NULL) {
    goto error_exit;
  }

  bin_cur += sizeof(struct rite_binary_header);

  result = mrb_write_section_irep(mrb, start_index, bin_cur);
  if (result != MRB_DUMP_OK) {
    goto error_exit;
  }

  bin_cur += section_irep_size;
  mrb_write_eof(mrb, bin_cur);

  result = write_rite_binary_header(mrb, *bin_size, *bin);

error_exit:
  if(result != MRB_DUMP_OK) {
    mrb_free(mrb, *bin);
    *bin = NULL;
  }
  return result;
}


int
mrb_dump_irep_binary(mrb_state *mrb, int start_index, FILE* fp)
{
  unsigned char *bin = NULL;
  uint32_t bin_size = 0;
  int result;

  if (fp == NULL) {
    return MRB_DUMP_INVALID_ARGUMENT;
  }

  result = mrb_dump_irep(mrb, start_index, &bin, &bin_size);
  if (result == MRB_DUMP_OK) {
    fwrite(bin, bin_size, 1, fp);
  }

  mrb_free(mrb, bin);
  return result;
}

int
mrb_dump_irep_cfunc(mrb_state *mrb, int start_index, FILE *fp, const char *initname)
{
  unsigned char *bin = NULL;
  uint32_t bin_size = 0, bin_idx = 0;
  int result;

  if (fp == NULL || initname == NULL) {
    return MRB_DUMP_INVALID_ARGUMENT;
  }

  result = mrb_dump_irep(mrb, start_index, &bin, &bin_size);
  if (result == MRB_DUMP_OK) {
    fprintf(fp, "const unsigned char %s[] = {", initname);
    while (bin_idx < bin_size) {
      if (bin_idx % 16 == 0 ) fputs("\n", fp);
      fprintf(fp, "0x%02x,", (unsigned char)bin[bin_idx++]);
    }
    fputs("\n};\n", fp);
  }

  mrb_free(mrb, bin);
  return result;
}

#endif /* ENABLE_STDIO */
