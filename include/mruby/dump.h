/*
** mruby/dump.h - mruby binary dumper (Rite binary format)
**
** See Copyright Notice in mruby.h
*/

#ifndef MRUBY_DUMP_H
#define MRUBY_DUMP_H

#if defined(__cplusplus)
extern "C" {
#endif

#include "mruby.h"
#ifdef ENABLE_STDIO
#include <stdio.h>
#endif
#include <stdint.h>

#ifdef ENABLE_STDIO
int mrb_dump_irep(mrb_state*,int,FILE*);
int mrb_bdump_irep(mrb_state *mrb, int n, FILE *f,const char *initname);

int mrb_read_irep_file(mrb_state*,FILE*);
#endif
int mrb_read_irep(mrb_state*,const char*);

#ifdef ENABLE_STDIO
mrb_value mrb_load_irep_file(mrb_state*,FILE*);
#endif

/* dump type */
#define DUMP_TYPE_CODE 0
#define DUMP_TYPE_BIN  1
#define DUMP_TYPE_HEX  2

/* dump/load error code
 *
 * NOTE: MRB_DUMP_GENERAL_FAILURE is caused by
 * unspecified issues like malloc failed.
 */
#define MRB_DUMP_OK                     0
#define MRB_DUMP_GENERAL_FAILURE        -1
#define MRB_DUMP_WRITE_FAULT            -2
#define MRB_DUMP_READ_FAULT             -3
#define MRB_DUMP_CRC_ERROR              -4
#define MRB_DUMP_INVALID_FILE_HEADER    -5
#define MRB_DUMP_INVALID_IREP           -6
#define MRB_DUMP_INVALID_ARGUMENT       -7

/* size of long/int/short value on dump/load */
#define MRB_DUMP_SIZE_OF_LONG          4
#define MRB_DUMP_SIZE_OF_INT           4
#define MRB_DUMP_SIZE_OF_SHORT         2
#define MRB_DUMP_SIZE_OF_CHAR          1

/* null symbol length */
#define MRB_DUMP_NULL_SYM_LEN          0xFFFF

/* Use HEX format string */
#define RITE_FILE_IS_HEX

#ifdef RITE_FILE_IS_HEX
#define RITE_FILE_HEX_SIZE             2
#else
#define RITE_FILE_HEX_SIZE             1
#endif

/* Rite Binary File header */
#define RITE_BINARY_IDENFIFIER        "RITE"
#define RITE_BINARY_FORMAT_VER        "0000"
#define RITE_VM_VER                   "00"

#define RITE_BINARY_EOF               "END "


/* irep header */
#define RITE_IREP_IDENFIFIER           'S'
#define RITE_IREP_TYPE_CLASS           'C'
#define RITE_IREP_TYPE_MODULE          'M'

#define MRB_DUMP_DEFAULT_STR_LEN       128

// Rite binary header
struct rite_binary_header {
  unsigned char binary_identify[4]; // Rite Binary Identify
  unsigned char binary_version[4];  // Rite Binary Format Version
  unsigned char binary_size[4];     // Rite Binary Size
  unsigned char binary_crc[4];      // Rite Binary CRC
};

// Rite section header
#define RITE_SECTION_HEADER \
  unsigned char section_identify[4]; \
  unsigned char section_size[4];

struct rite_section_irep_header {
  RITE_SECTION_HEADER;

  unsigned char rite_version[4];  // Rite Instruction Specification Version
  unsigned char compiler_type[4]; // Rite Compiler Type
  unsigned char compiler_version[4];
  unsigned char nirep[2];         // Number of ireps
  unsigned char sirep[2];         // Start index  
};

struct rite_binary_footer {
  RITE_SECTION_HEADER;
};

static inline int
uint8_to_bin(uint8_t s, unsigned char *bin)
{
  *bin = s;
  return sizeof(uint8_t);
}

static inline int
uint16_to_bin(uint16_t s, unsigned char *bin)
{
  *bin++ = (s >> 8) & 0xff;
  *bin   = s & 0xff;
  return sizeof(uint16_t);
}

static inline int
uint32_to_bin(uint32_t l, unsigned char *bin)
{
  *bin++ = (l >> 24) & 0xff;
  *bin++ = (l >> 16) & 0xff;
  *bin++ = (l >> 8) & 0xff;
  *bin   = l & 0xff;
  return sizeof(uint32_t);
}

static inline uint32_t
bin_to_uint32(unsigned char bin[])
{
  return (uint32_t)bin[0] << 24 |
         (uint32_t)bin[1] << 16 |
         (uint32_t)bin[2] << 8  |
         (uint32_t)bin[3];
}

static inline uint16_t
bin_to_uint16(unsigned char bin[])
{
  return (uint16_t)bin[0] << 8 |
         (uint16_t)bin[1];
}

static inline uint8_t
bin_to_uint8(unsigned char bin[])
{
  return (uint8_t)bin[0];
}

#if defined(__cplusplus)
}  /* extern "C" { */
#endif

#endif  /* MRUBY_DUMP_H */
