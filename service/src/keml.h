#ifndef __KEML_H__
#define __KEML_H__
#include <linux/spinlock.h>
#include <linux/types.h>

#define EMUL_PAGE_EXEC  4
#define EMUL_PAGE_WRITE 2
#define EMUL_PAGE_READ  1

void keml_emul_unit_destroy(struct kref *);

/* struct defs */
typedef struct keml_dev {
  spinlock_t mem_lock;
  spinlock_t unit_idr_lock;
  struct idr unit_idr;
} keml_dev_t;

struct keml_emul_unit {
  struct kref refcount;
  int id;
  spinlock_t unit_lock;
  unsigned long kernel_addr;
  unsigned int pages;
  int pending_free;
};

/* emulation */
enum {
  MOV_REG_IMM,
  MOV_REG_REG,
  ADD_REG_IMM, // 2
  ADD_REG_REG,
  SUB_REG_IMM, // 4
  SUB_REG_REG,
  XOR_REG_IMM, // 6
  XOR_REG_REG,
  STR_ADR_REG, // 8
  STR_REG_REG,
  LDR_REG_ADR, // 10
  LDR_REG_REG,
  CMP_REG_IMM, // 12
  CMP_REG_REG,
  JMP_IMM,     // 14
  JMP_REG,
  JE_IMM,      // 16
  JE_REG,
  JL_IMM,      // 18
  JL_REG,
  JA_IMM,      // 20
  JA_REG,
  JNE_IMM,     // 22
  JNE_REG,
  CALL_IMM,    // 24
  CALL_REG,
  RET,         // 26
  NOP,
  PUSH_REG,    // 28
  POP_REG,
};

struct processor {
  uint16_t pc;
  uint16_t sp;
  uint16_t flags;
  uint16_t gpr[16];
};

/* must be size of unsigned long */
struct instruction {
  uint8_t opcode; 
  uint8_t reg;
  union {
    uint16_t addr;
    uint16_t reg;
    uint16_t immed;
  } op;
};

/* ioctl params */
struct emul_create_param {
  unsigned int n_pages;
  unsigned int id;
};

struct emul_issue_order_param {
  size_t n_instructions;
  uint32_t *instructions;
  size_t n_units;
  int *unit_handles;
};

/* helpers */
static inline int
keml_emul_unit_get(struct keml_emul_unit *unit)
{
  if (unit)
    kref_get(&unit->refcount);
  return 0;
}

static inline int
keml_emul_unit_put(struct keml_emul_unit *unit)
{
  if (unit)
    kref_put(&unit->refcount, keml_emul_unit_destroy);
  return 0;
}

/* ioctl codes */
#define IOCTL_NEW_EMUL_UNIT   _IOWR('k', 1, void *)
#define IOCTL_NEW_DATA_UNIT   _IOWR('k', 2, uint64_t)
#define IOCTL_ISSUE_ORDER     _IOWR('k', 3, void *)
#define IOCTL_GET_UNIT        _IOWR('k', 4, void *)
#define IOCTL_DESTROY_UNIT    _IOWR('k', 5, int)
#endif
