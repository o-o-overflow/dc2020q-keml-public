#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/sched/mm.h>
#include <linux/slab.h>
#include <linux/mm.h>

#include "keml.h"

MODULE_DESCRIPTION("KEmulator");

#define MAJORNUM 414
#define MAX_UNIT_LEN 0x1000
#define MAX_PAGES 0x4
#define MAX_ORDER_INSTRUCTIONS 0x10000
#define MAX_ORDER_UNITS 0x4

keml_dev_t keml_device;
struct kmem_cache *emul_unit_cache = NULL;

bool keml_emul_unit_get_pend(struct keml_emul_unit *unit) {
    bool ret = false;

    spin_lock(&keml_device.mem_lock);
    if (unit->pending_free) {
        ret = true;
    }
    spin_unlock(&keml_device.mem_lock);
    return ret;
}

bool keml_emul_unit_set_pend(struct keml_emul_unit *unit) {
    bool ret = false;

    spin_lock(&keml_device.mem_lock);
    if (!unit->pending_free) {
        unit->pending_free = 1;
        ret = true;
    }
    spin_unlock(&keml_device.mem_lock);
    return ret;
}

struct keml_emul_unit *keml_emul_unit_create(int id, unsigned pages) {
    struct keml_emul_unit *out;

    if (pages > MAX_PAGES) {
        return NULL;
    }

    out = (struct keml_emul_unit *)kmem_cache_alloc(emul_unit_cache, GFP_KERNEL);
    if (IS_ERR_OR_NULL(out)) {
        return NULL;
    }
    memset(out, 0, sizeof(struct keml_emul_unit));

    kref_init(&out->refcount);

    spin_lock_init(&out->unit_lock);

    out->id = id;
    out->kernel_addr = __get_free_pages(GFP_KERNEL, get_order(pages * PAGE_SIZE));
    if (!out->kernel_addr) {
        kfree(out);
        return NULL;
    }
    memset((void *)out->kernel_addr, 0, pages * PAGE_SIZE);
    out->pages = pages;

    return out; 
}

void keml_emul_unit_destroy(struct kref *kref)
{
    struct keml_emul_unit *unit = container_of(
                kref,
                struct keml_emul_unit,
                refcount);

    //pr_info("in destroy");

    if (unit == NULL)
        return;

    //pr_info("destroying unit %d\n", unit->id);

    spin_lock(&keml_device.unit_idr_lock);
    if (unit->id != 0)
        idr_remove(&keml_device.unit_idr, unit->id);
    spin_unlock(&keml_device.unit_idr_lock);

    free_pages(unit->kernel_addr, get_order(unit->pages));
    kfree(unit);
}

struct keml_emul_unit * __must_check
keml_emul_unit_find_id(int id)
{
    struct keml_emul_unit *found = NULL;
    
    spin_lock(&keml_device.unit_idr_lock);
    found = idr_find(&keml_device.unit_idr, id);
    spin_unlock(&keml_device.unit_idr_lock);

    if (found) {
        if (keml_emul_unit_get_pend(found))
            return NULL;
        keml_emul_unit_get(found);
    }

    return found;
}

static int get_emul_unit(struct keml_emul_unit **out,
                         unsigned long pgoff,
                         unsigned long len)
{
    struct keml_emul_unit *unit = NULL;

    unit = keml_emul_unit_find_id(pgoff);
    if (!unit)
        return -EINVAL;

    if (len > (unit->pages * PAGE_SIZE)) {
        keml_emul_unit_put(unit);
        return -ERANGE;
    }

    *out = unit;

    return 0;
}

/* -- EMULATION -- */

static void *kernel_addr_for_emul_vaddr(uint16_t vaddr,
                                        struct keml_emul_unit **units,
                                        size_t n_units) {
    size_t i;
    uint8_t msb;
    uint16_t lsb;
    unsigned int current_off = 0;

    msb = (vaddr >> 12) & 0xf;
    lsb = vaddr & 0xfff;

    for (i=0;i<n_units;i++) {
        if (msb >= current_off && msb < current_off + units[i]->pages) {
            return (void *)(units[i]->kernel_addr + \
                            (msb - current_off) * PAGE_SIZE) + \
                            lsb;
        }
        current_off += units[i]->pages;
    }
    return NULL;
}

#define INC_PC(pc) *((uint16_t *)pc)+=4
#define REG(i) (i.reg&0xf)
#define OPREG(i) (i.op.reg&0xf)
#define OPIMM(i) (i.op.immed)
#define OPADR(i) (i.op.addr)
#define PUSH(imm) (stack[proc.sp++] = imm)
#define POP() (stack[--proc.sp])
#define ALLOC_STACK() do {\
        if (!stack) { \
            stack = (uint16_t *)__get_free_pages(GFP_KERNEL, get_order(0x10)); \
            if (!stack) { \
                ret = -ENOMEM; \
            } \
        } } while(0)

#define DEALLOC_STACK() do {\
        if (stack) { \
            free_pages((unsigned long )stack, get_order(0x10)); \
        } } while(0)

#define STACK_LIMIT (0x10000/sizeof(uint16_t))

long emulate_order(uint32_t *instrs,
                   size_t instrs_len,
                   struct keml_emul_unit **units,
                   size_t n_units)
{
    long ret = 0;
    uint16_t reg_val = 0;
    void *resaddr = NULL;
    struct processor proc = {0};
    uint16_t *stack = NULL;
    struct instruction instr;

    do {
        //pr_info("Instruction: %x\n", instrs[proc.pc/sizeof(uint32_t)]);
        instr = *((struct instruction *)&instrs[proc.pc/sizeof(uint32_t)]);
        instr.op.immed = htons(instr.op.immed);
        //pr_info("PC: %d\n", proc.pc);
        switch(instr.opcode) {
            case MOV_REG_IMM:
                //pr_info("mov [%d] <- %d\n", REG(instr), OPIMM(instr));
                proc.gpr[REG(instr)] = OPIMM(instr);
                INC_PC(&proc.pc);
                break;
            case MOV_REG_REG:
                //pr_info("mov [%d] <- [%d]\n", REG(instr), OPREG(instr));
                reg_val = proc.gpr[OPREG(instr)];
                proc.gpr[REG(instr)] = reg_val;
                INC_PC(&proc.pc);
                break;
            case ADD_REG_IMM:
                //pr_info("add [%d] <- %d\n", REG(instr), OPIMM(instr));
                proc.gpr[REG(instr)] += OPIMM(instr);
                INC_PC(&proc.pc);
                break;
            case ADD_REG_REG:
                //pr_info("add [%d] <- [%d]\n", REG(instr), OPREG(instr));
                proc.gpr[REG(instr)] += proc.gpr[OPREG(instr)];
                INC_PC(&proc.pc);
                break;
            case SUB_REG_IMM:
                //pr_info("sub [%d] <- %d\n", REG(instr), OPIMM(instr));
                proc.gpr[REG(instr)] -= OPIMM(instr);
                INC_PC(&proc.pc);
                break;
            case SUB_REG_REG:
                //pr_info("sub [%d] <- [%d]\n", REG(instr), OPREG(instr));
                proc.gpr[REG(instr)] -= proc.gpr[OPREG(instr)];
                INC_PC(&proc.pc);
                break;
            case XOR_REG_IMM:
                //pr_info("(%x) xor [%d] <- %d\n", proc.pc, REG(instr), OPIMM(instr));
                proc.gpr[REG(instr)] ^= OPIMM(instr);
                INC_PC(&proc.pc);
                break;
            case XOR_REG_REG:
                //pr_info("(%x) xor [%d] <- [%d]\n", proc.pc, REG(instr), OPREG(instr));
                proc.gpr[REG(instr)] ^= proc.gpr[OPREG(instr)];
                INC_PC(&proc.pc);
                break;
            case STR_ADR_REG:
                //pr_info("str [%d] <- %x\n", OPADR(instr), REG(instr));
                resaddr = kernel_addr_for_emul_vaddr(OPADR(instr), units, n_units);
                if (!resaddr) {
                    ret = -EFAULT;
                    break;
                }
                reg_val = proc.gpr[REG(instr)] & 0xff;
                *((uint8_t *)resaddr) = reg_val;
                INC_PC(&proc.pc);
                break;
            case STR_REG_REG:
                //pr_info("str [%d] <- [%d]\n", OPREG(instr), REG(instr));
                reg_val = proc.gpr[OPREG(instr)];
                resaddr = kernel_addr_for_emul_vaddr(reg_val, units, n_units);
                if (!resaddr) {
                    ret = -EFAULT;
                    break;
                }
                reg_val = proc.gpr[REG(instr)] & 0xff;
                *((uint8_t *)resaddr) = reg_val;    
                INC_PC(&proc.pc);
                break;
            case LDR_REG_ADR:
                //pr_info("ldr [%d] <- %x\n", REG(instr), OPADR(instr));
                resaddr = kernel_addr_for_emul_vaddr(OPIMM(instr), units, n_units); 
                if (!resaddr) {
                    ret = -EFAULT;
                    break;
                }
                proc.gpr[REG(instr)] = *((uint8_t *)resaddr);
                INC_PC(&proc.pc);
                break;
            case LDR_REG_REG:
                //pr_info("ldr [%d] <- [%d]\n", OPREG(instr), REG(instr));
                reg_val = proc.gpr[OPREG(instr)];
                resaddr = kernel_addr_for_emul_vaddr(reg_val, units, n_units);
                if (!resaddr) {
                    ret = -EFAULT;
                    break;
                }
                proc.gpr[REG(instr)] = *((uint8_t *)resaddr);
                INC_PC(&proc.pc);
                break;
            case CMP_REG_IMM:
                //pr_info("cmp [%d] ? %x\n", REG(instr), OPIMM(instr));
                // clear
                proc.flags &= 0;
                reg_val = proc.gpr[REG(instr)] - OPIMM(instr);
                proc.flags |= reg_val ? 0 : 1;
                proc.flags |= (reg_val > proc.gpr[REG(instr)] ? 1 : 0) << 1;
                INC_PC(&proc.pc);
                break;
            case CMP_REG_REG:
                //pr_info("cmp [%d] ? [%d]\n", REG(instr), OPREG(instr));
                // clear
                proc.flags &= 0;
                reg_val = proc.gpr[REG(instr)] - proc.gpr[OPREG(instr)];
                proc.flags |= reg_val ? 0 : 1;
                proc.flags |= (reg_val > proc.gpr[REG(instr)] ? 1 : 0) << 1;
                INC_PC(&proc.pc);
                break;
            case JMP_IMM:
                //pr_info("jmp %d\n", OPIMM(instr));
                if (OPIMM(instr) >= instrs_len ||
                        OPIMM(instr) % 4 != 0) {
                    ret = -EFAULT;
                    break;
                }
                proc.pc = OPIMM(instr);
                break;
            case JMP_REG:
                //pr_info("jmp [%d]\n", OPREG(instr));
                reg_val = proc.gpr[OPREG(instr)];
                if (reg_val >= instrs_len ||
                        reg_val % 4 != 0) {
                    ret = -EFAULT;
                    break;
                }
                proc.pc = reg_val;
                break;
            case JE_IMM:
                //pr_info("je %d\n", OPIMM(instr));
                if (proc.flags & 1) {
                    if (OPIMM(instr) >= instrs_len ||
                            OPIMM(instr) % 4 != 0) {
                        ret = -EFAULT;
                        break;
                    }
                    proc.pc = OPIMM(instr);
                } else {
                    INC_PC(&proc.pc);
                }
                break;
            case JE_REG:
                //pr_info("je [%d]\n", OPREG(instr));
                if (proc.flags & 1) {
                    reg_val = proc.gpr[OPREG(instr)];
                    if (reg_val >= instrs_len ||
                            reg_val % 4 != 0) {
                        ret = -EFAULT;
                        break;
                    }
                    proc.pc = reg_val;
                } else {
                    INC_PC(&proc.pc);
                }
                break;
            case JL_IMM:
                //pr_info("jl %d\n", OPIMM(instr));
                if (proc.flags & 2) {
                    if (OPIMM(instr) >= instrs_len ||
                            OPIMM(instr) % 4 != 0) {
                        ret = -EFAULT;
                        break;
                    }
                    proc.pc = OPIMM(instr);
                } else {
                    INC_PC(&proc.pc);
                }
                break;
            case JL_REG:
                //pr_info("jl [%d]\n", OPREG(instr));
                if (proc.flags & 2) {
                    reg_val = proc.gpr[OPREG(instr)];
                    if (reg_val >= instrs_len ||
                            reg_val % 4 != 0) {
                        ret = -EFAULT;
                        break;
                    }
                    proc.pc = reg_val;
                } else {
                    INC_PC(&proc.pc);
                }
                break;
            case JA_IMM:
                //pr_info("ja %d\n", OPIMM(instr));
                if (proc.flags == 0) {
                    if (OPIMM(instr) >= instrs_len ||
                            OPIMM(instr) % 4 != 0) {
                        ret = -EFAULT;
                        break;
                    }
                    proc.pc = OPIMM(instr);
                } else {
                    INC_PC(&proc.pc);
                }
                break;
            case JA_REG:
                //pr_info("ja [%d]\n", OPREG(instr));
                if (proc.flags == 0) {
                    reg_val = proc.gpr[OPREG(instr)];
                    if (reg_val >= instrs_len ||
                            reg_val % 4 != 0) {
                        ret = -EFAULT;
                        break;
                    }
                    proc.pc = reg_val;
                } else {
                    INC_PC(&proc.pc);
                }
                break;
            case JNE_IMM:
                //pr_info("jne %d\n", OPIMM(instr));
                if (!(proc.flags & 1)) {
                    if (OPIMM(instr) >= instrs_len ||
                            OPIMM(instr) % 4 != 0) {
                        ret = -EFAULT;
                        break;
                    }
                    proc.pc = OPIMM(instr);
                } else {
                    INC_PC(&proc.pc);
                }
                break;
            case JNE_REG:
                //pr_info("jne [%d]\n", OPREG(instr));
                if (!(proc.flags & 1)) {
                    reg_val = proc.gpr[OPREG(instr)];
                    if (reg_val >= instrs_len ||
                            reg_val % 4 != 0) {
                        ret = -EFAULT;
                        break;
                    }
                    proc.pc = reg_val;
                } else {
                    INC_PC(&proc.pc);
                }
                break;
            case CALL_IMM:
                //pr_info("call %x\n", OPIMM(instr));
                if (proc.sp >= STACK_LIMIT) {
                    ret = -EFAULT;  
                    break;
                }
                if (OPIMM(instr) >= instrs_len ||
                        OPIMM(instr) % 4 != 0) {
                    ret = -EFAULT;
                    break;
                }
                ALLOC_STACK();
                PUSH(proc.pc + 4);
                proc.pc = OPIMM(instr);
                break;
            case CALL_REG:
                //pr_info("call [%d]\n", OPREG(instr));
                if (proc.sp >= STACK_LIMIT) {
                    ret = -EFAULT;
                    break;
                }
                reg_val = proc.gpr[OPREG(instr)];
                if (reg_val >= instrs_len ||
                        reg_val % 4 != 0) {
                    ret = -EFAULT;
                    break;
                }
                ALLOC_STACK();
                PUSH(proc.pc + 4);
                proc.pc = reg_val;
                break;
            case RET:
                //pr_info("ret\n");
                if (proc.sp == 0) {
                    ret = -EFAULT;
                    break;
                }
                proc.pc = POP();
                break;
            case NOP:
                //pr_info("nop\n");
                INC_PC(&proc.pc);
                break;
            case PUSH_REG:
                ///pr_info("push [%d]\n", OPREG(instr));
                if (proc.sp >= STACK_LIMIT) {
                    ret = -EFAULT;
                    break;
                }
                reg_val = proc.gpr[OPREG(instr)];
                ALLOC_STACK();
                PUSH(reg_val);
                INC_PC(&proc.pc);
                break;
            case POP_REG:
                //pr_info("pop [%d]\n", OPREG(instr));
                if (proc.sp == 0) {
                    ret = -EFAULT;
                    break;
                }
                reg_val = POP();
                //pr_info("POPing %x\n", reg_val);
                proc.gpr[OPREG(instr)] = reg_val;
                INC_PC(&proc.pc);
                break;
            default:
                //pr_err("unimplemented instruction %x (%x)\n", instr.opcode, proc.pc);
                ret = -EINVAL;
                break;
        }
    } while (proc.pc < instrs_len && !ret);

    DEALLOC_STACK();
    return ret;
}

/* -- IOCTLS -- */

long keml_ioctl_emul_unit_create(void *arg)
{
    struct emul_create_param * __user user_param = 
        (struct emul_create_param * __user)arg;
    struct emul_create_param param = {0};
    struct keml_emul_unit *unit;
    long ret;
    int id;

    if (copy_from_user(&param.n_pages, user_param, sizeof(param.n_pages))) {
        return -EFAULT;
    }

    spin_lock(&keml_device.unit_idr_lock);
    id = idr_alloc(&keml_device.unit_idr, NULL, 1, 0, GFP_NOWAIT);
    spin_unlock(&keml_device.unit_idr_lock);

    if (id < 0) {
        //pr_err("failed to allocate new idr entry");
        return id;
    }

    param.id = id;

    unit = keml_emul_unit_create(id, param.n_pages);
    if (!unit) {
        ret = -ENOMEM;
        goto dealloc;
    }

    spin_lock(&keml_device.unit_idr_lock);
    idr_replace(&keml_device.unit_idr, unit, id);   
    spin_unlock(&keml_device.unit_idr_lock);

    //pr_info("created unit %d", unit->id);
    if (copy_to_user(&user_param->id, &param.id, sizeof(param.id))) {
        ret = -EFAULT;
        goto dealloc;
    }

    return 0;

dealloc:
    if (unit)
        keml_emul_unit_put(unit);

    return ret;
}

static long keml_ioctl_emul_unit_destroy(int id)
{
    long ret = 0;
    struct keml_emul_unit *unit;

    unit = keml_emul_unit_find_id(id);
    if (!unit)
        return -EINVAL;

    //pr_info("found unit %p", unit);
    if (keml_emul_unit_set_pend(unit)) {
        keml_emul_unit_put(unit);
    } else {
        ret = -EBUSY;
    }

    keml_emul_unit_put(unit);
    return ret;
}

static long keml_ioctl_issue_order(void *arg)
{
    struct emul_issue_order_param* __user user_param = 
        (struct emul_issue_order_param* __user)arg;
    struct emul_issue_order_param param = {0};
    int unit_handles[MAX_ORDER_UNITS] = {0};
    struct keml_emul_unit *units[MAX_ORDER_UNITS] = {0};
    uint32_t *instrs;
    size_t instr_len;
    size_t unit_len;
    long ret;
    int i;

    if (copy_from_user(&param, user_param, sizeof(param))) {
        return -EFAULT;
    }   

    if ((param.n_instructions > MAX_ORDER_INSTRUCTIONS) ||
        (param.n_instructions == 0) ||
        (param.n_units > MAX_ORDER_UNITS)) {
        return -EINVAL;
    }

    unit_len = param.n_units * sizeof(int);
    if (copy_from_user(&unit_handles, param.unit_handles, unit_len)) {
        return -EFAULT;
    }

    instr_len = sizeof(uint32_t) * param.n_instructions;
    instrs = (uint32_t *)kzalloc(instr_len, GFP_KERNEL);
    if (IS_ERR_OR_NULL(instrs)) {
        return -ENOMEM;
    }

    if (copy_from_user(instrs, param.instructions, instr_len)) {
        kfree(instrs);
        return -EFAULT;
    }

    /* convert the handles to units */
    for (i=0;i<param.n_units;i++) {
        struct keml_emul_unit *unit = keml_emul_unit_find_id(unit_handles[i]);
        if (!unit) { 
            ret = -EINVAL;
            goto dealloc_units;
        }
        units[i] = unit;    
    }

    /* lock the units to prevent concurrent accesses */
    for (i=0;i<param.n_units;i++) {
      spin_lock(&units[i]->unit_lock);
    }

    ret = emulate_order(instrs, instr_len, units, param.n_units);
  
    /* free them up for use */
    for(i=0;i<param.n_units;i++) {
      spin_unlock(&units[i]->unit_lock);
    }

dealloc_units:
    for (i=0;i<param.n_units;i++) {
        if (units[i])
            keml_emul_unit_put(units[i]);
    }

    return ret;
}

static long keml_ioctl(struct file *filp, unsigned int code, unsigned long arg)
{
    long ret = 0;

    switch (code) {
        case IOCTL_NEW_EMUL_UNIT:
            ret = keml_ioctl_emul_unit_create((void *)arg); 
            break;  
        case IOCTL_DESTROY_UNIT:
            ret = keml_ioctl_emul_unit_destroy((int)arg);
            break;
        case IOCTL_ISSUE_ORDER:
            ret = keml_ioctl_issue_order((void *)arg);
            break;
        default:
            return -EINVAL;
    }

    return ret;
}

/* --- MMAP --- */

static void keml_vm_open(struct vm_area_struct *vma)
{
    struct keml_emul_unit *unit = vma->vm_private_data;

    if (unit) {
        //pr_info("vm_open on %d", unit->id);
        keml_emul_unit_get(unit);
    }
}

static void keml_vm_close(struct vm_area_struct *vma)
{
    struct keml_emul_unit *unit = vma->vm_private_data;
    
    if (unit) {
        //pr_info("vm_close on %d", unit->id);
        keml_emul_unit_put(unit);
    }
}

static const struct vm_operations_struct keml_vm_ops = {
    .open = keml_vm_open,
    .close = keml_vm_close,
};

static int keml_mmap(struct file *filp, struct vm_area_struct *vma)
{
    unsigned int ret;
    struct keml_emul_unit *unit = NULL;
    unsigned long vmasize = vma->vm_end - vma->vm_start;

    //pr_info("in mmap for %d\n", (int)vma->vm_pgoff);
    if (vma->vm_flags & VM_WRITE)
        return -EPERM;

    ret = get_emul_unit(&unit, vma->vm_pgoff, vmasize);
    if (ret)
        return ret;

    //pr_info("mapping unit %d\n", unit->id);

    /* set up the vma to disallow writability */
    vma->vm_flags &= ~VM_MAYWRITE;

    /* allow open/close to reference it */
    vma->vm_private_data = unit;

    /* use our routines */
    vma->vm_ops = &keml_vm_ops;

    vma->vm_page_prot = pgprot_writecombine(vma->vm_page_prot);

    /* finally give access */
    ret = remap_pfn_range(vma,
                          vma->vm_start,
                          virt_to_phys((void *)unit->kernel_addr) >> PAGE_SHIFT,
                          vmasize,
                          vma->vm_page_prot);

    if (ret != 0) {
        //pr_err("failed to remap pfn range\n");
        goto errput;
    }

    return ret;

errput:
    keml_emul_unit_put(unit);
    return ret;
}

/* --- BOILERPLATE --- */
static int keml_open(struct inode *inode, struct file *filp)
{
    //pr_info("keml opened\n");
    return 0;
}

static const struct file_operations keml_fops = {
    .owner = THIS_MODULE,
    .open = keml_open,
    .mmap = keml_mmap,
    .unlocked_ioctl = keml_ioctl,
};

static int __init keml_init(void)
{
    int error = 0;

    error = register_chrdev(MAJORNUM, "keml", &keml_fops);
    if (error) {
        //pr_err("failed to register chrdev\n");
        return error;
    }

    //pr_info("keml initialized as chrdev\n");

    emul_unit_cache = kmem_cache_create("keml_emul_unit",
                                        sizeof(struct keml_emul_unit),
                                        __alignof__(struct keml_emul_unit),
                                        0,
                                        NULL);

    if (!emul_unit_cache) {
        //pr_err("failed to create kmem cache\n");
        return -1;
    }

    spin_lock_init(&keml_device.mem_lock);
    spin_lock_init(&keml_device.unit_idr_lock);
    idr_init(&keml_device.unit_idr);

    return 0;
}

static void __exit keml_cleanup(void)
{
    unregister_chrdev(MAJORNUM, "keml");
}

module_init(keml_init);
module_exit(keml_cleanup);

MODULE_LICENSE("GPL");
