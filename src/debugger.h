#ifdef ENABLE_DEBUGGER
# define HOOK_MRB_VM_FETCH_CODE(mrb, irep, pc, regs) ((mrb)->hook_vm_fetch_code ? (mrb)->hook_vm_fetch_code((mrb), (irep), (pc), (regs)) : NULL)
#else
# define HOOK_MRB_VM_FETCH_CODE(mrb, irep, pc, regs)
#endif
