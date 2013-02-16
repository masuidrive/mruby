#ifdef ENABLE_DEBUGGER
# define HOOK_MRB_READ_IREP(mrb, ret, bin) ((mrb)->hook_mrb_read_irep ? (mrb)->hook_mrb_read_irep((mrb), (ret), (bin)) : NULL)
# define HOOK_MRB_VM_FETCH_CODE(mrb, irep, pc) ((mrb)->hook_vm_fetch_code ? (mrb)->hook_vm_fetch_code((mrb),(irep), (pc)) : NULL)
#else
# define HOOK_MRB_READ_IREP(mrb, ret, bin)
# define HOOK_MRB_VM_FETCH_CODE(mrb, irep, pc)
#endif
