#
# Defined constants
#

import archinfo

# Taint/Untaint
TAINT_BUF = "taint_buf"
PAGE_SIZE = 4096  # 1 page
BOGUS_RETURN = 0x41414141
GLOB_TAINT_DEP_KEY = 'taint_deps'
UNTAINT_DATA = 'untainted_data'
UNTAINTED_VARS = 'untainted_vars'

# Taint dependency
SEEN_MASTERS = 'seen_masters'
CURRENT_IFL = 'current_ifl'
TAINT_APPLIED = 'taint_applied'

# Loops
BACK_JUMPS = 'back_jumps'

# Flags
FLAGS = 'flags'
IL = 'interfunction_level'
SC = 'smart_call'
PAC = 'precise_argument_check'
FU = 'follow_unsat'
NFC = 'not_follow_any_calls'
TR = 'taint_returns_from_unfollowed_calls'
TA = 'taint_arguments_from_unfollowed_call'
AU = 'allow_untaint'
SCC = 'use_smart_concretization'


# Arch spec info
def ordered_argument_registers(arch):
    return list(filter(lambda x: x.argument is True, arch.register_list))

# HACK: FIXME: This works, but this is an accident
def return_register(arch):
    return ordered_argument_registers(arch)[0]
