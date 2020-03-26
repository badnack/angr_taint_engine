import copy
import logging
import random
from threading import Event

import angr
import claripy
from angr.exploration_techniques import ExplorationTechnique

from defines import *

log = logging.getLogger("TaintTracking")
log.setLevel("DEBUG")


def get_sym_val(name, bits):
    var = claripy.BVS(name=name, size=bits)
    return var


def is_tainted(var, state=None, taint_buf=TAINT_BUF):
    """
    Check whether the variable is tainted or not.

    :param state:
    :param var:
    :param taint_buf:
    :return:
    """

    def is_untaint_constraint_present(v, untaint_var_strs):
        for u in untaint_var_strs:
            # get argument name
            if v.args[0] in u:
                # variable is untainted
                return True
        # no untaint found, var is tainted!
        return False

    # Nothing is tainted
    if taint_buf not in str(var):
        return False

    #
    # something is tainted
    #
    if not state or not state.globals[FLAGS][AU]:
        return True

    # check whether it exists at least one still tainted variable in the expression
    untaint_var_strs = state.globals[UNTAINT_DATA][UNTAINTED_VARS]
    if not untaint_var_strs:
        # if nothing was ever untainted, the expression is tainted
        return True

    # get the tainted leafs of the given expression
    taint_leafs = list(set([l for l in var.recursive_leaf_asts if taint_buf in str(l)]))

    # for each of them, check if a untaint constraint is present
    if any([l for l in taint_leafs if not is_untaint_constraint_present(l, untaint_var_strs)]):
        return True

    return False


def add_taint_glob_dep(master, slave, state):
    """
    Add a taint dependency: if master gets untainted, slave should be untainted
    :param master: master expression
    :param slave: slave expression
    :param state: state
    :return:
    """

    if not is_tainted(master):
        return
    leafs = list(set([l for l in master.recursive_leaf_asts if is_tainted(l)]))
    key = tuple(map(str, leafs))
    if key not in state.globals[GLOB_TAINT_DEP_KEY]:
        state.globals[GLOB_TAINT_DEP_KEY][key] = []
    state.globals[GLOB_TAINT_DEP_KEY][key].append(slave)


def remove_taint(dst, state):
    # given an expression to untaint, we untaint every single tainted variable in it.
    # E.g., given (taint_x + taint_y) to untaint, both variables gets untainted as
    # they cannot assume no longer arbitrary values down this path.
    if state.globals[FLAGS][AU]:
        return

    state = state
    leafs = list(set([l for l in dst.recursive_leaf_asts if is_tainted(l)]))

    # then we use the collected untainted variables
    # and check whether we should untaint some other variables
    state.globals[UNTAINT_DATA][UNTAINTED_VARS] += map(str, leafs)
    deps = dict(state.globals[GLOB_TAINT_DEP_KEY])
    i = 0
    while i < len(deps.keys()):
        master, salve = deps.items()[i]

        # if not already untainted, let's consider it
        if master not in state.globals[UNTAINT_DATA][SEEN_MASTERS]:
            untainted_vars = set(state.globals[UNTAINT_DATA][UNTAINTED_VARS])
            set_master = set(master)

            # we can not untaint it
            if set_master.intersection(untainted_vars) == set_master:
                state.globals[UNTAINT_DATA][SEEN_MASTERS].append(master)
                for entry in deps[master]:
                    remove_taint(entry, state)
                # restart!
                i = 0
                continue
        i += 1


def is_or_points_to_tainted_data(x, state):
    return is_tainted(x, state) or \
           is_tainted(state.memory.load(x), state)


def new_tainted_value(name, bits):
    """
    return a fresh tainted value, with the given name
    :param name: variable name
    :param bits: number of bits
    :return:
    """
    taint_name = TAINT_BUF + '_' + name + '_'
    val = get_sym_val(name=taint_name, bits=bits)
    return val


def new_tainted_page(name=''):
    """
    return a fresh tainted page, with the given name
    :param name: variable name
    :return:
    """
    taint_name = TAINT_BUF + '_' + name + '_'
    # TODO: Check the architecture page size
    val = get_sym_val(name=taint_name, bits=PAGE_SIZE)
    return val


def apply_taint(state, addr, taint_id='', bits=PAGE_SIZE, var=None):
    """
    Apply taint to a memory location

    :param state: angr state
    :param addr:  memory address
    :param taint_id: taint id
    :param bits: number of bits
    :param var: symbolic variable to store
    :return:
    """
    if var is None:
        var = new_tainted_value(taint_id, bits)
    # if not (isinstance(addr, int) or addr.concrete) and state.globals[SC]:
    #     # FIXME: Nilo, fix this
    #     raise RuntimeError("Nilo fix me!")
    #     #addr = self._get_target_concretization(self, addr, state)
    state.memory.store(addr, var, inspect=False, disable_actions=True)
    state.globals[TAINT_APPLIED] = True


class TaintTracker(ExplorationTechnique):
    """
    Taint-tracking based on DSE.
    """

    def __init__(self,
                 interfunction_level=0,
                 smart_call=True,
                 precise_argument_check=True,
                 follow_unsat=True,
                 function_whitelist=[],
                 function_blacklist=[],
                 not_follow_any_calls=False,
                 concretization_strategy=None,
                 taint_returns_from_unfollowed_calls=False,
                 taint_arguments_from_unfollowed_calls=False,
                 allow_untaint=True,
                 use_smart_concretization=True,
                 taint_deref_values=True,
                 n_iter_loop=10):
        """
        Initialization function
        :param interfunction_level: interfunction level
        :param smart_call: if True a call is followed only if at least one of its parameters is tainted
        :param precise_argument_check: if set it uses the angr's calling convention analysis to retrieve function arguments.
                            Or else, it checks the basic block making the call to retrieve them
        :param follow_unsat: if true unsat successors are also considered during path exploration. In this case
                            the collected constraints up to that point will be dropped.
        :param function_whitelist: addresses of functions to always follow
        :param function_blacklist: Addresses of functions to always ignore
        :param not_follow_any_calls: if set no call is followed
        :param concretization_strategy: concretization strategy callback
        :param taint_returns_from_unfollowed_calls: if set return values from unfollowed calls are tainted if any
                            function parameter is tainted
        :param taint_arguments_from_unfollowed_calls: if set function's arguments from unfollowed calls are tainted
                            if any of them is already tainted
        :param allow_untaint: allow to untaint variables.
        :param use_smart_concretization: use smart conrectization strategy. This options should be set unless you have
                            something smarter in mind :)
        :param taint_deref_values: whether to taint values returned from dereferencing tainted
                            data.  NOTE: The original AST will not be preserved!
                            (you probably want this on, unless you know what you're doing)
        :param n_iter_loop: maximum number of iteration of a loop
        """
        super(TaintTracker, self).__init__()
        self._interfunction_level = interfunction_level
        self._smart_call = smart_call
        self._precise_argument_check = precise_argument_check
        self._follow_unsat = follow_unsat
        self._function_whitelist = function_whitelist
        self._function_blacklist = function_blacklist
        self._not_follow_any_calls = not_follow_any_calls
        self._concretization_strategy = concretization_strategy if concretization_strategy else \
            TaintTracker.default_concretization_strategy
        self._concretizations = {}
        self._taint_returns_from_unfollowed_calls = taint_returns_from_unfollowed_calls
        self._taint_arguments_from_unfollowed_calls = taint_arguments_from_unfollowed_calls
        self._allow_untaint = allow_untaint
        self._use_smart_concretization = use_smart_concretization
        self._taint_deref_values = taint_deref_values
        self._callbacks = []
        self._function_summaries = []
        self._deref = (None, None)
        self._N = n_iter_loop
        self._stop = Event()

    #
    # Static methods
    #

    @staticmethod
    def default_concretization_strategy(state, cnt):
        extra_constraints = state.inspect.added_constraints
        if not extra_constraints:
            extra_constraints = tuple()
        concs = state.solver.eval_upto(cnt, 50,  extra_constraints=extra_constraints)
        return random.choice(concs)

    #
    # Public methods
    #

    def add_function_summary(self, where, what):
        """
        Add a function summary for a given address or symbol

        :param where: memory address or symbol to hook
        :param what: function callback
        :return:
        """
        self._function_summaries.append((where, what))

    def add_callback(self, what, why, when):
        """
        Add a callback. You'll want to do this to implement your taint policy.
        Some examples include:
        - Hook on a memory read, and taint all values read from that address
        - Hook on a basic block, and check whether taint reached a sink
        - Hook on a basic block exit, and check for tainted return values from a function

        You actually apply the taint using TaintTracking.apply_taint()

        You can check the taint using TaintTracking.is_tainted()

        See the SimInspect documentation for the possible breakpoint types and the "when" field.

        You should do this before running the technique!

        :param what: The function to call.  Your function should be be of the form "def some_callback(state): "
        :param why: When should your callback occur.  See SimInspect for these (e.g. 'mem_read', 'exit', ...)
        :param when: When to callback, relative to the reason.  Possible values are angr.BP_BEFORE, angr.BP_AFTER
        :return: None
        """
        self._callbacks.append((what, why, when,))

    #
    # Private methods
    #

    def _set_deref_bounds(self, ast_node):
        """
        Check an ast node and if  contains a dereferenced address, it sets
        its bounds
        :param ast_node: ast node
        :return: None
        """
        lb = self._deref[0]
        ub = self._deref[1]

        if hasattr(ast_node, 'op') and ast_node.op == 'Extract' \
                and is_tainted(ast_node.args[2]):
            m = min(ast_node.args[0], ast_node.args[1])
            lb = m if lb is None or m < lb else lb
            m = max(ast_node.args[0], ast_node.args[1])
            ub = m if ub is None or m > ub else ub
            self._deref = (lb, ub)
        elif hasattr(ast_node, 'args'):
            for a in ast_node.args:
                self._set_deref_bounds(a)
        elif is_tainted(ast_node):
            self._deref = (0, 0)

    def _addr_concrete_after(self, state):
        """
        Hook for address concretization
        :param state: Program state
        """
        addr_expr = state.inspect.address_concretization_expr
        state.inspect.address_concretization_result = [self._get_target_concretization(addr_expr, state)]

        # a tainted buffer's location is used as address
        if is_tainted(addr_expr, state=state):
            self._set_deref_bounds(addr_expr)

            if state.inspect.address_concretization_action == 'load':
                # new fresh var
                name = "cnt_pt_by(" + TAINT_BUF + '[' + str(self._deref[0]) + ', ' + str(
                    self._deref[1]) + ']' + ")"
                bits = state.inspect.mem_read_length * 8
                if type(bits) not in (int, ) and hasattr(bits, 'symbolic'):
                    bits = state.solver.max_int(bits)
                var = get_sym_val(name, bits)
                state.memory.store(state.inspect.address_concretization_result[0], var, inspect=False)

    def _get_target_concretization(self, var, state):
        """
        Concretization must be done carefully in order to perform
        a precise taint analysis. We concretize according the following
        strategy:
        * every symbolic leaf of an ast node is concretized to unique value, according on its name.

        In this way we obtain the following advantages:
        a = get_pts();
        b = a

        c = a + 2
        d = b + 1 + 1

        d = get_pts()

        conc(a) = conc(b)
        conc(c) = conc(d)
        conc(d) != any other concretizations

        :param var: ast node
        :param state: current state
        :return: concretization value
        """

        def get_key_cnt(x):
            return str(x)

        # check if uncontrained
        se = state.solver
        leafs = [l for l in var.recursive_leaf_asts]

        if not leafs:
            conc = self._concretization_strategy(state, var)
            if not se.solution(var, conc):
                conc = se.eval(var)
            key_cnt = get_key_cnt(var)
            self._concretizations[key_cnt] = conc
            return conc

        for cnt in leafs:
            key_cnt = get_key_cnt(cnt)
            # concretize all unconstrained children
            if cnt.symbolic:
                # first check whether the value is already constrained
                if key_cnt in self._concretizations.keys():
                    conc = self._concretizations[key_cnt]
                    if state.solver.solution(cnt, conc):
                        # FIXME: adding contraints to the state might be useless, check me
                        state.add_constraints(cnt == conc)
                        continue

                conc = self._concretization_strategy(state, cnt)
                self._concretizations[key_cnt] = conc
                state.add_constraints(cnt == conc)

        val = state.solver.eval(var)
        return val

    def _fake_ret(self, state):
        """
        Transform the state such that it has "returned" from a function call it won't actually take.
        :param: state: state to transform
        :return: angr path
        """
        args, ret = self._get_calling_convention(state)

        # Set the jumpkind
        state.history.jumpkind = "Ijk_FakeRet"

        # Set the PC to whatever was in the link register
        state.regs.pc = state.callstack.current_return_target

        # Clean up angr's internal callstack details so everything's consistent.
        state.callstack.ret()

        # check whether any of the function parameters are tainted
        # If so, we taint also the return value
        to_taint = False
        if state.globals[TAINT_APPLIED] and \
                any([is_or_points_to_tainted_data(a.get_value(state), state) for a in args]):
            to_taint = True

        # We didn't follow this call,
        # so we return unconstrained data.
        # In other words, should the return value be bogus, or bogus AND tainted?
        name = 'ret_'
        bits = self.project.arch.bits
        if state.globals[FLAGS][TR] and to_taint:
            var = new_tainted_value(name, bits=bits)
        else:
            var = get_sym_val(name=name, bits=bits)

        ret.set_value(state, var)

        # taint function arguments, e.g., we passed a pointer to a function
        # this too should be tainted, it might have been written to!
        if to_taint and state.globals[FLAGS][TA]:
            for o, a in enumerate(args):
                if not is_or_points_to_tainted_data(a, state):
                    name = '_f_arg_' + str(o)
                    bits = PAGE_SIZE
                    if hasattr(a, 'reg_name'):
                        bits = self.project.arch.bits

                    val = new_tainted_value(name, bits)
                    a.set_value(state, val)
        return state

    def _should_follow_back_jump(self, state):
        """
        Check if a back jump should be followed.

        :param state:  current state
        :return:  true if should back jump, false otherwise
        """

        bj = (state.addr, state.history.addr)
        if bj not in state.globals[BACK_JUMPS]:
            state.globals[BACK_JUMPS][bj] = 1
        if state.globals[BACK_JUMPS][bj] > self._N:
            # we do not want to follow the same back jump infinite times
            return False
        else:
            state.globals[BACK_JUMPS][bj] += 1
        return True

    def _drop_constraints(self, state):
        log.debug("Dropping constraints from unsat state at %#08x" % state.addr)
        state.solver._stored_solver.constraints = []
        state.solver.reload_solver()

    def _get_calling_convention_precise(self, state):
        """
        Returns the set of possible arguments a function takes, and the location of the return value

        :param state: angr state
        :return: (a list of Sim*Args, a SimArg for the return value)
        """
        try:
            f = self.project.kb.functions[state.addr]
        except:
            log.warning("Your code just called a "
                               "function not in the CFG at %#08x.  Falling back to "
                               "a naive approach..." % state.addr)
            return None

        try:
            cca = self.project.analyses.CallingConvention(f)
            if cca.cc:
                return cca.cc
        except Exception as e:
            log.exception("get_function_argumens_precise failed: %s" % str(e))
        return None

    def _get_calling_convention_fast(self, state):
        """
        Returns a set of possible arguments a function takes, by looking at the basic block
        leading to the function

        :param state: angr state
        :return: a list of SimArgs
        """

        # get the previous bb (the one leading to the call)
        arg_regs = ordered_argument_registers(state.arch)
        ret_reg = return_register(state.arch)

        #
        # Argument registers
        #

        try:
            caller_bl = self.project.factory.block(state.history.addr)
        except:
            raise
        puts = [s for s in caller_bl.vex.statements if s.tag == 'Ist_Put']

        expected = 0
        index = 0
        sim_args = []

        # Looks for function arguments in the block containing the call
        # falling the cc order so to filter false positives
        while True:
            if index >= len(puts):
                break
            if expected >= len(arg_regs):
                break
            p = puts[index]
            if p.offset == arg_regs[expected].vex_offset:
                # got the expected argument, check if tainted
                reg_name = arg_regs[expected].name
                reg_size = arg_regs[expected].size
                var = angr.calling_conventions.SimRegArg(reg_name, reg_size)
                sim_args.append(var)
                expected += 1
                index = 0
                continue
            index += 1

        #
        # Return register
        #

        ret = angr.calling_conventions.SimRegArg(ret_reg.name, ret_reg.size)

        return sim_args, ret

    def _get_calling_convention(self, state):
        """
        Get teh args and return value for a given state.
        We  assume this state is currently at the start of a function that has been called.

        :param state:
        :return:
        """
        args = []
        ret = None
        if state.globals[FLAGS][PAC]:
            cc = self._get_calling_convention_precise(state)
            if cc:
                args = cc.args
                ret = cc.return_val

        # if we don't have args at this point it's either because th flag precise_argument_check is unset
        # or the above function failed
        if not args:
            args, ret = self._get_calling_convention_fast(state)
        return args, ret

    def _should_follow_call(self, state):
        """
        Checks if a call should be followed or not: if any of its parameters is tainted
        and the current depth of transitive closure allows it yes, otherwise no.

        :param state: The current state, that would take a call
        :return: True if call should be followed, false otherwise
        """

        if state.globals[FLAGS][NFC]:
            log.debug("Calls are disabled")
            return False

        if state.addr in self._function_whitelist:
            log.debug("Function %#08x is whitelisted, following" % state.addr)
            return True

        # check if call falls within bound binary
        if state.addr > self.project.loader.max_addr or state.addr < self.project.loader.min_addr:
            log.debug("Function %#08x is outside the mapped memory, not following" % state.addr)
            return False

        # if the function is summarized by angr, we follow it
        if self.project.is_hooked(state.addr):
            log.debug("Function %#08x is a SimProcedure, following" % state.addr)
            return True

        # NOTE: EDG: Do we want this before the simprocs?
        if state.addr in self._function_blacklist:
            log.debug("Function %#08x is blacklisted, not following" % state.addr)
            return False

        # Check if we hit our inter-function limit
        if state.globals[CURRENT_IFL] <= 0:
            log.debug("Function %#08x is outside the inter-function level, not following" % state.addr)
            return False

        # The rest is about smart calls, so if we don't use those
        # we're done now.
        if not self._smart_call:
            log.debug("Will follow call to %#08x. (smart calls are disabled)" % state.addr)
            return True

        #
        # smart call: check whether any of the parameters is tainted
        #

        # If we never applied any taint to this state, then obviously we shouldn't go there
        if not state.globals[TAINT_APPLIED]:
            log.debug("Not following call to %#08x, no taint is applied" % state.addr)
            return False

        sim_args, _ = self._get_calling_convention(state)

        if any([is_or_points_to_tainted_data(sim_arg.get_value(state), state) for sim_arg in sim_args]):
                log.debug("Argument containts taint, following call to %#08x" % state.addr)
                return True
        log.debug("Not following call to %#08x, no tainted data present" % state.addr)
        return False

    #
    # Exploration Technique methods
    #

    def stop(self):
        """
        Stop the analysis after the next step.
        You could do this, for example, to implement a timeout using a threading.Timer

        """
        self._stop.set()

    def setup(self, simgr):

        if len(simgr.active) == 0:
            raise ValueError("You can only use the TaintTracker when there's something in the active stash!")

        if self._precise_argument_check:
            # Make sure we have a cached VariableRecovery
            try:
                # TODO: This isn't super great
                # NR says: fix this ugly stuff at some point
                has_cfg = False
                for st in simgr.active:
                    # As CFG construction might be expensive, we try first to get the functions
                    # we need without it. Then, if we can't find them, we build a CFG and try one more time.
                    if st.addr not in self.project.kb.functions and not has_cfg:
                        self.project.analyses.CFGFast()
                        has_cfg = True

                    starting_f = self.project.kb.functions[st.addr]
                    self.project.analyses.VariableRecoveryFast(starting_f)
            except:
                log.exception("Couldn't find Function %#08x analysis will switch back to a faster yet less precise"
                              "mode", st.addr)
                self._precise_argument_check = False

        # Register breakpoints
        for s in simgr.active:
            if self._use_smart_concretization:
                if self._taint_deref_values:
                    s.inspect.b(
                        'address_concretization',
                        angr.BP_AFTER,
                        action=self._addr_concrete_after)
            for what, why, when in self._callbacks:
                s.inspect.b(why, when, action=what)

            for where, what in self._function_summaries:
                self.project.hook_symbol(where, what, replace=True)

            # Set up some in-state variables
            s.globals[GLOB_TAINT_DEP_KEY] = {}
            s.globals[UNTAINT_DATA] = {UNTAINTED_VARS: [], SEEN_MASTERS: []}
            s.globals[CURRENT_IFL] = self._interfunction_level
            s.globals[TAINT_APPLIED] = False
            s.globals[BACK_JUMPS] = {}

            # flags
            s.globals[FLAGS] = {}
            s.globals[FLAGS][IL] = self._interfunction_level
            s.globals[FLAGS][SC] = self._smart_call
            s.globals[FLAGS][PAC] = self._precise_argument_check
            s.globals[FLAGS][FU] = self._follow_unsat
            s.globals[FLAGS][NFC] = self._not_follow_any_calls
            s.globals[FLAGS][TR] = self._taint_returns_from_unfollowed_calls
            s.globals[FLAGS][TA] = self._taint_arguments_from_unfollowed_calls
            s.globals[FLAGS][AU] = self._allow_untaint
            s.globals[FLAGS][SCC] = self._use_smart_concretization

    def step(self, simgr, *kargs, **kwargs):

        for s in simgr.active:
            s.globals[BACK_JUMPS] = copy.deepcopy(s.globals[BACK_JUMPS])
            s.globals[GLOB_TAINT_DEP_KEY] = copy.deepcopy(s.globals[GLOB_TAINT_DEP_KEY])
            s.globals[UNTAINT_DATA] = copy.deepcopy(s.globals[UNTAINT_DATA])

        # Step the simmanager
        simgr = simgr.step(**kwargs)

        # First, if there are unsat paths, and we are going to force those to execute
        # drop their constraints, and move them into active.
        if self._follow_unsat and len(simgr.unsat) > 0:
            map(self._drop_constraints, simgr.unsat)
            simgr.move(from_stash='unsat', to_stash='active')

        # Look at the sat states
        for s in simgr.active:
            log.debug("Checking state at %#08x" % s.addr)

            # Did we just call something? Check the IFL
            if s.history.jumpkind == "Ijk_Call":
                if self._should_follow_call(s):
                    # follow the call
                    log.debug("Following function call to %#08x" % s.addr)
                    s.globals[CURRENT_IFL] -= 1
                else:
                    log.debug("Not following function call to %#08x" % s.addr)
                    # Don't follow the call, make it into a "fake ret"
                    self._fake_ret(s)

            # Did we return from a function? If so, increment the IFL
            if s.history.jumpkind == 'Ijk_Ret':
                s.globals[CURRENT_IFL] += 1

            # we have a back jump
            if s.history.jumpkind == 'Ijk_Boring' and \
                    s.addr <= s.history.addr and \
                    not self._should_follow_back_jump(s):
                log.debug("Breaking loop at %#08x" % s.addr)
                simgr.active.remove(s)
                simgr.deadended.append(s)

            # the successor leads out of the function, we do not want to follow it
            if s.addr == BOGUS_RETURN:
                log.debug("Returned out of the original function!")
                simgr.active.remove(s)
                simgr.deadended.append(s)
        log.debug("Done checking states.")
        return simgr

    def complete(self, simgr):
        return len(simgr.active) == 0 or self._stop.is_set()
