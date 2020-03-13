import signal
from angr_taint.taint_tracker.taint_tracking import *
from dfs import *
import datetime

l = logging.getLogger("TaintLauncher")
l.setLevel(logging.DEBUG)


class TimeOutException(Exception):
    def __init__(self, message):
        super(TimeOutException, self).__init__(message)


class TaintLauncher:
    """
    Provides an easy interface to run a taint tracking analysis
    """

    def __init__(self, binary_path,
                 log_path='/tmp/angr_taint.out',
                 **angr_opts):
        """
        Init method: prepare the angr project.

        :param binary_path: binary path
        :param angr_opts: angr options
        """

        # timeout stuff
        self._force_exit_after = -1
        self._timer = -1

        if not angr_opts:
            angr_opts = {'auto_load_libs': False}

        self._p = angr.Project(binary_path, **angr_opts)
        self._log = open(log_path, 'w')
        self._tt = None
        self._simgr = None

    def run(self,
            start_addr=None,
            check_function=lambda x: None,
            sym_bss=True,
            use_dfs=True,
            **kwargs):
        """
        Prepare the analysis instance and run the analysis

        :param start_addr: analysis starting address
        :param check_function: callback function that is called for every visited basic block
        :param sym_bss: make bss symbolic
        :param use_dfs: use a depth first seach approach
        :param kwargs
        """

        if not start_addr:
            start_addr = self._p.entry

        # set up the taint tracking exploration technique
        start_state = self._p.factory.call_state(start_addr)
        if sym_bss:
            self._unconstrain_bss(start_state)

        self._tt = TaintTracker(**kwargs)
        self._tt.add_callback(check_function, 'irsb', angr.BP_BEFORE)
        self._simgr = self._p.factory.simgr(start_state)
        self._simgr.use_technique(self._tt)

        if use_dfs:
            self._simgr.use_technique(DFS())

        try:
            self._simgr.run()
        except TimeOutException:
            l.warning("Hard timeout triggered!")
            self.stop()

    def stop(self):
        l.info("Stopping the analysis")
        self._tt.stop()

    def _handler(self, signum, frame):
        """
        Timeout handler

        :param signum: signal number
        :param frame:  frame
        :return:
        """

        log.info("Timeout triggered, %s left...." % str(self._force_exit_after))
        self.stop()
        self._force_exit_after -= 1
        self.set_timeout(self._timer, self._force_exit_after)
        if self._force_exit_after <= 0:
            # time to stop this non-sense!
            raise TimeOutException("Hard timeout triggered")

    def set_timeout(self, timer, n_tries=0):
        # setup a consistent initial state
        signal.signal(signal.SIGALRM, self._handler)
        signal.alarm(timer)
        self._force_exit_after = n_tries
        self._timer = timer

    def _unconstrain_bss(self, state):
        bss = [s for s in self._p.loader.main_object.sections if s.name == '.bss']
        if not bss:
            return

        bss = bss[0]
        min_addr = bss.min_addr
        max_addr = bss.max_addr

        for a in range(min_addr, max_addr + 1):
            var = get_sym_val(name="bss_", bits=8)
            state.memory.store(a, var)

    def start_logging(self):
        self._log.write("Starts: \n" + str(datetime.datetime.now().time()) + "=================================\n\n")

    def log(self, msg):
        self._log.write(msg)

    def stop_logging(self):
        self._log.write("Ends: \n" + str(datetime.datetime.now().time()) + "=================================\n\n")
        self._log.close()
