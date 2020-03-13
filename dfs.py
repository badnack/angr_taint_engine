from angr.exploration_techniques import ExplorationTechnique
import random

class DFS(ExplorationTechnique):
    """
    Depth-first search.

    Will only keep one path active at a time, any others will be stashed in the 'deferred' stash.
    When we run out of active paths to step, we take the longest one from deferred and continue.
    """

    def __init__(self, deferred_stash='deferred', num_states=1):
        super(DFS, self).__init__()
        self._random = random.Random()
        self._random.seed(10)
        self.deferred_stash = deferred_stash
        self._num_states = num_states

    def setup(self, simgr):
        if self.deferred_stash not in simgr.stashes:
            simgr.stashes[self.deferred_stash] = []

    def step(self, simgr, stash, **kwargs):
        simgr = simgr.step(stash=stash, **kwargs)
        if len(simgr.stashes[stash]) > self._num_states:
            self._random.shuffle(simgr.stashes[stash])
            simgr.split(from_stash=stash, to_stash=self.deferred_stash, limit=self._num_states)

        if len(simgr.stashes[stash]) == 0:
            if len(simgr.stashes[self.deferred_stash]) == 0:
                return simgr
            simgr.stashes[stash].append(simgr.stashes[self.deferred_stash].pop())

        return simgr
