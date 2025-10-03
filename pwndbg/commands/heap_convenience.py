import gdb
from pwndbg.gdblib.heap_base import resolve_heap_base

class HeapFunc(gdb.Function):
    #  $heap([offset]) -> returns heap base (+ optional offset).

    def __init__(self):
        super().__init__("heap")  # exposes `$heap`

    def invoke(self, *args):
        base = resolve_heap_base()
        if base is None:

            # return 0 and a warning so expressions won't explode but the user still gets a helpful message
            gdb.write("[pwndbg] Unable to resolve heap base.\n")
            return gdb.Value(0)

        # Optional single numeric argument
        offset = 0
        if len(args) > 1: #if more than 1 argument
            raise gdb.GdbError("$heap takes at most one argument: $heap([offset])")
        if len(args) == 1:
            try:
                # args may be gdb.Value; int() handles hex constants too
                offset = int(args[0])
            except Exception as e:
                raise gdb.GdbError(f"Invalid offset for $heap: {e}")

        return gdb.Value(base + offset)

# Register on import
HeapFunc()