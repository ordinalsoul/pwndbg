import gdb

def _int_or_none(val):
    try:
        return int(val)
    except Exception:
        return None

def resolve_heap_base():
    """
    Returns an integer heap base, or None if it cannot be determined.
    Tries pwndbg's heap helpers first; falls back to $base("heap") if present.
    """
    # 1st path: native pwndbg heap resolver (preferred)
    try:

        from pwndbg import gdblib
        # Try common resolvers (ptmalloc):

        if hasattr(gdblib, "heap") and hasattr(gdblib.heap, "heap_base"):
            base = gdblib.heap.heap_base()
            base_int = _int_or_none(base)
            if base_int is not None:
                return base_int
        # Fallback:
        if hasattr(gdblib, "memory") and hasattr(gdblib.memory, "heap"):
            # returns a pwndbg.memory.Page or similar with .start
            heap_region = gdblib.memory.heap()
            if heap_region and hasattr(heap_region, "start"):
                base_int = _int_or_none(heap_region.start)
                if base_int is not None:
                    return base_int
    except Exception:
        # Non-fatal: continue
        pass

    # 2nd path: try $base("heap")
    try:
        val = gdb.parse_and_eval('$base("heap")')
        return int(val)
    except Exception:
        return None