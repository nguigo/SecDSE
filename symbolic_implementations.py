import logging
import struct
from miasm.os_dep.linux_stdlib              import linobjs
from miasm.expression.expression            import ExprId, ExprInt, ExprMem, ExprOp, ExprCond, ExprAssign, get_expr_ids
from miasm.expression.expression_helper     import CondConstraintNotZero
from miasm.expression.simplifications       import expr_simp_explicit
from miasm.core.interval                    import interval

log = logging.getLogger('secdse')

MAX_ALLOC_SIZE = 0x100000
MIN_ALLOC_SIZE = 0x32

def track_callsite(func):
  def wrapper(dse):
    # Store ret addr in DSE
    dse.callsite = dse.eval_expr(ExprMem(ExprInt(dse.jitter.cpu.RSP, 64), 64))
    func(dse)
    dse.callsite = None
  return wrapper

# Skipping useless calls
def skip(jitter):
  ret_ad, _ = jitter.func_args_systemv([])
  return jitter.func_ret_systemv(ret_ad)

def skip_symb(dse):
  # Get the return address from stack
  ret = dse.eval_expr(ExprMem(ExprInt(dse.jitter.cpu.RSP, 64), 64))
  dse.update_state({dse.ir_arch.IRDst: ret,
                    ExprId('RSP', 64): ExprInt(dse.jitter.cpu.RSP+0x8, 64)})
  return True

def xxx_malloc(jitter):
  ret_ad, args = jitter.func_args_systemv(["msize"])
  addr = 0x0
  if args.msize < MAX_ALLOC_SIZE:
    addr = linobjs.heap.alloc(jitter, args.msize)
  else:
    log.warning('UNSAFELY LARGE ALLOCATION REQUEST: ' + str(args.msize))
  return jitter.func_ret_systemv(ret_ad, addr)

# TODO: Check for z3 solutions for size request of 0
def xxx_malloc_symb(dse):
  # Get the return address from stack
  ret = dse.eval_expr(ExprMem(ExprInt(dse.jitter.cpu.RSP, 64), 64))
  # Use the concrete address for the symbolic range
  buf = linobjs.heap.addr
  size = dse.eval_expr(ExprId('RDI', 64))
  log.debug('xxx_malloc_symb({})'.format(size))
  concrete_size = int(size) if size.is_int() else dse.jitter.cpu.RDI
  writes = {}
  if concrete_size < MAX_ALLOC_SIZE:
    # Compute the symbolic allocation range
    symbolic_range_start = ExprInt(buf, 64)
    symbolic_range_end = ExprOp('+', ExprOp('+', symbolic_range_start, size), ExprInt(-0x1, 64))
    # Update the DSE's valid ranges
    dse.valid_ranges.append((symbolic_range_start , symbolic_range_end))
    # Mark the memory as uninitialized
    for i in range(concrete_size):
      #dse.uninitialized_mems = sdahdjahd
      writes[expr_simp_explicit(ExprMem(ExprOp('+', symbolic_range_start, ExprInt(i, size.size)), 8))] = ExprId('UNINIT_{:08X}'.format(buf+i), 8)
  else:
    symbolic_range_start = ExprInt(0x0, 64)
  # Fix stack and PC
  writes.update({ExprId('RAX', 64): symbolic_range_start,
                 dse.ir_arch.IRDst: ret,
                 ExprId('RSP', 64): ExprInt(dse.jitter.cpu.RSP+0x8, 64)}
               )
  dse.update_state(writes)
  return True

def xxx_calloc(jitter):
  ret_ad, args = jitter.func_args_systemv(['nmemb', 'size'])
  total = (args.nmemb*args.size) & 0xFFFFFFFFFFFFFFFF
  addr = linobjs.heap.alloc(jitter, total)
  # calloc zeroes the memory
  jitter.vm.set_mem(addr, '\x00'*total)
  return jitter.func_ret_systemv(ret_ad, addr)

# TODO: Flag for int overflow?
def xxx_calloc_symb(dse):
  # Get the return address from stack
  ret = dse.eval_expr(ExprMem(ExprInt(dse.jitter.cpu.RSP, 64), 64))
  # Use the concrete address for the symbolic range
  buf = linobjs.heap.addr
  nmemb = dse.eval_expr(ExprId('RDI', 64))
  conc_nmemb = int(nmemb) if nmemb.is_int() else dse.jitter.cpu.RDI
  size = dse.eval_expr(ExprId('RSI', 64))
  conc_size = int(size) if size.is_int() else dse.jitter.cpu.RSI
  total = (conc_nmemb*conc_size) & 0xFFFFFFFFFFFFFFFF
  log.debug('xxx_calloc_symb({}, {})'.format(nmemb, size))
  concrete_size = size if size.is_int() else dse.jitter.cpu.RDX
  if concrete_size < MAX_ALLOC_SIZE:
    # Compute the symbolic allocation range
    symbolic_range_start = ExprInt(buf, 64)
    symbolic_range_end = ExprOp('+', ExprOp('+', symbolic_range_start, size), ExprInt(-0x1, 64))
    # Update the DSE's valid ranges
    dse.valid_ranges.append((symbolic_range_start , symbolic_range_end))
  else:
    symbolic_range_start = ExprInt(0x0, 64)
  # Fix stack and PC
  dse.update_state({ExprId('RAX', 64): symbolic_range_start,
                    dse.ir_arch.IRDst: ret,
                    ExprId('RSP', 64): ExprInt(dse.jitter.cpu.RSP+0x8, 64)})
  return True

# TODO: Check ptr's possible values for invalid ones
def xxx_free_symb(dse):
  # Get the ptr to free
  ptr = int(dse.eval_expr(ExprInt(dse.jitter.cpu.RDI, 64)))
  size = linobjs.heap.get_size(dse.jitter.vm, int(ptr))
  # Get the return address from stack
  ret = dse.eval_expr(ExprMem(ExprInt(dse.jitter.cpu.RSP, 64), 64))
  # Remove  addresses from valid_ranges
  to_remove = [r for r in dse.valid_ranges if r[0]==dse.eval_expr(ExprId('RDI', 64))][0]
  log.debug('xxx_free_symb: [{}, {}]'.format(str(to_remove[0]), str(to_remove[1])))
  dse.valid_ranges.remove(to_remove)
  dse.update_state({dse.ir_arch.IRDst: ret,
                    ExprId('RSP', 64): ExprInt(dse.jitter.cpu.RSP+0x8, 64)})
  # Fix stack and PC
  return True

# Just sync it and continue
@track_callsite
def xxx_memcpy_symb(dse):
  # Just use the concrete return address
  ret = dse.eval_expr(ExprMem(ExprInt(dse.jitter.cpu.RSP, 64), 64))
  # Do the copy byte per byte (usually not the actual implementation but that'll do)
  dst = dse.eval_expr(ExprId('RDI', 64))
  src = dse.eval_expr(ExprId('RSI', 64))
  n = dse.eval_expr(ExprId('RDX', 64))
  log.debug('xxx_memcpy_symb(dst={:s}, src={:s}, n={:s})'.format(dst, src, n))
  writes = {}
  size = n if n.is_int() else dse.jitter.cpu.RDX
  # Sanity check: with such a large size, this is likely uninteded program behavior
  #TODO: ensure an AV occurs, signal it and kill the run
  if size < MAX_ALLOC_SIZE:
    for i in range(size):
      writes[expr_simp_explicit(ExprMem(ExprOp('+', dst, ExprInt(i, n.size)), 8))] = dse.eval_expr(ExprMem(ExprOp('+', src, ExprInt(i, n.size)), 8))
  #else:
  # Evaluate min and max reachable memory references against valid ranges
  # with additional constraint that size cannot be 0, otherwise there is no mem access at all
  dse.symb.solve_for_memory_access(ExprMem(src, 8), \
                                   'READ', \
                                   set([CondConstraintNotZero(n)]))
  dse.symb.solve_for_memory_access(ExprMem(ExprOp('+', ExprOp('+', src, n), ExprInt(-0x1, 64)), 8), \
                                   'READ', \
                                   set([CondConstraintNotZero(n)]))
  dse.symb.solve_for_memory_access(ExprMem(dst, 8), \
                                   'WRITE', \
                                   set([CondConstraintNotZero(n)]))
  dse.symb.solve_for_memory_access(ExprMem(ExprOp('+', ExprOp('+', dst, n), ExprInt(-0x1, 64)), 8), \
                                   'WRITE' , \
                                   set([CondConstraintNotZero(n)]))
  #import pdb; pdb.set_trace()
  # Fix stack and PC
  writes.update({ExprId('RAX', 64): dst,
                 dse.ir_arch.IRDst: ret,
                 ExprId('RSP', 64): ExprInt(dse.jitter.cpu.RSP+0x8, 64)}
               )
  dse.update_state(writes)
  # Clear ret addr in DSE
  dse.callsite = None
  return True

def xxx___ctype_b_loc(jitter):
  ret_ad, _ = jitter.func_args_systemv([])
  return jitter.func_ret_systemv(ret_ad, 0x40000)

def xxx___ctype_b_loc_symb(dse):
  # Just use the concrete return address
  ret = dse.eval_expr(ExprMem(ExprInt(dse.jitter.cpu.RSP, 64), 64))
  dse.update_state({ExprId('RAX', 64): ExprInt(0x40000, 64),
                    dse.ir_arch.IRDst: ret,
                    ExprId('RSP', 64): ExprInt(dse.jitter.cpu.RSP+0x8, 64)})
  return True

# Pow(double, double) XMM implementation
def xxx_pow(jitter):
  ret_ad, _ = jitter.func_args_systemv([])
  x = struct.unpack('d', struct.pack('L', jitter.cpu.XMM0))[0]
  y = struct.unpack('d', struct.pack('L', jitter.cpu.XMM1))[0]
  jitter.cpu.XMM0 = struct.unpack('L', struct.pack('d', x*y))[0]
  jitter.func_ret_systemv(ret_ad)

# Pow(double, double) XMM implementation
def xxx_pow_symb(dse):
  # Just use the concrete return address
  ret = dse.eval_expr(ExprMem(ExprInt(dse.jitter.cpu.RSP, 64), 64))
  # Get the args from XMM regs
  x = dse.eval_expr(ExprId('XMM0', 64))
  y = dse.eval_expr(ExprId('XMM1', 64))
  # This is wrong but that'll do
  dse.update_state({ExprId('RAX', 64): ExprOp('**', x, y),
                    dse.ir_arch.IRDst: ret,
                    ExprId('RSP', 64): ExprInt(dse.jitter.cpu.RSP+0x8, 64)})
  return True

def xxx_printf_symb(dse):
  return skip_symb(dse)

# Skip the logging
def xxx_sprintf(jitter):
  return skip(jitter)

def xxx_sprintf_symb(dse):
  return skip_symb(dse)

 # Ignore for now
def xxx_puts_symb(dse):
  return skip_symb(dse)
