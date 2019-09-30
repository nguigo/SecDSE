import z3
import os
import logging
from collections                        import namedtuple
from itertools                          import combinations
from miasm.jitter.jitcore_python        import JitCore_Python
from miasm.core.interval                import interval
from miasm.analysis.dse                 import ESETrackModif, DSEPathConstraint as DSEPC, DriftException
from miasm.expression.expression        import ExprId, ExprInt, ExprMem, ExprLoc, ExprOp, ExprCond, get_expr_ids, get_expr_mem
from miasm.expression.expression_helper import possible_values
from miasm.analysis.expression_range    import expr_range
from miasm.analysis.modularintervals    import ModularIntervals
from miasm.analysis.sandbox             import Sandbox_Linux_x86_64
from miasm.ir.translators               import Translator
from future.utils                       import viewitems
from symbolic_implementations           import *

hnd = logging.StreamHandler()
hnd.setFormatter(logging.Formatter("[%(levelname)s]: %(message)s"))
log = logging.getLogger('secdse')
log.addHandler(hnd)

# Consts
RET_ADDR = 0xCAFED00D8BADF00D

# Simple structs
todo = namedtuple('todo', ['buf', 'to_symbolize'])

class crash(object):

  def __init__(self, pc, address, t,  buf, callsite=None):
    self.pc = pc
    self.address = address
    self.type = t
    self.buf = buf
    self.callsite = callsite

  def __eq__(self, other):
    return self.__hash__()==other.__hash__()

  def __ne__(self, other):
    return not self.__eq__(other)

  # For set inclusion, only care about unique crashes
  def __hash__(self):
    return pow(hash(self.pc)^hash(self.callsite)^hash(self.type),2)

  def __str__(self):
    return 'ID={:X} | RIP= {:08X} {} |  buf= {} | {}'.format( self.__hash__(), \
                                                    self.pc, \
                                                    '(ret= '+hex(self.callsite)[2:]+')' if self.callsite else '', \
                                                     ':'.join('{:02X}'.format(ord(x)) for x in self.buf), \
                                                     self.type + '['+str(self.address)+']' if self.address else 'UNDEFINED'\
                                                   )

class FnReturnException(Exception):
    """Raised when the function returns normally"""

    def __init__(self, info):
        super(FnReturnException, self).__init__()
        self.info = info

class MemSquareException(Exception):
    """Raised when the symbengine accesses a symbolized memory address"""

    def __init__(self, info, ptr):
        super(MemSquareException, self).__init__()
        self.info = info
        self.ptr = ptr

# Memory tracking symbolic execution engine
class ESETrackMemory(ESETrackModif):

  @property
  def dse_memory_range(self):
    return self._dse_memory_range

  @dse_memory_range.setter
  def dse_memory_range(self, value):
    self._dse_memory_range = value
    # Observer pattern to update the symbols
    self._symbolized_mem_ids = self.recompute_symbolized_mem_ids()
    return self._dse_memory_range

  @property
  def symbolized_mem_ids(self):
    return self._symbolized_mem_ids

  def recompute_symbolized_mem_ids(self):
    smi = list()
    for mem_range in self.dse_memory_range:
      for byte_addr in range(mem_range[0], mem_range[1]+1):
        smi.append(self.dse.memory_to_expr(byte_addr))
    return set(smi)

  def derive_crashbuf(self, model):
    crashbuf= ''
    for i, expr in enumerate([self.dse_memory_to_expr(b) for r in self.dse_memory_range for b in range(r[0], r[1]+1)]):
      symbval = model[self.dse.z3_trans.from_expr(expr)]
      crashbuf += self.dse.current.buf[i] if symbval is None else chr(symbval.as_long())
    return crashbuf

  def get_values_from_model(self, model):
    values = {}
    for symbval in model:
       values[ExprId(str(symbval), 8)] = ExprInt(model[symbval].as_long(), 8)
    return values

  def solve_for_memory_access(self, expr_mem, access_type, additional_constraints=set()):
    # Check that input has effect on memory referenced
    if get_expr_ids(expr_mem.ptr) & self.symbolized_mem_ids:
      for possibility in possible_values(expr_mem.ptr):
        address_expr = possibility.value
        access_len = expr_mem.size/8
        # 5 sec timeout
        #self.dse.cur_solver.set('timeout', 5000)
        # Save solver state
        self.dse.cur_solver.push()
        # Add constraints from the expr itself
        for cons in possibility.constraints.union(additional_constraints):
          eaff = cons.to_constraint()
          #print '\tADDING CONSTRAINT: ' + str(eaff)
          self.dse.cur_solver.add(self.dse.z3_trans.from_expr(eaff))
        # Add memory constraints
        for mem_range in self.dse.valid_ranges:
          # Add range constraint
          rc = z3.Not(z3.And(z3.UGE(self.dse.z3_trans.from_expr(address_expr), self.dse.z3_trans.from_expr(mem_range[0])),
                             z3.ULE(self.dse.z3_trans.from_expr(address_expr), self.dse.z3_trans.from_expr(mem_range[1]-ExprInt(access_len-1, 64)))
                            )
                     )
          self.dse.cur_solver.add(rc)
        #print solver
        #import pdb; pdb.set_trace()
        if self.dse.cur_solver.check()==z3.sat:
          model = self.dse.cur_solver.model()
          #import pdb; pdb.set_trace()
          log.debug('SYMB 0x{:08X}: {:s} -> {}AV[{:s}]  '.format(self.dse.jitter.pc, \
                                                          str(model), access_type, \
                                                          str(self.dse.symb.eval_expr(address_expr, eval_cache={})))
                  )
          # Evaluate the buffer that would cause the crash
          crashbuf = self.derive_crashbuf(model)
          # Evaluate the AV adress
          values = self.get_values_from_model(model)
          self.dse.crashes.append(crash( self.dse.jitter.pc, \
                                      self.dse.symb.eval_expr(address_expr, eval_cache=values), \
                                      access_type, \
                                      crashbuf, \
                                      int(self.dse.callsite)
                                    )
                              )
        # Reset the solver
        self.dse.cur_solver.pop()
    return

  # Limitation: Currently only checks for uninitialized memory access in concrete engine
  def mem_read(self, expr_mem):
    #print expr_mem
    if not self.dse._state_check_in_progress:
      # Check for ReadAV
      self.solve_for_memory_access(expr_mem, 'READAV')
    val = super(ESETrackMemory, self).mem_read(expr_mem)
    # Check for uninitialized memory access
    if not self.dse._state_check_in_progress:
      # TODO: Something with better perf
      for uninit in  [i for i in get_expr_ids(val) if i.name.startswith('UNINIT')]:
        log.debug('LIVE 0x{:08X}: UNINIT on "{:s}"  '.format(self.dse.jitter.pc, uninit))
        self.dse.crashes.append(crash( self.dse.jitter.pc, \
                                    uninit, \
                                    'UNINIT', \
                                    self.dse.current.buf, \
                                    int(self.dse.callsite)
                                  )
                            )
    return val

  def mem_write(self, expr_mem, data):
    self.solve_for_memory_access(expr_mem, 'WRITEAV')
    # Call Symbolic mem_write (avoid side effects on vm)
    return super(ESETrackMemory, self).mem_write(expr_mem, data)

class SecDSE(DSEPC):

  SYMB_ENGINE= ESETrackMemory

  def __init__(self, machine, produce_solution=DSEPC.PRODUCE_SOLUTION_CODE_COV,
               known_solutions=None, **kwargs):
    ESETrackMemory.dse = self
    self.crashes = list()
    self.visited_bbls = set()
    self._state_check_in_progress = False
    super(SecDSE, self).__init__(machine,
                                 produce_solution,
                                 known_solutions,
                                 **kwargs)

  def refresh_valid_jitter_ranges(self):
    self.valid_ranges = [(ExprInt(m, 64), ExprInt(m+i['size']-1, 64)) for m, i in self.jitter.vm.get_all_memory().iteritems()]

  def get_todo(self):
    self.current = self.todos.pop(0) # FIFO for output clarity
    return self.current

  def get_virtids_addresses(self, expr):
    addresses = set()
    mems = get_expr_mem(expr)
    for mem in mems:
      addresses |= set([{self.symb.dse_memory_to_expr(b):b for r in self.symb.dse_memory_range for b in range(r[0], r[1]+1)}[exprid] for exprid in get_expr_ids(mem.ptr)])
    return addresses

  def _check_state(self):
    self._state_check_in_progress = True
    super(SecDSE, self)._check_state()
    self._state_check_in_progress = False

  def handle(self, cur_addr):
    cur_addr = self.ir_arch.loc_db.canonize_to_exprloc(cur_addr)
    self.visited_bbls.add(cur_addr)
    symb_pc = self.eval_expr(self.ir_arch.IRDst)
    possibilities = possible_values(symb_pc)
    cur_path_constraint = set() # path_constraint for the concrete path
    if len(possibilities) == 1:
      dst = next(iter(possibilities)).value
      dst = self.ir_arch.loc_db.canonize_to_exprloc(dst)
      assert dst == cur_addr
    else:
      for possibility in possibilities:
        target_addr = self.ir_arch.loc_db.canonize_to_exprloc(possibility.value)
        path_constraint = set() # Set of ExprAssign for the possible path

        # Get constraint associated to the possible path
        memory_to_add = ModularIntervals(symb_pc.size)
        for cons in possibility.constraints:
          eaff = cons.to_constraint()
          # eaff.get_r(mem_read=True) is not enough
          # ExprAssign consider a Memory access in dst as a write
          mem = eaff.dst.get_r(mem_read=True)
          mem.update(eaff.src.get_r(mem_read=True))
          for expr in mem:
            if expr.is_mem():
              # Sanity check that we don't have a read square
              virt_addresses = self.get_virtids_addresses(expr)
              if virt_addresses:
                raise MemSquareException("ExprMem ptr is symbolized: %s" % str(expr), virt_addresses)
                #print 'ExprMem ptr is symbolized: {} ({})'.format(str(expr), str([hex(va) for va in virt_addresses]))
              addr_range = expr_range(expr.ptr)
              # At upper bounds, add the size of the memory access
              # if addr (- [a, b], then @size[addr] reachables
              # values are in @8[a, b + size[
              for start, stop in addr_range:
                stop += expr.size // 8 - 1
                full_range = ModularIntervals( symb_pc.size, [(start, stop)])
                memory_to_add.update(full_range)
          path_constraint.add(eaff)

        if memory_to_add.length > self.MAX_MEMORY_INJECT:
          # TODO re-croncretize the constraint or z3-try
          raise RuntimeError("Not implemented: too long memory area")

        # Inject memory
        for start, stop in memory_to_add:
          for address in range(start, stop + 1):
            expr_mem = ExprMem(ExprInt(address, self.ir_arch.pc.size), 8)
            value = self.eval_expr(expr_mem)
            if not value.is_int():
              raise TypeError("Rely on a symbolic memory case, address 0x%x" % address)
            path_constraint.add(ExprAssign(expr_mem, value))

        if target_addr == cur_addr:
          # Add path constraint
          cur_path_constraint = path_constraint

        elif self.produce_solution(target_addr):
          # Looking for a new solution
          self.cur_solver.push()
          for cons in path_constraint:
            trans = self.z3_trans.from_expr(cons)
            trans = z3.simplify(trans)
            self.cur_solver.add(trans)

          result = self.cur_solver.check()
          if result == z3.sat:
            model = self.cur_solver.model()
            self.handle_solution(model, target_addr)
          self.cur_solver.pop()

    self.handle_correct_destination(cur_addr, cur_path_constraint)

  def done(self):
    #print 'DONE @{:08X}'.format(self.jitter.pc)
    if self.cur_solver.check()==z3.sat:
      # If we symbolicly determined that we can reach a new block
      for bbl, model in self.new_solutions.items():
        if type(bbl)==ExprLoc:
          bbl_addr = self.loc_db.get_location_offset(bbl.loc_key) # Get the bbl offset the DSE hit
          log.warning('Found solution for new bbl at 0x%x' % (bbl_addr))
        else:
          log.warning('Found solution for new bbl')
        new_blob = b''
        # Capture the values of the symbolized bytes
        for i, c in enumerate(self.current.buf):
          try:
            val = model.eval(self.z3_trans.from_expr(self.memory_to_expr(self.input_buffer_ptr+i))).as_long()
          except:
            # Fallback to current values
            val = self.current.buf[i]
          new_blob += bytearray([val])
        self.todos.append(todo(bytes(new_blob), self.current.to_symbolize)) # Put the new blob in the todo list
    return False # End current concrete execution

  def gen_new_bufs(self, indexes):
    combs = combinations(list(range(256)), len(indexes))
    newbufs = list()
    for c in combs:
      newbuf = ''
      j=0
      # enumerate has the ability to offset. neat.
      for i, val in enumerate(self.current.buf, self.input_buffer_ptr):
        if i in indexes:
          newbuf+=chr(c[j])
          j+=1
        else:
          newbuf+=val
      newbufs.append(newbuf)
    #import pdb; pdb.set_trace()
    return newbufs

def ret(jitter):
  raise FnReturnException('Clean Function Return')

def run(jitter_setup, dse_setup):
  JitCore_Python.SymbExecClass = ESETrackMemory
  # Create sandbox
  parser = Sandbox_Linux_x86_64.parser(description='PE sandboxer')
  parser.add_argument('filename', help='PE Filename')
  parser.add_argument('-if', '--infile', nargs='?', help='Input buffer from file')
  parser.add_argument('-is', '--insize', nargs='?', default='32', help='Input buffer size')
  parser.add_argument('-fs', '--fullsymb', action='store_true', default=False, help='Forbid fallback to concretizing')
  parser.add_argument('-v', '--verbose', nargs='?', default='2', help='Verbosity level (0-4)')
  parser.add_argument('-df', '--dump', action='store_true', default=False, help='Dump crashing data blobs to files')
  options = parser.parse_args()
  # First thing, set log level
  log.setLevel(50-int(options.verbose)*10)
  options.jitter = 'llvm'
  options.mimic_env= True
  #options.singlestep = True
  # Input params
  if options.infile:
    with open(options.infile, 'rb') as f:
      input_buf= f.read()
  else:
    input_buf = os.urandom(int(options.insize, 0))
  # Instantiate
  sb = Sandbox_Linux_x86_64(options.filename, options, globals())
  jitter_setup(sb.jitter, int(options.address, 16), input_buf, len(input_buf))
  # Create and attach DSE
  dse = SecDSE(sb.machine)
  dse.add_lib_handler(sb.libs, globals())
  dse.attach(sb.jitter)
  # Record valid memory ranges
  dse.refresh_valid_jitter_ranges()
  dse.update_state_from_concrete()
  # Configure DSE
  dse_setup(dse, input_buf)
  # Take snapshot
  snapshot = dse.take_snapshot()
  nb_run=0
  while dse.todos:
    nb_run+=1
    current = dse.get_todo()
    # Restore concrete & symb contexts
    dse.restore_snapshot(snapshot, keep_known_solutions=True)
    dse.symbolize_memory(current.to_symbolize)
    # Update the buffer in concrete engine
    sb.jitter.vm.set_mem(dse.input_buffer_ptr, current.buf)
    log.error('-'*80 + ' RUN #%i | %i BBL visited | %i todos | %i crashes' % (nb_run, len(dse.visited_bbls), \
                                                                          len(dse.todos), len(dse.crashes) \
                                                                         )
             )
    log.error('SYMBOLIZED %s (%i/%i bytes)' % (str(current.to_symbolize), current.to_symbolize.length, len(input_buf)))
    try:
      sb.jitter.continue_run()
    except DriftException as e:
      print hex(dse.jitter.pc) + ' ' + str(e)
      break
    # TODO: Rename to SymbToConcException
    except MemSquareException as e:
      # TODO: We can just concretize the byte and continue from here
      print hex(dse.jitter.pc) + ' ' + str(e.info)
      dse.done()
      new_to_symbolize = current.to_symbolize
      for mem in e.ptr:
        # Concretize that byte and retry
        new_to_symbolize -= interval([(mem, mem)])
      # Compute all possible concrete bytes
      if options.fullsymb:
        for buf in dse.gen_new_bufs(e.ptr):
          dse.todos.append(todo(buf, current.to_symbolize)) # Put it in the todo list
      else:
        print 'CONCRETIZING: ' + hex(mem)
        dse.todos.insert(0, todo(current.buf, new_to_symbolize))
      # Continue the current run?
      #import pdb; pdb.set_trace()
      continue
    except RuntimeError as e:
      log.warning('LIVE 0x{:08X}: AV with "{:s}"  '.format(dse.jitter.pc, e.message))
      dse.crashes.append(crash(dse.jitter.pc, None, 'UNDEFINED', current.buf))
      dse.done()
      continue
    except FnReturnException as e:
      log.info('FUNCTION RET')
      dse.done()
      continue
    except KeyboardInterrupt:
      break
    except Exception as e:
      dse.done()
      print hex(dse.jitter.pc) + ' ' + str(type(e)) + ': ' + str(e)
      import pdb; pdb.set_trace()
      continue
  log.error('-'*80 + ' RESULTS | %i BBL visited | %i todos | %i unique crashes' % (len(dse.visited_bbls), \
                                                                                   len(dse.todos), len(set(dse.crashes)) \
                                                                           )
           )
  for i, record in enumerate(set(dse.crashes)):
    if options.dump:
      with open('crash_{:X}'.format(record.__hash__()), 'wb') as f:
        f.write(record.buf)
    log.error(str(record))
  log.error('-'*80)
  import pdb; pdb.set_trace()
