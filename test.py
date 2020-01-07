from miasm.jitter.csts                  import PAGE_READ, PAGE_WRITE
from miasm.core.utils                   import pck8, pck16, pck64
from miasm.os_dep.linux_stdlib          import *
from symbolic_implementations           import *
from secdse                             import *

INPUT_BUFFER_PTR= 0x100000

def jitter_setup(jitter, start_address, input_buf, buffer_size):
  # TODO: CUSTOMIZE HERE
  jitter.vm.add_memory_page(INPUT_BUFFER_PTR, PAGE_READ, input_buf, 'Input Buffer')
  jitter.cpu.RDI = INPUT_BUFFER_PTR
  jitter.cpu.RSI = buffer_size
  # End conditions
  jitter.add_breakpoint(RET_ADDR, ret)
  jitter.push_uint64_t(RET_ADDR)
  # Get run ready
  jitter.init_run(start_address)
  print(jitter.vm)

def dse_setup(dse, input_buf):
  # TODO: CUSTOMIZE HERE
  dse.input_buffer_ptr = INPUT_BUFFER_PTR
  # Symbolize the entire range
  dse.todos = [todo(input_buf, interval([(INPUT_BUFFER_PTR, INPUT_BUFFER_PTR+len(input_buf)-1)]))]

def main():
  run(jitter_setup, dse_setup)

if __name__ == '__main__':
  main()
