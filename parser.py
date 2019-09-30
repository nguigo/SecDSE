from miasm.jitter.csts                  import PAGE_READ, PAGE_WRITE
from miasm.core.utils                   import pck8, pck16, pck64
from miasm.os_dep.linux_stdlib          import *
from symbolic_implementations           import *
from secdse                             import *

INPUT_BUFFER_PTR= 0x1000000

ctype_table = '\x00\00'*0x80 + \
'\x02\x00\x02\x00\x02\x00\x02\x00' \
'\x02\x00\x02\x00\x02\x00\x02\x00' \
'\x02\x00\x03\x20\x02\x20\x02\x20' \
'\x02\x20\x02\x20\x02\x00\x02\x00' \
'\x02\x00\x02\x00\x02\x00\x02\x00' \
'\x02\x00\x02\x00\x02\x00\x02\x00' \
'\x02\x00\x02\x00\x02\x00\x02\x00' \
'\x02\x00\x02\x00\x02\x00\x02\x00' \
'\x01\x60\x04\xc0\x04\xc0\x04\xc0' \
'\x04\xc0\x04\xc0\x04\xc0\x04\xc0' \
'\x04\xc0\x04\xc0\x04\xc0\x04\xc0' \
'\x04\xc0\x04\xc0\x04\xc0\x04\xc0' \
'\x08\xd8\x08\xd8\x08\xd8\x08\xd8' \
'\x08\xd8\x08\xd8\x08\xd8\x08\xd8' \
'\x08\xd8\x08\xd8\x04\xc0\x04\xc0' \
'\x04\xc0\x04\xc0\x04\xc0\x04\xc0' \
'\x04\xc0\x08\xd5\x08\xd5\x08\xd5' \
'\x08\xd5\x08\xd5\x08\xd5\x08\xc5' \
'\x08\xc5\x08\xc5\x08\xc5\x08\xc5' \
'\x08\xc5\x08\xc5\x08\xc5\x08\xc5' \
'\x08\xc5\x08\xc5\x08\xc5\x08\xc5' \
'\x08\xc5\x08\xc5\x08\xc5\x08\xc5' \
'\x08\xc5\x08\xc5\x08\xc5\x04\xc0' \
'\x04\xc0\x04\xc0\x04\xc0\x04\xc0' \
'\x04\xc0\x08\xd6\x08\xd6\x08\xd6' \
'\x08\xd6\x08\xd6\x08\xd6\x08\xc6' \
'\x08\xc6\x08\xc6\x08\xc6\x08\xc6' \
'\x08\xc6\x08\xc6\x08\xc6\x08\xc6' \
'\x08\xc6\x08\xc6\x08\xc6\x08\xc6' \
'\x08\xc6\x08\xc6\x08\xc6\x08\xc6' \
'\x08\xc6\x08\xc6\x08\xc6\x04\xc0' \
'\x04\xc0\x04\xc0\x04\xc0\x02\x00' + \
'\x00\00'*0x80

def breakin(jitter):
  import pdb;pdb.set_trace()

def jitter_setup(jitter, start_address, file_buffer, buffer_size):
  jitter.vm.add_memory_page(INPUT_BUFFER_PTR, PAGE_READ, file_buffer, 'Input Buffer')
  jitter.cpu.RDI = INPUT_BUFFER_PTR
  jitter.cpu.RSI = buffer_size
  # Ouput params
  jitter.vm.add_memory_page(0x20000, PAGE_READ|PAGE_WRITE, '\xCD'*0x1000, 'Output Buffer')
  jitter.cpu.RDX = 0x20000
  # End conditions
  jitter.add_breakpoint(RET_ADDR, ret)
  jitter.push_uint64_t(RET_ADDR)
  # Table for is_digit() to work (via __ctype_b_loc)
  jitter.vm.add_memory_page(0x40000, PAGE_READ, pck64(0x50000), 'ctype_table_ptr')
  jitter.vm.add_memory_page(0x50000-0x100, PAGE_READ, ctype_table, 'ctype_table')
  # Get run ready
  jitter.init_run(start_address)
  print jitter.vm
  return

def dse_setup(dse, input_buf):
  # TODO: CUSTOMIZE HERE
  dse.input_buffer_ptr = INPUT_BUFFER_PTR
  # Symbolize the entire range
  dse.todos = [todo(input_buf, interval([(INPUT_BUFFER_PTR, INPUT_BUFFER_PTR+len(input_buf)-1)]))]

def main():
  run(jitter_setup, dse_setup)

if __name__ == '__main__':
  main()
