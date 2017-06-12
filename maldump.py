import pydbg
import pydbg.defines
import pydasm
import win32process
import sys
import struct
import os

INVALID_HANDLE_VALUE = -1
CURRENT_PROCESS_HANDLE_VALUE = -1

process_handle = INVALID_HANDLE_VALUE
output_filename = "output.ex"

def read_param(dbg, param_index):
	param_addr = dbg.context.Esp + (4 * (param_index + 1))
	packed_param = dbg.read_process_memory(param_addr, 4)
	return struct.unpack("L", packed_param)[0]

def set_bp_on_ret(dbg, addr, handler):
	sizeof_code_to_read = 0x1000
	asm = dbg.read_process_memory(addr, sizeof_code_to_read)
	i = 0
	while i < sizeof_code_to_read:
		inst = pydasm.get_instruction(asm[i:], pydasm.MODE_32)
		inststr = pydasm.get_instruction_string(inst, pydasm.FORMAT_INTEL, 0)
		if inststr.startswith("jmp"):
			return
		elif inststr.startswith("ret"):
			dbg.bp_set(addr + i, description="", handler=handler)
			return
		i += inst.length
	return

def handler_create_process_w_on_ret(dbg):
	global process_handle
	process_handle = hex(struct.unpack("L", dbg.read_process_memory(read_param(dbg, 9), 4))[0])
	return pydbg.defines.DBG_CONTINUE

def handler_create_process_w(dbg):
	creation_flags = read_param(dbg, 5)
	if creation_flags & win32process.CREATE_SUSPENDED != win32process.CREATE_SUSPENDED:
		print "Not RunPE. Exiting"
		dbg.terminate_process()
	set_bp_on_ret(dbg, dbg.context.Eip, handler_create_process_w_on_ret)
	return pydbg.defines.DBG_CONTINUE

def handler_nt_write_virtual_memory(dbg):
	handle = hex(read_param(dbg, 0))
	src_buf = read_param(dbg, 2)
	bytes_to_write = read_param(dbg, 3)
	global process_handle
	if handle == process_handle and bytes_to_write > 4:
		buf = dbg.read_process_memory(src_buf, bytes_to_write)
		with open(output_filename, "ab+") as f:
			f.write(buf)
			f.close()
	return pydbg.defines.DBG_CONTINUE

def handler_load_dll(dbg):
	dll = dbg.get_system_dll(-1)
	if dll.name.lower() == "kernelbase.dll":
		create_process_w = dbg.func_resolve("kernelbase", "CreateProcessW")
		if create_process_w != 0:
			dbg.bp_set(create_process_w, description="", handler=handler_create_process_w)
	elif dll.name.lower() == "kernel32.dll":
		create_process_w = dbg.func_resolve("kernel32", "CreateProcessW")
		if create_process_w != 0:
			dbg.bp_set(create_process_w, description="", handler=handler_create_process_w)
	return pydbg.defines.DBG_CONTINUE

if len(sys.argv) < 3:
	print("Usage: python runpe_dump.py C:\\malwares\\crypted_malware.exe output_malware.exe")
	exit()

if os.path.isfile(sys.argv[1]) == False:
	print("Input file is not existing")
	exit()

dbg = pydbg.pydbg()
dbg.load(sys.argv[1])

output_filename = sys.argv[2]

try:
	os.remove(output_filename)
except Exception:
	pass

nt_write_virtualMemory = dbg.func_resolve("ntdll", "NtWriteVirtualMemory")
dbg.bp_set(nt_write_virtualMemory, description="", handler=handler_nt_write_virtual_memory)
dbg.set_callback(pydbg.defines.LOAD_DLL_DEBUG_EVENT, handler_load_dll)

dbg.run()

try:
	dbg.terminate_process()
except Exception:
	pass