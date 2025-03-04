import ida_nalt
import idaapi
from idaapi import *
from idc import *

def find_ncases(ea, reg):

	limit = ea - 0x500
	already_jumped = 0
	while ea > limit:
		if get_first_cref_to(ea) != idaapi.BADADDR and already_jumped == 0:
			ea = get_first_cref_to(ea)
			# Reset limit to new ea
			limit = ea - 0x500
			# Only one cref is supported for now,
			#99% of binaries should be fine anyway.
			already_jumped = 1

		if print_insn_mnem(ea) in ["cmplwi", "cmpldi"] and get_operand_value(ea, 1) == reg:
			condition_reg = print_operand(ea, 0)
			temp_ea = ea + 4
			while temp_ea < limit+0x500:
				branch = print_insn_mnem(temp_ea)[0:3] # 3 characters (handle bgtlr etc.)
				if branch in ["ble", "bgt", "bge", "blt"] and print_operand(temp_ea, 0) == condition_reg:
					if branch in ["ble", "bgt"]:
						ncases = get_operand_value(ea, 2) + 1
					else:
						ncases = get_operand_value(ea, 2)
					set_cmt(ea, "switch {:d} cases".format(ncases), 0)
					return ncases

				temp_ea += 4
				
		ea -= 4
	
	return 0


def jump_table_search():

	address = 0
	old_si = ida_nalt.switch_info_t()
	while address < idaapi.BADADDR:
		
		if idaapi.IDA_SDK_VERSION > 760:
			binpat = idaapi.compiled_binpat_vec_t()
			idaapi.parse_binpat_str(binpat, address, "4E 80 04 20", 0x10)
			try:
				address, _ = idaapi.bin_search(address, idaapi.BADADDR, binpat, SEARCH_DOWN)
			except:
				address, _ = idaapi.bin_search3(address, idaapi.BADADDR, binpat, SEARCH_DOWN)
		else:
			address = idaapi.find_binary(address, idaapi.BADADDR, "4E 80 04 20", 0x10, SEARCH_DOWN)

		if address < idaapi.BADADDR and idaapi.get_switch_info(old_si, address) != None:#old_si.startea != ida_idaapi.BADADDR:
			bctr_ea = address
			if old_si.regnum == -1:
				print("Unable to resolve jump table at: 0x{:08X}".format(bctr_ea))
				print("Regnum = {:d}".format(old_si.regnum))
				address += 4
				continue
			ncases = find_ncases(bctr_ea, old_si.regnum)
			if ncases == 0:
				print("Ivalid jump table found at: 0x{:08X}".format(bctr_ea))
				print("ncases = 0")
				address += 4
				continue

			# Setup valid switch info and create table.
			si = ida_nalt.switch_info_t()
			si.set_jtable_element_size(4)
			si.set_jtable_size(ncases)
			si.ncases = ncases
			si.startea = bctr_ea
			si.jumps = bctr_ea + 4
			si.elbase = bctr_ea + 4
			si.set_shift(0)
			si.regnum = old_si.regnum
			si.lowcase = 0 # 0 is ok for most tables. To handle this, much more code is needed.
			si.flags = idaapi.SWI_SIGNED | idaapi.SWI_ELBASE | idaapi.SWI_J32
			si.flags2 = 0
			del_items(si.jumps, 4, ncases * 4)
			idaapi.set_switch_info(bctr_ea, si)
			idaapi.create_switch_table(bctr_ea, si)
			
			# Ok... This is stupid, but it's required.
			# When jump table with invalid values is in function,
			# IDA asks auto analyzer to redefine function after new jump table
			# boundaries are set. For unknown reason this break jump table again.
			# But if we recreate jump table info again after auto analyze, IDA is happy.
			if get_func_flags(bctr_ea) != -1:
				#fnc_start = get_func_attr(bctr_ea, idc.FUNCATTR_START)
				#fnc_end = find_func_end(fnc_start)
				#print("start = 0x{:08X} , end = 0x{:08X}".format(fnc_start, fnc_end))
				#auto_mark_range(fnc_start, fnc_end, idaapi.AU_USED);
				auto_wait()
				idaapi.set_switch_info(bctr_ea, si)
				idaapi.create_switch_table(bctr_ea, si)


		address += 4


class fix_ppcjt_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL
	comment = "Fix PowerPC jump tables."
	help = "Press Alt + Shift + 5 to Fix PPCJT"
	wanted_name = "Fix PPCJT"
	wanted_hotkey = "Alt-Shift-5"

	def init(self):
		if idaapi.ph.id == idaapi.PLFM_PPC:
			idaapi.msg("Fix PPCJT loaded.\n")
			return idaapi.PLUGIN_KEEP

		return idaapi.PLUGIN_SKIP
	
	def run(self, arg):
		jump_table_search()
	
	def term(self):
		pass

def PLUGIN_ENTRY():
	return fix_ppcjt_t()
