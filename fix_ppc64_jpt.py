import ida_nalt
import idaapi
import ida_auto
from ida_auto import *
from idaapi import *
from idc import *

DEBUG = 0

def find_ncases(ea, reg):

	limit = ea - 0x500
	already_jumped = 0
	while ea > limit:
		check_ea = get_first_cref_to(ea)
		if DEBUG:
			print("ea   : " + hex(ea))
			print("check: " + hex(check_ea))
		if print_insn_mnem(ea) not in ["cmplwi", "cmpldi"] or get_operand_value(ea, 1) != reg:
			if check_ea != idaapi.BADADDR and check_ea != ea - 4 and already_jumped < 3:
				if get_func_attr(ea, FUNCATTR_START) == get_first_cref_to(ea):
					# Give up if we reached function start..
					print("[Fix PPCJT] Reached function start.")
					break
				ea = get_first_cref_to(ea)
				if DEBUG:
					print(hex(ea))
					print(already_jumped)
				limit = ea - 0x500
				already_jumped += 1
		
		if DEBUG:
			print(print_insn_mnem(ea))
		if print_insn_mnem(ea) in ["cmplwi", "cmpldi"] and get_operand_value(ea, 1) == reg:
			condition_reg = print_operand(ea, 0)
			temp_ea = ea + 4
			while temp_ea < ea+0x500:
				branch = print_insn_mnem(temp_ea)[0:3] # 3 characters (handle bgtlr etc.)
				if DEBUG:
					print("temp_ea   : " + hex(temp_ea))
					print("branch    : " + branch)
				if branch in ["ble", "bgt", "bge", "blt"] and print_operand(temp_ea, 0) == condition_reg:
					default_jump = -1
					if print_operand(temp_ea, 1) != "lr":
						if branch in ["bgt", "bge"]:
							default_jump = get_operand_value(temp_ea, 1)
						else:
							default_jump = temp_ea + 4

					if branch in ["ble", "bgt"]:
						ncases = get_operand_value(ea, 2) + 1
					else:
						ncases = get_operand_value(ea, 2)
					set_cmt(ea, "switch {:d} cases".format(ncases), 0)
					return ncases, default_jump

				temp_ea += 4
				
		ea -= 4
	
	return 0, -1


def create_table(bctr_ea, ncases, default_case, regnum):

	# Setup valid switch info and create table.
	si = ida_nalt.switch_info_t()
	si.set_jtable_element_size(4)
	si.set_jtable_size(ncases)
	si.ncases = ncases
	si.startea = bctr_ea
	si.jumps = bctr_ea + 4
	si.elbase = bctr_ea + 4
	si.set_shift(0)
	si.regnum = regnum
	si.lowcase = 0 # 0 is ok for most tables. To handle this, much more code is needed.
	if default_case != -1:
		si.defjump = default_case
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
		auto_wait()
		idaapi.set_switch_info(bctr_ea, si)
		idaapi.create_switch_table(bctr_ea, si)


def do_all_tables():

	if auto_is_ok() == False:
		print("[Fix PPCJT] Please wait for autoanalyzer to finish and try again.")
		return

	address = 0
	old_si = ida_nalt.switch_info_t()
	while address < idaapi.BADADDR:
		
		# Borrowed from https://github.com/SocraticBliss/ps4_module_loader
		if idaapi.IDA_SDK_VERSION > 760:
			binpat = idaapi.compiled_binpat_vec_t()
			idaapi.parse_binpat_str(binpat, address, "4E 80 04 20", 0x10)
			try:
				address, _ = idaapi.bin_search(address, idaapi.BADADDR, binpat, SEARCH_DOWN)
			except:
				address, _ = idaapi.bin_search3(address, idaapi.BADADDR, binpat, SEARCH_DOWN)
		else:
			address = idaapi.find_binary(address, idaapi.BADADDR, "4E 80 04 20", 0x10, SEARCH_DOWN)

		if address < idaapi.BADADDR and idaapi.get_switch_info(old_si, address) != None:
			bctr_ea = address

			if old_si.regnum == -1:
				print("[Fix PPCJT] Unable to resolve jump table at: 0x{:08X}".format(bctr_ea))
				print("[Fix PPCJT] Regnum = -1")
				address += 4
				continue

			ncases, default_case = find_ncases(bctr_ea, old_si.regnum)
			if ncases == 0:
				print("[Fix PPCJT] Ivalid jump table found at: 0x{:08X}".format(bctr_ea))
				print("[Fix PPCJT] ncases = 0")
				address += 4
				continue

			create_table(bctr_ea, ncases, default_case, old_si.regnum)

		address += 4


def do_single_table():

	if auto_is_ok() == False:
		print("[Fix PPCJT] Please wait for autoanalyzer to finish and try again.")
		return
	
	bctr_ea = get_screen_ea()
	if print_insn_mnem(bctr_ea) != "bctr":
		print("[Fix PPCJT] Unable to resolve jump table at: 0x{:08X}".format(bctr_ea))
		print("[Fix PPCJT] Selected opcode is not bctr!")
		return

	old_si = ida_nalt.switch_info_t()
	if idaapi.get_switch_info(old_si, bctr_ea) == None:
		print("[Fix PPCJT] Unable to recreate jump table at: 0x{:08X}".format(bctr_ea))
		print("[Fix PPCJT] Retrieving old table info failed!")		
		return

	if old_si.regnum == -1:
		print("[Fix PPCJT] Unable to resolve jump table at: 0x{:08X}".format(bctr_ea))
		print("[Fix PPCJT] Regnum = -1")
		return

	ncases, default_case = find_ncases(bctr_ea, old_si.regnum)
	if ncases == 0:
		print("[Fix PPCJT] Ivalid jump table found at: 0x{:08X}".format(bctr_ea))
		print("[Fix PPCJT] ncases = 0")
		return

	create_table(bctr_ea, ncases, default_case, old_si.regnum)


class ActionHandler(idaapi.action_handler_t):

    def __init__(self, callback):
        
        idaapi.action_handler_t.__init__(self)
        self.callback = callback
    
    def activate(self, ctx):

        self.callback()
        return 1

    def update(self, ctx):
        
        return idaapi.AST_ENABLE_ALWAYS


def register_actions():   

    actions = [
        {
            'id': 'start:do_single_table',
            'name': 'Fix single PowerPC jump table.',
            'hotkey': 'Alt-Shift-4',
            'comment': 'Fix PowerPC jump table.',
            'callback': do_single_table,
            'menu_location': 'Edit/Other/'
        },
        {
            'id': 'start:do_all_tables',
            'name': 'Fix PowerPC jump tables.',
            'hotkey': 'Alt-Shift-5',
            'comment': 'Fix PowerPC jump tables.',
            'callback': do_all_tables,
            'menu_location': 'Edit/Other/'
        }
    ]


    for action in actions:

        if not idaapi.register_action(idaapi.action_desc_t(
            action['id'], # Must be the unique item
            action['name'], # The name the user sees
            ActionHandler(action['callback']), # The function to call
            action['hotkey'], # A shortcut, if any (optional)
            action['comment'] # A comment, if any (optional)
        )):

            print('Failed to register ' + action['id'])

        if not idaapi.attach_action_to_menu(
            action['menu_location'], # The menu location
            action['id'], # The unique function ID
            1):
		
            print('Failed to attach to menu '+ action['id'])



class fix_ppcjt_t(idaapi.plugin_t):
	flags = idaapi.PLUGIN_UNL | idaapi.PLUGIN_HIDE
	comment = "Fix PowerPC jump tables."
	help = ""
	wanted_name = "Fix PPCJT"
	wanted_hotkey = ""

	def init(self):
		if idaapi.ph.id == idaapi.PLFM_PPC:
			idaapi.msg("Fix PPCJT loaded.\n")
			register_actions()
			return idaapi.PLUGIN_KEEP

		return idaapi.PLUGIN_SKIP
	
	def run(self, arg):
		idaapi.msg("Fix PPCJT run.\n")
	
	def term(self):
		pass


def PLUGIN_ENTRY():
	return fix_ppcjt_t()
