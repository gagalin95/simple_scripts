import idc,idaapi,idautils

g_sum = -1
g_formula = []
g_result = []

def parse_inst(ea,target):
	global g_formula
	#pop add ldr
	inst = idc.GetDisasm(ea)
	# print "inst : 0x%x -> %s" % (ea,inst)
	m = idc.GetMnem(ea)
	if m == 'POP':
		# POP {R0}
		op_Rd = idc.GetOpnd(ea,0)
		if target == op_Rd[1:-1]:
			op_Rd = idc.GetOpnd(ea,0)
			if target in op_Rd:
				# print "valid inst : 0x%x -> %s" % (ea,inst)
				# print "target change to PUSH"
				return 'PUSH'
	
	elif m == 'PUSH' and target == 'PUSH':
		# PUSH {R4}
		op_Rd = idc.GetOpnd(ea,0)
		# print "valid inst : 0x%x -> %s" % (ea,inst)
		# print "target change to %s" % op_Rd[1:-1]
		return op_Rd[1:-1]
	
	elif m == 'LDR':
		op_Rd = idc.GetOpnd(ea,0)
		if op_Rd == target:
			Rn_type =  idc.GetOpType(ea,1)
			# print "Rn_type : %d" % Rn_type
			if Rn_type == 2: #o_mem
				# LDR R0,=0xB5F	
				mem_addr = idc.GetOperandValue(ea,1)
				g_formula.append({'=':idc.Dword(mem_addr)})
				# print "valid inst : 0x%x -> %s" % (ea,inst)
				return None

			elif Rn_type == 4: #o_displ
				#LDR     R5, [SP,#0x188+var_18]
				op_Rn = GetOpnd(ea, 1)
				# print "valid inst : 0x%x -> %s" % (ea,inst)
				# print "target change to %s" % op_Rn
				return op_Rn

	elif m == 'ADDS':
		# ADDS R0,#0x28
		op_Rd = idc.GetOpnd(ea,0)
		if op_Rd == target:
			Rn_type = idc.GetOpType(ea,1)
			# print "Rn_type : %d" % Rn_type
			if Rn_type == 5:#o_imm
				# print "valid inst : 0x%x -> %s" % (ea,inst)
				imm = idc.GetOperandValue(ea,1)
				g_formula.append({'+':imm})

	elif m == 'STR':
		#STR     R0, [SP,#0x188+var_18]
		op_Rn = idc.GetOpnd(ea,1)
		if op_Rn == target:
			op_Rd = GetOpnd(ea, 0)
			# print "valid inst : 0x%x -> %s" % (ea,inst)
			# print "target change to %s" % op_Rd
			return op_Rd

	elif m == 'MOVS':
		op_Rd = idc.GetOpnd(ea,0)
		if op_Rd == target:
			Rn_type = idc.GetOpType(ea,1)
			if Rn_type == 5:#o_imm
				imm = idc.GetOperandValue(ea,1)
				g_formula.append({'=':imm})
				return None

	elif m == 'LSLS':
		#0xa4560
		op_Rd = idc.GetOpnd(ea,0)
		if op_Rd == target:
			Rm_type = idc.GetOpType(ea,1)
			op_Rm = idc.GetOpnd(ea,1)
			Rs_type = idc.GetOpType(ea,2)
			if Rm_type == 1 and Rs_type == 5:#o_reg/o_imm
				imm = idc.GetOperandValue(ea,2)
				g_formula.append({'*':(2 ** imm)})
				# print "valid inst : 0x%x -> %s" % (ea,inst)
				# print "target change to %s" % op_Rm
				return op_Rm
			else:
				print "error,  inst : 0x%x -> %s" % (ea,inst)

	return target

def calu_r0(ea):
	global g_sum,g_formula
	inst_addr = idc.PrevHead(ea)
	cur_func = idaapi.get_func(ea)
	target = 'R0'
	g_sum = -1
	g_formula = []
	while (inst_addr != idc.BADADDR)  and (inst_addr > cur_func.startEA):
		target = parse_inst(inst_addr,target)
		if target == None:
			break
		inst_addr = idc.PrevHead(inst_addr)

	for idx,operator_dic in enumerate(reversed(g_formula)) :
		key = operator_dic.keys()[0]
		value = operator_dic[key]
		if idx == 0:
			if key == '=':
				g_sum = value
			else:
				#0xd617e
				print "error, first operator is not ="
				break
		elif idx > 0:
			if key == '+':
				g_sum += value
			elif key == '*':
				g_sum *= value

	print "finish, g_sum : %d " % g_sum

	if g_sum != -1:
		d = {ea:g_sum}
		g_result.append(d)

# calu_r0(idc.ScreenEA())
addr = idc.LocByName("StrDecrypt")
print "addr : 0x%x" % addr
for ea in idautils.CodeRefsTo(addr, 0):
	# if 0x203C3A < ea < 0x20468C:
	# 	continue
	print "start ea : 0x%x" % ea
	calu_r0(ea)

# print g_result
