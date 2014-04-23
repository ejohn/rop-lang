import sys
import re
from runner import Runner

if len(sys.argv) != 2:
	print "Usage: %s prog.rop" % sys.argv[0]


prog = open(sys.argv[1], 'r').readlines()
prog = [line for line in prog if line.strip() != ""]
current = 0


def tokenize(s):
	return re.sub(r'[\(\),\[\]"]', ' ', s).split()

def atom(token):
    try: return int(token)
    except ValueError:
    	if token.startswith('0x'): return int(token, 16)
    	else:
    		return str(token) 

if prog[0].startswith("libc_base"):
		libc_line = [atom(token) for token in tokenize(prog[0])]
		addr_line = [atom(token) for token in tokenize(prog[1])]
	
		if libc_line[0] == "libc_base" and addr_line[0] == "mem_addr":
			libc_base = libc_line[2]
			mem_addr = addr_line[2]
			r = Runner(calculate_offsets=False, offsets=[libc_base, mem_addr])

			current += 2
		else:
			r = Runner()
else:
	r = Runner()

vars = []
env = {
		'+': r.add, 
		'-': r.sub_generic,
		'^':r.xor, 
		'&': r.and_,
	    '||': r.or_, 
	    '<<': r.left_shift_generic, 
	    '>>': r.right_shift_generic,
	    '<': r.left_rotate_generic,
	    '>': r.right_rotate_generic
	}

syscalls = {
	'write': 4,
	'exit': 1,
	'execve': 11
}

def assign(line):
	if line[0][1:] in pointers:
		r.update_pointer(line[0], line[2])
	else:
		r.store_variable(line[0], line[2])


def do_action(line, result=None):
	op = line[3]

	if op in env:
		action = env[op]
		
		if op == '-':
			action(line[2], line[4], result)
		elif op in ['<<', '>>', '<', '>']:
			action(line[2], line[4], result)
		else:
			r.operation_generic(action, line[2], line[4], result)


def process_syscall(line, conditions):
	syscall = line[0]
	args = line[1:]
	offset = 0

	if len(conditions) > 0:
		current_payload = r.payload
		r.payload = ""

		for cond in conditions:
			r.conditions(cond, 0)

		offset = len(r.payload)
		r.payload = current_payload

	r.syscall(syscalls[syscall], args, offset)


ifs = []
loops = []
if_conditions = []
pointers = []


while current < len(prog):
	line = tokenize(prog[current])
	line = [atom(token) for token in line]	

	if line[0] == "var":
		vars.append(line[1])

		if len(line[1:]) == 3 and line[2] == "=":
			r.create_variable(line[1], line[3])
		elif len(line[1:]) == 5:
			r.create_variable(line[1])
			do_action(line[1:], line[1])
		elif len(line[1:]) == 1:
			r.create_variable(line[1])

	elif line[0] == "if":
		r.create_new_payload_block()

		ifs.append(r.get_current_block())
		if_conditions.append(line[1:])
	
	elif line[0] == "endif":
		last_if = ifs.pop()
		last_cond = if_conditions.pop()
		last_payload_size = r.get_last_block_length()

		r.merge_payload_block(last_if, last_cond, last_payload_size)

	elif line[0] == "loop":
		loops.append(r.checkpoint_blocks())


	elif line[0] == "while":
		start = loops.pop()
		cond = line[2]

		if cond == '<' or cond == '==':
			r.sub_generic(line[1], line[3])
		else:
			r.sub_generic(line[3], line[1])

		end = r.checkpoint_blocks()
		delta = r.find_block_delta(start, end)

		r.conditions(line[1:], -delta, skip_sub=True)

	elif line[0] == "array":
		name = line[1]
		nums = line[3:]

		r.create_array(name, nums)

	elif line[0] == "pointer":
		name = line[1]
		target = line[3]

		pointers.append(name)
		r.create_pointer(name, target)


	elif line[0] in vars \
			or line[0] in pointers \
			or (line[0].startswith('*') and line[0][1:] in pointers):

		if len(line) == 3:
			assign(line)
		else:
			do_action(line, line[0])


	elif line[0] == "breakpoint":
		r.nop()

	elif line[0] == "string":
		name = line[1]
		string = ' '.join(line[3:])

		r.create_variable(name)
		vars.append(name)
		r.store_string(string, name)

	elif line[0] == "syscall":
		process_syscall(line[1:], if_conditions)

	else:
		print 'Wrong syntax: ', line
		break

	current += 1

r.finalize()
