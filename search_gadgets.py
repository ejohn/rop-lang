from ropeme import gadgets
import sys
import json


depth = 3

OKGREEN = '\033[92m'
FAIL = '\033[91m'
ENDC = '\033[0m'


print 'Searching for gadgets in %s' % sys.argv[1]

gadgets = gadgets.ROPGadget(debug=0)
gadgets.generate(sys.argv[1], depth)



search_list = open('gadget_search_list', 'r').readlines()
search_list = json.loads("".join(search_list))

save_file = open('gadget_address_list', 'w+')
found_list = {}


for gadget in search_list.keys():
    found = gadgets.asm_search(search_list[gadget], [set([]), set([])])

    if len(found) < 1:
        print FAIL + gadget.strip() + " || Not found" + ENDC
        continue

    print OKGREEN + gadget.strip() + " || found @ " + hex(found[0][1]) + ENDC
    found_list[gadget] = hex(found[0][1])


found_list_json=json.dumps(found_list, indent=4)
save_file.write(found_list_json)
save_file.close()