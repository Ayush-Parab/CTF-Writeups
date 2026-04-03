# This File will be used as a keygen for the switcheroo problem as there are multiple solutions to the question

import itertools

def inc_asci_new(inp_str, value): # Increases ascii by 'value' for specific indices of string
    copy_str = inp_str
    for i in range(value):
        copy_str[((i + value) % len(copy_str))] = chr((ord(copy_str[((i + value) % len(copy_str))]) + value) % 256)
    return copy_str

def dec_asci_new(inp_str, value): # Decreases ascii by 'value' for specific indices of string
    copy_str = inp_str
    for i in range(value):
        copy_str[(i * value) % len(copy_str)] = chr((ord(copy_str[(i * value) % len(copy_str)]) - value) % 256)
    return copy_str

def shift_left(inp_list, offset): # Function to shift characters in list by offset value
    copy_list = inp_list
    mod_list = []
    for i in range(len(copy_list)):
        mod_list.append(copy_list[(i + offset) % len(copy_list)])
    return mod_list

def even_rev(inp_list, param_2): # Function to reverse when param_2 is even
    string_one = shift_left(inp_list, param_2)
    list_two = dec_asci_new(string_one, param_2)
    return list_two

def odd_rev(inp_list, param_2): # Function to reverse when param_2 is odd
    list_one = inc_asci_new(inp_list, param_2)
    list_two = shift_left(list_one, param_2)
    return list_two

def full_transform(inp_list): #This function reverses our final string to give back our original
    rev_seven_list = odd_rev(inp_list, 7)
    rev_ten_list = even_rev(rev_seven_list, 10)
    rev_twentyfour_list = even_rev(rev_ten_list, 24)
    rev_three_list = odd_rev(rev_twentyfour_list, 3)
    rev_thirteen_list = odd_rev(rev_three_list, 13)
    rev_six_list = even_rev(rev_thirteen_list, 6)
    rev_five_list = odd_rev(rev_six_list, 5)
    print("".join(rev_five_list))
    return

# options is a list of lists to make all possible combinations of the final_string which is acceptable, total 80 combinations

options = [
    ['s'],
    ['e'],
    ['i'],
    [chr(0x1e)],
    ['R'],
    [chr(0x91), chr(0x92)],
    ['3'],
    ['^'],
    [chr(0x7f)],
    ['`'],
    ['&'],
    ['«'],
    ['1'],
    ['s'],
    ['ª'],
    ['Y'],
    ['}', '~', chr(0x7f), chr(0x80), chr(0x81)],
    ['¥'],
    ['Y'],
    ['t', 'u', 'v', 'w'],
    ['µ'],
    ['v'],
    ['A'],
    [chr(0xad), '®'],
    ['1'],
    ['e'],
    [chr(0xC0)]
]

combinations = list(itertools.product(*options)) # All 80 combinations present

print(f"Total combinations found: {len(combinations)}")

for combo in combinations:
    full_transform(list(combo))
