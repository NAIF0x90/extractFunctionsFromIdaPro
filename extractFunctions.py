import idaapi
import idautils
import idc
import re
import sys

# Set a higher recursion limit
sys.setrecursionlimit(10000)  # You can adjust the limit as needed

def print_function_details(func_name):
    func_ea = idc.get_name_ea_simple(func_name)
    func = idaapi.get_func(func_ea)
    functions = []
    offsets = []
    #print(f"void {func_name} ()<<")

    # Print instructions with locations
    for head in idautils.Heads(func.start_ea, func.end_ea):
        instruction = idc.generate_disasm_line(head, 0)
        modified_string = re.sub("ADRL", "ADRP", instruction, count=1)
            
        #print(f"    \"{modified_string}\\n \" ")
        if 'sub_' in modified_string:
            pattern = r'sub_[0-9A-Fa-f]+'
            # Search for the pattern in the input string
            match = re.search(pattern, modified_string)
            
            if match:
                # Extract the matched substring
                sub_string = match.group(0)
                functions.append(sub_string)

    #print(">>")
    return functions

def process_functions(functions):
    for functionName in functions:
        newFunctions = print_function_details(functionName)
        for newFunction in newFunctions:
            if newFunction not in functions:
                functions.append(functionName)
                process_functions(newFunctions)

# Example usage: pass the function name as an argument
function_name = "sub_10079651C"
functionsTemp = set()  # Use a set to store processed functions
functions = print_function_details(function_name)
process_functions(functions)
for functionName in functions:
    print(functionName)
