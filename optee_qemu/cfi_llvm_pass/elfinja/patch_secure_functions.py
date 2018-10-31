from elfinja import ELFinja
import argparse
import time
import sys
import os
import struct
from loguy import log_success, log_info, log_error, log_warning
from subprocess import Popen, PIPE


def setup_args():
    parser = argparse.ArgumentParser()

    parser.add_argument('-f', action='store', dest='sec_func_file',
                        help='Path to the file that contains all the functions in the secure region.')

    parser.add_argument('-i', action='store', dest='input_elf',
                        help='Path to the elf file which needs to be patched.')

    parser.add_argument('-o', action='store', dest='output_elf',
                        help='Path where the output file should be stored.')

    parser.add_argument('-s', action='store', dest='cfi_symbol_name',
                        help='Name of the symbol where the CFI data needs to be written',
                        default="cfi_data_start_guy")

    return parser


def usage():
    log_error("Invalid Usage.")
    log_error("Run: python ", __file__, "--help", ", to know the correct usage.")
    sys.exit(-1)


def get_all_symbols(curr_elf):
    to_ret = {}
    newp = Popen("/home/ocean/projects/tarnhelm/qemu_cfi/optee_qemu/toolchains/aarch32/bin/arm-linux-gnueabihf-nm " + curr_elf, shell=True, stdout=PIPE, stderr=PIPE)
    output_text, error_text = newp.communicate()
    if error_text:
        log_error(error_text)

    if newp.returncode == 0:
        for curr_sym_line in output_text.split("\n"):
            curr_sym_line = curr_sym_line.strip()
            if curr_sym_line:
                all_parts = curr_sym_line.split()
                if len(all_parts) > 2:
                    to_ret[all_parts[-1]] = int("0x" + all_parts[0], 16)
    return to_ret


def main():
    arg_parser = setup_args()
    parsed_args = arg_parser.parse_args()
    func_list_file = parsed_args.sec_func_file
    input_elf = parsed_args.input_elf
    output_elf = parsed_args.output_elf
    cfi_symbol_name = parsed_args.cfi_symbol_name

    log_info("Trying to get symbol information.")
    all_symbol_info = get_all_symbols(input_elf)
    log_success("Got:", len(all_symbol_info), " symbols.")

    log_info("Trying to get function list from:", func_list_file)
    all_lines = open(func_list_file, "r").readlines()
    all_lines = map(lambda x: x.strip(), all_lines)
    all_lines = filter(lambda x: len(x) > 0, all_lines)
    log_success("Got:", len(all_lines), " function names.")
    log_info("Trying to get address of the functions.")
    target_func_addrs = []
    for curr_fun in all_lines:
        target_func_addrs.append(all_symbol_info[curr_fun])
    log_success("Got addresses of all the secure functions.")

    insert_symbol_name = cfi_symbol_name
    log_info("Trying to insert at the symbol:", insert_symbol_name)
    target_insert_address = all_symbol_info[insert_symbol_name]
    log_info("Got address of the symbol at:", hex(target_insert_address))

    newefinja = ELFinja(input_elf)

    log_info("Trying to write number of functions:", len(target_func_addrs), "at:", hex(target_insert_address))
    curr_addr = target_insert_address
    newefinja.patch_bytes(curr_addr, struct.pack('<q', len(target_func_addrs)))
    curr_addr += 8
    i = 0
    while i < len(target_func_addrs):
        currr_insert_addr = target_func_addrs[i]
        log_info("Trying to insert address:", hex(currr_insert_addr), "at:", hex(curr_addr))
        newefinja.patch_bytes(curr_addr, struct.pack('<q', currr_insert_addr))
        curr_addr += 8
        i += 1
    log_success("Patched all bytes.")
    log_info("Trying to write to the output file:", output_elf)
    newefinja.writeout(output_elf)
    log_success("Patched elf file present at:", output_elf)


if __name__ == "__main__":
    main()



