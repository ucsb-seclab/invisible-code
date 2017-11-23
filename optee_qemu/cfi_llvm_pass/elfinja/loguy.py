class Bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def log_info(*args):
    log_str = Bcolors.OKBLUE + "[*] "
    for curr_a in args:
        log_str = log_str + " " + str(curr_a)
    log_str += Bcolors.ENDC
    print log_str


def log_error(*args):
    log_str = Bcolors.FAIL + "[!] "
    for curr_a in args:
        log_str = log_str + " " + str(curr_a)
    log_str += Bcolors.ENDC
    print log_str


def log_warning(*args):
    log_str = Bcolors.WARNING + "[?] "
    for curr_a in args:
        log_str = log_str + " " + str(curr_a)
    log_str += Bcolors.ENDC
    print log_str


def log_success(*args):
    log_str = Bcolors.OKGREEN + "[+] "
    for curr_a in args:
        log_str = log_str + " " + str(curr_a)
    log_str += Bcolors.ENDC
    print log_str