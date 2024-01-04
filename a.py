import itertools
import os,sys
import subprocess
import time
import re

#>adb -s 10.14.14.208:5555 shell
FUZZ_WAIT = 5
DEBUG = True
ADB_BINARY = "adb.exe"
CRASH_IDENTIFIERS = ['SIGSEGV', 'SIGFPE', 'SIGILL']

FUZZ_IP = "10.14.14.204"
# Device Settings
DEVICE_ID = "R58MA2EYZYN"

SERVER_IP = "0.0.0.0"
SERVER_PORT = 1337


parcels = {"i32":[1, 0, 65535, 0xfffffffe, 0xfffffff],
            "i64":[0xffffffffffffffffe,0xfffffffffffffffff,1,0],
            "f":[-1, 3.141592],
            "s16":["3%%n%x%%s%s%%n1","A"*10,"A"*4,"\xff\xfff\xff\xff\xff\xff\xff\xfc"]
        }

def list_services():
    adb = ADB_BINARY
        #print([adb, "shell", "service list"])
    x = subprocess.run([adb, "shell", "service list"], stdout=subprocess.PIPE)
    k = str(x.stdout).split("\\r\\n")
    final = []
    for i in k:
        temp = i.split()[0].replace(":","").replace("\\t","")
        zeta = ''.join(filter(lambda x: not x.isdigit(),temp))
        final.append(zeta)
    return final

def adb_connection_int():
    '''
    Starts ADB server
    Connect to Device
    Kills All Apps
    '''
    adb = ADB_BINARY
    dev_id = DEVICE_ID
    subprocess.call([adb, "kill-server"])
    subprocess.call([adb, "start-server"])
    subprocess.call([adb, "-s", dev_id, "wait-for-device"])



def mutate(service_name):
    to_return = []
    SERVICE_STILL_HAS_CODES = True
    CODE = 1
    while SERVICE_STILL_HAS_CODES:
        for args_count in range(4): # the number of args (outputs) that the fuzzer will produce
            NEXT_CODE = True
            for args_schema in itertools.combinations(parcels.keys(),args_count):
                arg_collection = []
                if NEXT_CODE == False:
                    break
                for arg_type in args_schema:
                    for current_arg_value in parcels[arg_type]:
                        arg_collection.append("{} \"{}\" ".format(arg_type, current_arg_value))
                for fuzzed_args in itertools. combinations(arg_collection,args_count):
                    arg_list = [a for a in fuzzed_args]
                    str_args = "".join(arg_list)
                    FUZZCMD = "service call {} {} {}". format (service_name, CODE, str_args)
                    to_return.append(FUZZCMD)
        CODE = CODE+1
        if CODE > 128:
            SERVICE_STILL_HAS_CODES = False
    return to_return

def Fuzz():
    adb_connection_int()
    servicii = list_services()
    servicii = servicii[1:len(servicii)-1]
    print(servicii)
    wait = FUZZ_WAIT
    adb = ADB_BINARY
    for i in servicii:
        process = mutate(i)
        for i in process:
            args = [adb, "shell"] + list(i.split(" "))
            out = subprocess.Popen(args, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT).communicate()[0]
            print("[INFO] Waiting for " + str(wait) + " seconds")
            time.sleep(wait)
            # Debug
            print(out)
            logcat_args = [adb, 'logcat', '-d']
            logcat = subprocess.Popen(
                logcat_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT).communicate()[0]
            # clear logs
            logcat_args = [adb, 'logcat', '-c']
            subprocess.call(logcat_args)
            crash_identifiers = CRASH_IDENTIFIERS
            logcat = str(logcat).split("\\r\\n")
            #print(type(logcat))
            if any(id_string in logcat for id_string in crash_identifiers):
                print("[VALID CRASH] - ")
                print(i.split())

Fuzz()
