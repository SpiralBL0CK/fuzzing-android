import itertools
import os,sys
import subprocess
from multiprocessing import Pool
from types import FunctionType
import threading
import random
import marshal
import time
import re

#>adb -s 10.14.14.208:5555 shell
FUZZ_WAIT = 5
DEBUG = True
HAS_CRASHED = 0
ADB_BINARY = "..\\adb.exe"
CRASH_IDENTIFIERS = ['FATAL EXCEPTION','FATAL EXCEPTION IN','FATAL EXCEPTION IN SYSTEM PROCESS: main','backtrace','SI_QUEUE','SIGSEGV', 'SIGFPE', 'SIGILL','SIGABRT','OOM','OutOfMemoryError','java.lang.OutOfMemoryError']
NOT_CRASHED = 0
CRASHED = 1
FUZZ_IP = "10.14.14.204"
# Device Settings
DEVICE_ID = "R58MA2EYZYN"

SERVER_IP = "0.0.0.0"
SERVER_PORT = 1337

def _applicable(*args, **kwargs):
    name = kwargs['__pw_name']
    code = marshal.loads(kwargs['__pw_code'])
    gbls = globals() #gbls = marshal.loads(kwargs['__pw_gbls'])
    defs = marshal.loads(kwargs['__pw_defs'])
    clsr = marshal.loads(kwargs['__pw_clsr'])
    fdct = marshal.loads(kwargs['__pw_fdct'])
    func = FunctionType(code, gbls, name, defs, clsr)
    func.fdct = fdct
    del kwargs['__pw_name']
    del kwargs['__pw_code']
    del kwargs['__pw_defs']
    del kwargs['__pw_clsr']
    del kwargs['__pw_fdct']
    return func(*args, **kwargs)

def make_applicable(f, *args, **kwargs):
    if not isinstance(f, FunctionType): raise ValueError('argument must be a function')
    kwargs['__pw_name'] = f.__name__  # edited
    kwargs['__pw_code'] = marshal.dumps(f.__code__)   # edited
    kwargs['__pw_defs'] = marshal.dumps(f.__defaults__)  # edited
    kwargs['__pw_clsr'] = marshal.dumps(f.__closure__)  # edited
    kwargs['__pw_fdct'] = marshal.dumps(f.__dict__)   # edited
    return _applicable, args, kwargs

def _mappable(x):
    x,name,code,defs,clsr,fdct = x
    code = marshal.loads(code)
    gbls = globals() #gbls = marshal.loads(gbls)
    defs = marshal.loads(defs)
    clsr = marshal.loads(clsr)
    fdct = marshal.loads(fdct)
    func = FunctionType(code, gbls, name, defs, clsr)
    func.fdct = fdct
    return func(x)

def make_mappable(f, iterable):
    if not isinstance(f, FunctionType): raise ValueError('argument must be a function')
    name = f.__name__    # edited
    code = marshal.dumps(f.__code__)   # edited
    defs = marshal.dumps(f.__defaults__)  # edited
    clsr = marshal.dumps(f.__closure__)  # edited
    fdct = marshal.dumps(f.__dict__)  # edited
    return _mappable, ((i,name,code,defs,clsr,fdct) for i in iterable)

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

def check_if_crash(process):
    global HAS_CRASHED
    #nr de iterari se da custom acu ca plm ai seed dee inceput
    #nr_de_iter = 2455
    nr_de_iter = 1

    adb = ADB_BINARY
    crash_identifiers = CRASH_IDENTIFIERS
    status = NOT_CRASHED
    wait = FUZZ_WAIT
    #print("AVEM DE ITERAT ATAT")
    #print(len(process))
    #you can change the iteration number , so basically change the seed
    for i in range(1,len(process)):
        while(HAS_CRASHED == 1):
            time.sleep(1)

        print(process[i])
        #print('\n')
        #print("=======Debug Stats===========")
        #print(HAS_CRASHED)
        #print("nr de iter"+str(len(process)))
        #print(nr_de_iter)
        #print("=======Debug Stats===========")
            
        args = [adb, "shell"] + list(process[i].split(" "))
        out = subprocess.Popen(args, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT).communicate()[0]
        #print("[INFO] Waiting for " + str(wait) + " seconds")
        #time.sleep(wait)
        # Debug
        #print(out)
        logcat_args = [adb, 'logcat', '-d']
        #print("ba muje am ajuns 1 da nu 2")
        logcat = subprocess.Popen(
            logcat_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)#.communicate()[0]
                # clear logs
        #print(logcat)
        #print("hehehehehehe horje")
        #subprocess.call(logcat_args)
        time.sleep(wait)
        logcat.kill()
        logcat2 = [line.strip().decode('utf-8',errors='backslashreplace').replace("\\","").rstrip().lstrip()  for line in iter(logcat.stdout.readline, b'')]
        #print(logcat2)
        #print("+++++++++++++++++++logcat2+++++++++++++++++++++")
        #print(logcat2)
        #print("+++++++++++++++++++logcat2+++++++++++++++++++++")
        #print("ba muje am ajuns")
        logcat_args = [adb, 'logcat', '-b', 'crash']
        logcat_chrash_pozitiv = subprocess.Popen(
            logcat_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        time.sleep(10)
        logcat_chrash_pozitiv.kill()
        logcat_chrash_pozitiv_result = [line.strip().decode('utf-8',errors='backslashreplace').replace("\\","").rstrip().lstrip() for line in iter(logcat_chrash_pozitiv.stdout.readline, b'')]
        if(len(logcat_chrash_pozitiv_result) > 0):
            print("+++++++++++++++++++logcat_chrash_pozitiv_result+++++++++++++++++++++")
            print(logcat_chrash_pozitiv_result)
            print("+++++++++++++++++++logcat_chrash_pozitiv_result+++++++++++++++++++++")

        
        nr_de_iter+=1
        logcat2 = "\n".join(logcat2)
        logcat_chrash_pozitiv_result = "\n".join(logcat_chrash_pozitiv_result)

        for id_string in crash_identifiers:
            FLAG = False
                    #print(id_string)
            if id_string in logcat2:
                FLAG = True
            if id_string in logcat_chrash_pozitiv_result:
                FLAG = True
            if(FLAG):
                f= open("crash_rez.txt","a")
                HAS_CRASHED = 1
                print("[VALID CRASH] - ")
                print(process[i].split())
                f.write(str(process[i]))
                f.write("\n")
                f.write("canonical form"+str(args))
                f.write("\n")
                print("AM IESIT NEXT THING ")
                f.close()
                time.sleep(60)
                HAS_CRASHED = 0
                #exit(0)
                clear_log_args = [adb, 'logcat', '-c']
                clear_log = subprocess.Popen(
                clear_log_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                clear_log.wait()
                break
        #clear_log_args = [adb, 'logcat', '-c']
        #clear_log = subprocess.Popen(
        #clear_log_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        #clear_log.wait()
        
    #                    return
        # print("muje rito")
    #   return
        


def make_method(servicii):
    to_send = mutate(servicii)
    #print(to_send)
    check_if_crash(to_send)
    return 

q = []
threads = []

def f(id, arg1, arg2,arg3):
    global q
    #aici pui tu ce cod vrei
    make_method(arg3)
    #time.sleep(arg1)
   # print(str(arg2)+"\n", end='', flush=True)#daca nu, se baga threadurile unele peste altele la print
    #punem threadul ca gata
    q.append(id)

#main
#pui cate threaduri vrei
n_threads = 10
for i in range(n_threads):
    q.append(i)
    threads.append(None)

#pui cate apeluri vrei

def Fuzz():
    global HAS_CRASHED
    adb_connection_int()
    servicii = list_services()
    servicii = servicii[4:len(servicii)-1]
    n=len(servicii)-30
    #print(servicii)
    #print(len(servicii))

    while n>0:
    #print(q)
        if q and HAS_CRASHED == 0: #adica daca nu e goala
            id = q.pop()
            s = 5
            a = threading.Thread(target=f, args=(id, s, n, servicii[n-1]))
            a.start()
            #print(id)
            threads[id] = a
            n -= 1
    for i in range(0,(n_threads)):
        if threads[id] is not None:
            threads[id].join()#asteptam sa termine executia


if __name__ == '__main__':
    Fuzz()
