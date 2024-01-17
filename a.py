import itertools
import subprocess
from multiprocessing import Pool
import threading
import random
import time
from queue import PriorityQueue, Queue

#>adb -s 10.14.14.208:5555 shell
FUZZ_WAIT = 5
DEBUG = True
HAS_CRASHED = 0
ADB_BINARY = "..\\adb.exe"
CRASH_IDENTIFIERS = ['FATAL EXCEPTION','FATAL EXCEPTION IN','FATAL EXCEPTION IN SYSTEM PROCESS: main','backtrace','SI_QUEUE','SIGSEGV', 'SIGFPE', 'SIGILL','SIGABRT','OOM','OutOfMemoryError','java.lang.OutOfMemoryError']
NOT_CRASHED = 0
CRASHED = 1
FUZZ_IP = "10.14.14.219" #"10.14.14.204"
# Device Settings
DEVICE_ID = "R5CT70PRNXM" #"R58MA2EYZYN"

SERVER_IP = "0.0.0.0"
SERVER_PORT = 1337

service_enum_q = Queue()
call_q = PriorityQueue()

parcels = {"i32":[1, 0, 65535, 0xfffffffe, 0xfffffff],
            "i64":[0xffffffffffffffffe,0xfffffffffffffffff,1,0],
            "f":[-1, 3.141592],
            "s16":["3%%n%x%%s%s%%n1","A"*10,"A"*4,"\xff\xfff\xff\xff\xff\xff\xff\xfc"]
        }

def enum_services():
    list_temporary = []
    adb = ADB_BINARY
        #print([adb, "shell", "service list"])
    x = subprocess.run([adb, "shell", "service list"], stdout=subprocess.PIPE)
    k = list(filter(lambda z : b"\t" in z, x.stdout.split(b"\r\n") ))
    for i in k:
        service_name = i.split(b"\t")[1].split(b':')[0].decode()
        service_running = subprocess.run([adb, "shell", "service", "check", service_name], stdout=subprocess.PIPE)
        if b"not found" not in service_running.stdout:
            list_temporary.append(service_name)
    list_temporary = list_temporary[4:len(list_temporary)-1]
    new_services = []
    one = list_temporary[191:197]
    for i in range(0,len(one)):
        new_services.append(one[i])
    #print(one)

    two = list_temporary[181:191]
    for i in range(0,len(two)):
        new_services.append(two[i])
    #print(two)

    three = list_temporary[161:171]
    for i in range(0,len(three)):
        new_services.append(three[i])
   # print(three)

    four =  list_temporary[151:161]
    for i in range(0,len(four)):
        new_services.append(four[i])
    #print(four)


    five = list_temporary[82:92]
    for i in range(0,len(five)):
        new_services.append(five[i])
    #print(five)
    #print("eeeeeeeeeeeeeeeeeeeeeeeeepetreeeeeeeeeeeeeeeeeeeeeeeeeeeee")

    five = list_temporary[141:151]
    for i in range(0,len(five)):
        new_services.append(five[i])
    #print(five)

    sever = list_temporary[112:122]
    for i in range(0,len(sever)):
        new_services.append(sever[i])

    six = list_temporary[130:140]
    for i in range(0,len(six)):
        new_services.append(six[i])
    #print(six)

    sever = list_temporary[160:170]
    for i in range(0,len(sever)):
        new_services.append(sever[i])
    #print(sever)
    sever = list_temporary[71]
    new_services.append(sever)
    #print(sever)

    sever = list_temporary[42:44]
    for i in range(0,len(sever)):
        new_services.append(sever[i])
    #print(sever)

    sever = list_temporary[50]
    new_services.append(sever)
    #print(sever)

    sever = list_temporary[21:29]
    #print(sever)
    for i in range(0,len(sever)):
        new_services.append(sever[i])

    n=len(new_services)-78
    #print(n)
    #we start fuzzing from 0-20 and we are elft from 21-(79-21)
    #print(list_temporary)
    print("eeeeeeeeeeeeeeeeeeeeeeeeepetreeeeeeeeeeeeeeeeeeeeeeeeeeeee")
    print(new_services[0:20])
    #0-79 to fuzz
#C:\Users\Vlad\Desktop\platform-tools\fuzzing_android
    for i in range(0,n):
        service_enum_q.put(new_services[i])






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
    for method_no in range(1,128):
        for args_count in range(4): # the number of args (outputs) that the fuzzer will produce
            for args_schema in itertools.combinations(parcels.keys(),args_count):
                arg_collection = []
                for arg_type in args_schema:
                    for current_arg_value in parcels[arg_type]:
                        arg_collection.append("{} \"{}\" ".format(arg_type, current_arg_value))
                for fuzzed_args in itertools. combinations(arg_collection,args_count):
                    arg_list = [a for a in fuzzed_args]
                    str_args = "".join(arg_list)
                    FUZZCMD = "service call {} {} {}". format (service_name, method_no, str_args)
                    call_q.put((random.randrange(1,100), FUZZCMD))

def check_if_crash(process):
    global HAS_CRASHED
    #nr de iterari se da custom acu ca plm ai seed dee inceput
    #nr_de_iter = 2455
    nr_de_iter = 1

    adb = ADB_BINARY
    crash_identifiers = CRASH_IDENTIFIERS

    print(process)
    #print('\n')
    #print("=======Debug Stats===========")
    #print(HAS_CRASHED)
    #print("nr de iter"+str(len(process)))
    #print(nr_de_iter)
    #print("=======Debug Stats===========")
        
    args = [adb, "shell"] + list(process.split(" "))
    out = subprocess.Popen(args, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT).communicate()[0]
    #print("[INFO] Waiting for " + str(wait) + " seconds")
    #time.sleep(wait)
    # Debug
    #print(out)
    logcat_args = [adb, 'logcat', '-d']
    logcat = subprocess.Popen(
        logcat_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    time.sleep(FUZZ_WAIT)
    logcat.kill()
    logcat2 = [line.strip().decode('utf-8',errors='backslashreplace').replace("\\","").rstrip().lstrip()  for line in iter(logcat.stdout.readline, b'')]
    logcat_args = [adb, 'logcat', '-b', 'crash', '-d']
    logcat_chrash_pozitiv = subprocess.Popen(
        logcat_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    logcat_chrash_pozitiv.wait()
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
            if "java.lang.OutOfMemoryError" in logcat2:
                FLAG = False
            if "AdroidRuntime: java.lang.OutOfMemoryError" in logcat2:
                FLAG = False
            if "AdroidRuntime:java.lang.OutOfMemoryError" in logcat2:
                FLAG = False
            else:
                FLAG = True
        if id_string in logcat_chrash_pozitiv_result:
            if "java.lang.OutOfMemoryError" in logcat_chrash_pozitiv_result:
                FLAG = False
            if "AdroidRuntime: java.lang.OutOfMemoryError" in logcat_chrash_pozitiv_result:
                FLAG = False
            if "AdroidRuntime:java.lang.OutOfMemoryError" in logcat_chrash_pozitiv_result:
                FLAG = False
            else:
                FLAG = True
            FLAG = True
        if(FLAG):
            f= open("four_crash.txt","a")
            HAS_CRASHED = 1
            print("[VALID CRASH] - ")
            #print(process.split())
            f.write(str(process))
            f.write("\n")
            #f.write("canonical form"+str(args))
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
        

def producer():
    print(f"Started Producer {threading.get_ident()}")
    while True:
        service = service_enum_q.get()
        if (service == "stop"):
            service_enum_q.task_done()
            break
        mutate(service)
        service_enum_q.task_done()
    print(f"Done Producer {threading.get_ident()}")

def consumer():
    print(f"Started Consumer {threading.get_ident()}")
    while True:
        call = call_q.get()[1]
        print(call)
        if (call == "stop"):
            call_q.task_done()
            break
        check_if_crash(call)
        call_q.task_done()
    print(f"Done Consumer {threading.get_ident()}")

def Fuzz():
    global HAS_CRASHED
    adb_connection_int()
    
    prod_threads = []
    consumer_threads = []
    for _ in range(20):
        t = threading.Thread(target=producer)
        t.start()
        prod_threads.append(t)


    enum_services()

    for _ in range(20):
        service_enum_q.put('stop')

    for _ in range(20):
        t = threading.Thread(target=consumer)
        t.start()
        consumer_threads.append(t)

    service_enum_q.join()

    for _ in range(20):
        call_q.put((1000,'stop'))
    call_q.join()


if __name__ == '__main__':
    Fuzz()
