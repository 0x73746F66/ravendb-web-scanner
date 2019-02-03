#!/usr/bin/env python
import time, multiprocessing

def process(i):
    time.sleep(5)
    return i

def log_result(i):
    print('Dome %d' % i)

pool = multiprocessing.Pool(1000)
try:
    for i in range(0, 100000):
        print('Queue %d to process' % i)
        pool.apply_async(process, args=(i, ), callback = log_result)
finally:
    pool.close()
pool.join()