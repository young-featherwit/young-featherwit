#encoding:utf8
# cython: language_level=3

"""
License: Research Only.
Author Sun Xiaoshan


"""
from __future__ import print_function


import time
import argparse
import random
from collections import defaultdict
import re
import shutil
import stat
from os.path import join
import mmap
from fuzz_config import ValueTypeStage, FaultCode, configs, FuzzStage, MutateStage
from core import fastmap
import signal
import random
import struct
import resource
import ctypes
import traceback

from fuzzer import FuzzerEngine, FuzzerMainEntry,MutateVars,Abandon
import fuzzer




"""

相关数据类型：

class TestCase(object):
    def __init__(self,fn,sz, depth, passed_det):
        self.file_name=fn #样本文件名称
        self.len = sz     #样本文件长度

        self.depth=depth+1
        self.exec_us = 0  #执行时间
        self.handicap=0

        self.bitmap_size=0 #边覆盖数量
        self.exec_cksum = 0

        self.cal_failed=0            
        self.trim_done = False
        self.was_fuzzed= False       #是否已经过执行测试
        self.passed_det = passed_det # 跳过确定性阶段的开关
        self.has_new_cov =False      # 本样本是否产生新的边覆盖
        self.var_behavior=0          # 是否存在不稳定的边
        self.favored=False           # 是有优先
        self.fs_redundant=False      # 

        self.tc_ref=0
        self.trace_mini=None #简化的去掉数量的边覆盖

        self.id = 0
        
        
class MutateVars(object):
    def __init__(self):
        self.new_hit_cnt = 0 # 临时存储发现的新路径数量
        self.out_buf = None  # 生成的样本缓存，进入函数时已经初始化为 in_buf的内容。
        self.temp_len = 0    # 生成的样本长度，可能比out_buf实际长度小。初始化为 in_buf 的长度
        self.in_buf = None   # 输入的样本
        self.ret_val = 1     # 
        self.orig_in = None  # 最原始的样本内容，中间用于恢复现场。一般用不到。
        
"""


class PhpFuzzEngine(FuzzerEngine):
    """  php模糊测试的引擎。  """
    def __init__(self, config):
        config.disable_deterministic = True
        super(PhpFuzzEngine, self).__init__(config)

        # self.work_queue 存储了全部的路径，也就是之前测试能够触发新路径的样本。
        # self.work_queue 是TestCase list

    def havoc_stage(self, mvar: MutateVars):
        """ 这里对url进行变异。可以采用多种的方法进行，例如采用某些工具生成
            典型的做法是对所有的可能的php文件进行遍历，对php可能接受的参数进行遍历。
        """

        leno = len(mvar.in_buf)
        # leno = curq.len

        self.stage_cur_byte = -1

        self.stage_name = "havoc"
        self.stage_short = "havoc"

        mvar.temp_len = leno
        orig_hit_cnt = self.queued_paths + self.unique_crashes
        self.havoc_queued = self.queued_paths

        mvar.new_hit_cnt = self.queued_paths + self.unique_crashes
        self.stage_max = self.config.HAVOC_CYCLES_INIT if self.doing_det else self.config.HAVOC_CYCLES
        self.stage_max = int(self.stage_max * self.perf_score / self.havoc_div / 100)

        self.stage_cur = -1
        # print('debug: havoc_stage: stage_max: {}'.format(self.stage_max))

        while self.stage_cur < self.stage_max - 1:
            self.stage_cur += 1

            # 在这里实现SQL注入url生成，存储到out_buf中，长度设置为temp_len。#TODO

            # common_fuzz_stuff 是执行模糊测试的代码。
            if self.common_fuzz_stuff(mvar.out_buf, mvar.temp_len):
                raise Abandon

            if len(mvar.out_buf) < leno:
                mvar.out_buf = bytearray(leno)
            mvar.temp_len = leno
            mvar.out_buf[0:leno] = mvar.in_buf[0:leno]

            if (self.queued_paths != self.havoc_queued):
                if (self.perf_score <= self.config.HAVOC_MAX_MULT * 100):
                    self.stage_max *= 2
                    self.perf_score *= 2
                self.havoc_queued = self.queued_paths

        self.stage_finds[FuzzStage.STAGE_HAVOC] += mvar.new_hit_cnt - orig_hit_cnt
        self.stage_cycles[FuzzStage.STAGE_HAVOC] += self.stage_max


if __name__=='__main__':
    parser = argparse.ArgumentParser(description=' GrayBox Fuzzer.')

    parser.add_argument('-i','--input', help='input dir', required=True)
    parser.add_argument('-o', '--output',help='output dir', required=True)
    groupsync = parser.add_mutually_exclusive_group()
    groupsync.add_argument('-M', '--master', help='master sync ID')
    groupsync.add_argument('-S', '--slave', help='slave sync ID')
    parser.add_argument('-f', '--target', help='target file')
    parser.add_argument('-x', '--dictionary', help='dictionary')
    parser.add_argument('-t', '--timeout', help='timeout', default='1000')
    parser.add_argument('-m', '--mem_limit', help='mem limit', default='50')
    parser.add_argument('-d', '--disable_deterministic', help='skip deterministic', action='store_true')
    parser.add_argument('-B', '--bitmap', help='load bitmap')
    parser.add_argument('-C', '--crash_mode', help='crash mode',action='store_true')
    parser.add_argument('-n', '--dumb_mode', help='dumb mode',action='store_true')
    parser.add_argument('-T', '--banner', help='banner')
    parser.add_argument('-Q', '--qemu_mode', help='QEMU mode (QEMU binary path)')
    parser.add_argument('-P', '--pt_mode', action='store_true',help='Intel PT-enabled mode. '
                                                'Supported on intel i5/i7 5000 and beyond. (root privileges required)')
    parser.add_argument('-u', '--uid', help='uid of target process', required=True)
    parser.add_argument('-h', '--host', help='the base url of host, used in mutation', required=True)
    # h 是访问php对应网站的url，例如 http://localhost/test.php，

    parser.add_argument('program_args',help='program and its arguments, @@ for the file-input',  nargs=argparse.REMAINDER)

    args = parser.parse_args()

    configs.disable_deterministic=True

    fuzzer = FuzzerMainEntry(id='0', input=args.input, output=args.output, master=args.master, slave=args.slave,
                             target=args.target, dictionary=args.dictionary, timeout=args.timeout, mem_limit=args.mem_limit,
                             disable_det=args.disable_deterministic, bitmap=args.bitmap, crash_mode=args.crash_mode,
                             dumb_mode=args.dumb_mode, banner=args.banner, qemu_mode=args.qemu_mode,
                             pt_mode=args.pt_mode, program_args=args.program_args, uid=args.uid, myengine=PhpFuzzEngine)
