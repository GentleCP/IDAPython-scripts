#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-----------------File Info-----------------------
Name: extract_cfg_ida.py
Description:
Author: GentleCP
Email: me@gentlecp.com
Create Date: 2022/9/15
-----------------End-----------------------------
"""
import json
import subprocess

import idc
import idaapi
import idautils
import ida_pro

from pathlib import Path
from cptools import LogHandler


def execute_cmd(cmd, timeout=900):
    """
    execute system command
    :param cmd:
    :param f: 用于指定输出到文件显示，方便后台追踪长时间运行的程序
    :param timeout:
    :return:
    """
    try:
        p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                           timeout=timeout)

    except subprocess.TimeoutExpired as e:
        return {
            'errcode': 401,
            'errmsg': 'timeout'
        }
    return {
        'errcode': p.returncode,
        'errmsg': p.stdout.decode()
    }


logger = LogHandler('CFGExtract', log_path='log/', file=True)


def wait_for_analysis_to_finish():
    """
    等待ida将二进制文件分析完毕再执行其他操作
    :return:
    """
    idaapi.auto_wait()


def get_func_name(func_t):
    return idaapi.get_func_name(func_t.start_ea)


def get_blocks_and_cfg(func_t):
    flowchart = idaapi.FlowChart(func_t)

    blocks = []
    cfg = []
    for block in flowchart:
        # block id from 0 -> flowchart.size
        cfg_i = []
        blocks.append((block.id, hex(block.start_ea), hex(block.end_ea)))
        for successor in block.succs():
            cfg_i.append(successor.id)
        cfg.append(cfg_i)
    return blocks, cfg


def get_assembly_code(func_t):
    items = idautils.FuncItems(func_t.start_ea)

    code = []
    for item in items:
        code.append((hex(item), idc.GetDisasm(item)))
    return code


def main():
    if len(idc.ARGV) > 1:
        feat_path = Path(idc.ARGV)
    else:
        feat_path = Path(f'{idaapi.get_root_filename()}_cfg.json')

    logger.info(feat_path)
    with open(feat_path, 'w') as f:
        for i in range(0, idaapi.get_func_qty()):
            func = idaapi.getn_func(i)
            seg_name = idc.get_segm_name(func.start_ea)
            if seg_name[1:3] not in ["OA", "OM", "te"]:
                continue
            blocks, cfg = get_blocks_and_cfg(func_t=func)
            f.write(json.dumps({
                'func_name': get_func_name(func_t=func),
                'cfg': cfg,
                'blocks': blocks,
                'code': get_assembly_code(func_t=func)
            }) + '\n')
    logger.info(f'cfg saved in {feat_path}')


if __name__ == '__main__':
    try:
        wait_for_analysis_to_finish()
        main()
    except Exception as e:
        import traceback

        logger.info(traceback.format_exc())
    ida_pro.qexit(0)
