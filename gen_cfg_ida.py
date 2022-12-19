#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-----------------File Info-----------------------
Name: gen_cfg_ida.py
Description: 提取指定binary的所有函数的cfg，block，汇编代码
Author: GentleCP
Email: me@gentlecp.com
Create Date: 2022/9/15
-----------------End-----------------------------
"""
import json

import idc
import idaapi
import idautils

from pathlib import Path
from cptools import LogHandler
from utils.tool_function import waiting_analysis, quit_ida

logger = LogHandler('CFGExtract', log_path='log/', file=True)


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
                'func_name': idaapi.get_func_name(func.start_ea),
                'cfg': cfg,
                'blocks': blocks,
                'code': get_assembly_code(func_t=func)
            }) + '\n')
    logger.critical(f'cfg saved in {feat_path}')


if __name__ == '__main__':
    try:
        waiting_analysis()
        main()
    except Exception as e:
        import traceback

        logger.error(traceback.format_exc())
        quit_ida(400)
    else:
        quit_ida(0)
