#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-----------------File Info-----------------------
Name: utils.py
Description:
Author: GentleCP
Email: me@gentlecp.com
Create Date: 6/16/22 
-----------------End-----------------------------
"""
import idc
import ida_pro
import idaapi
from pathlib import Path
import json
from cptools import LogHandler

ROOT_PATH = Path(__file__).resolve().parent.parent

logger = LogHandler('idapython', log_path=ROOT_PATH.joinpath('log/'), file=True, stream=True)


def read_json(fname):
    fname = Path(fname)
    with fname.open('rt') as handle:
        return json.load(handle)

def write_json(content, fname):
    fname = Path(fname)
    with fname.open('wt') as handle:
        json.dump(content, handle, indent=4, sort_keys=False)

def waiting_analysis():
    print("Waiting for ida to finish analysis")
    idaapi.auto_wait()
    print("Analysis finished")


def get_param(index, default):
    """
    从命令行终端获取参数
    :param index:
    :param default:
    :return:
    """
    try:
        return idc.ARGV[index]
    except IndexError:
        return default


def quit_ida(status=0):
    ida_pro.qexit(status)
