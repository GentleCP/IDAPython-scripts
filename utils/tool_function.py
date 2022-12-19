#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Common tool functions used in IDA scripts
"""
import subprocess

import idaapi
import ida_pro
import idc


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
