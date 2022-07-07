#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-----------------File Info-----------------------
Name: gen_caller_callee.py
Description: 生成每个函数的caller和callee调用关系
Author: GentleCP
Email: me@gentlecp.com
Create Date: 6/24/22 
-----------------End-----------------------------
"""

import idaapi
import idautils
import idc
from collections import defaultdict
from tqdm import tqdm
from utils import write_json, get_param, waiting_analysis


class CallViewer(object):
    """
    generate caller and callee for each function
    """

    def __init__(self):
        self._func2calls = defaultdict(dict)  # {'f1': {'caller': list, 'callee': list}}

    def get_calls(self, only_funcs=None):
        if self._func2calls:
            return {k: v for k, v in self._func2calls.items() if k in only_funcs} if only_funcs else self._func2calls

        bar = tqdm(list(idautils.Functions()))
        for function_ea in bar:
            func_name = idaapi.get_func_name(function_ea)
            bar.set_description(f'generate calls for {func_name}')
            for ref_ea in idautils.CodeRefsTo(function_ea, 0):
                caller_name = idaapi.get_func_name(ref_ea)
                if caller_name:
                    self._func2calls[func_name].setdefault('caller', []).append(caller_name)
            for f_name in self._func2calls[func_name].get('caller', []):
                # update callee by reverse call, f_name -> func_name
                if f_name:
                    self._func2calls[f_name].setdefault('callee', []).append(func_name)
        return {k: v for k, v in self._func2calls.items() if k in only_funcs} if only_funcs else self._func2calls

    def save(self, save_path='caller_callee.json', only_funcs=None):
        """
        保存结果到本地
        :param save_path:
        :param only_funcs: 只保存选定的函数calls
        :return:
        """
        save_data = self.get_calls(only_funcs)
        write_json(save_data, save_path)


if __name__ == '__main__':
    waiting_analysis()
    CallViewer().save(save_path=get_param(1, 'caller_callee.json'))
