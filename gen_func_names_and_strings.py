#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-----------------File Info-----------------------
Name: gen_func_names_and_strings.py
Description: 提取二进制中的有效字符串和函数名
Author: GentleCP
Email: me@gentlecp.com
Create Date: 2022/6/21
-----------------End-----------------------------
"""
import idc
import idaapi
import idautils
from tqdm import tqdm
from utils import write_json, get_param, waiting_analysis


class FuncnameViewer(object):
    """
    generate function names
    """

    def __init__(self):
        self._func_names = []

    def get_func_names(self, only_name=False):
        if self._func_names:
            return [item[-1] for item in self._func_names] if only_name else self._func_names
        bar = tqdm(list(idautils.Functions()))
        for ea in bar:
            f_name = idaapi.get_func_name(ea)
            bar.set_description(f'generate {ea}, {f_name}')
            self._func_names.append((ea, f_name))
        return [item[-1] for item in self._func_names] if only_name else self._func_names

    def save(self, save_path='func_names.json', only_name=False):
        save_data = self.get_func_names(only_name)
        write_json(save_data, save_path)


class StringViewer(object):
    """
    generate strings table list
    """

    def __init__(self):
        self._strings = []
        self._strings_in_rodata = []

    def get_strings(self, only_name=False, rodata=False):
        if self._strings:
            res = self._strings_in_rodata if rodata else self._strings
        else:
            bar = tqdm(list(idautils.Strings()))
            for s in bar:
                bar.set_description(f'generate {s}')
                seg = idc.get_segm_name(s.ea)
                self._strings.append((s.ea, seg, s.length, s.strtype, str(s)))
                if seg == '.rodata':
                    self._strings_in_rodata.append(self._strings[-1])
            res = self._strings_in_rodata if rodata else self._strings

        return [item[-1] for item in res] if only_name else res

    def save(self, save_path="strings.json", only_name=False):
        save_data = {
            'strings_all': self.get_strings(only_name),
            'strings_in_rodata': self.get_strings(only_name, rodata=True),
        }
        write_json(save_data, save_path)


if __name__ == '__main__':
    waiting_analysis()
    FuncnameViewer().save(get_param(1, 'func_names.json'), only_name=get_param(3, True))
    StringViewer().save(get_param(2, 'string.json'), only_name=get_param(3, True))
