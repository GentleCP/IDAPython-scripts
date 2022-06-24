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
import idaapi
import idautils
import idc
from pathlib import Path
import json


def write_json(content, fname):
    fname = Path(fname)
    with fname.open('wt') as handle:
        json.dump(content, handle, indent=4, sort_keys=False)


class FuncnameViewer(object):
    """
    generate function names and imports exports
    """

    def __init__(self):
        self._func_names = []
        self._imports = []
        self._exports = []

    def imports_names_cb(self, ea, name, ord):
        tmp = name.split('@@')
        if len(tmp) == 1:
            self._imports.append([ord, ea, tmp[0], ''])
        else:
            self._imports.append([ord, ea, tmp[0], tmp[1]])
        return True

    def get_imports(self):
        if self._imports:
            return self._imports

        nimps = idaapi.get_import_module_qty()
        for i in range(nimps):
            idaapi.enum_import_names(i, self.imports_names_cb)
        self._imports.sort(key=lambda x: x[2])
        return self._imports

    def get_exports(self):
        if self._exports:
            return self._exports
        self._exports = list(idautils.Entries())
        return self._exports

    def get_func_names(self):
        if self._func_names:
            return self._func_names
        for ea in idautils.Functions():
            self._func_names.append((ea, idc.get_func_name(ea)))
        return self._func_names

    def save(self, save_path='imports_exports.json', only_name=False):
        if only_name:
            save_data = {
                'func_names': [item[-1] for item in self.get_func_names()],
                'imports': [item[2:] for item in self.get_imports()],
                'exports': [item[3] for item in self.get_exports()],
            }
        else:
            save_data = {
                'func_names': self.get_func_names(),
                'imports': self.get_imports(),
                'exports': self.get_exports(),
            }

        write_json(save_data, save_path)


class StringViewer(object):
    """
    generate strings table list
    """

    def __init__(self):
        self._strings = []
        self._strings_in_rodata = []

    def get_strings(self, rodata=False):
        if self._strings:
            return self._strings_in_rodata if rodata else self._strings
        for s in idautils.Strings():
            seg = idc.get_segm_name(s.ea)
            self._strings.append((s.ea, seg, s.length, s.strtype, str(s)))
            if seg == '.rodata':
                self._strings_in_rodata.append(self._strings[-1])
        return self._strings_in_rodata if rodata else self._strings

    def save(self, save_path="strings.json", only_name=False):
        if only_name:
            save_data = {
                'strings_all': [item[-1] for item in self.get_strings()],
                'strings_in_rodata': [item[-1] for item in self.get_strings(rodata=True)]
            }
        else:
            save_data = {
                'strings_all': self.get_strings(),
                'strings_in_rodata': self.get_strings(rodata=True),
            }

        write_json(save_data, save_path)


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


if __name__ == '__main__':
    only_name = get_param(3, True)
    FuncnameViewer().save(get_param(1, 'func_names.json'), only_name=only_name)
    StringViewer().save(get_param(2, 'string.json'), only_name=only_name)
