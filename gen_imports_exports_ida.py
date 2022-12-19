#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-----------------File Info-----------------------
Name: gen_imports_exports_ida.py
Description: 提取binary的导入导出表
Author: GentleCP
Email: me@gentlecp.com
Create Date: 6/15/22
-----------------End-----------------------------
"""
import idaapi
import idautils
import idc
from cptools import write_json
from utils.tool_function import waiting_analysis, get_param, quit_ida


class IEViewer(object):
    """
    generate import and export table list
    """

    def __init__(self):
        self._imports = []
        self._exports = []

    def imports_names_cb(self, ea, name, ord):
        tmp = name.split('@@')
        if len(tmp) == 1:
            self._imports.append([ord, ea, tmp[0], ''])
        else:
            self._imports.append([ord, ea, tmp[0], tmp[1]])
        return True

    def get_imports(self, only_name=False):
        if self._imports:
            return [item[2:] for item in self._imports] if only_name else self._imports

        nimps = idaapi.get_import_module_qty()
        for i in range(nimps):
            idaapi.enum_import_names(i, self.imports_names_cb)
        self._imports.sort(key=lambda x: x[2])
        return [item[2:] for item in self._imports] if only_name else self._imports

    def get_exports(self, only_name=False):
        if self._exports:
            return [item[3] for item in self._exports] if only_name else self._exports
        self._exports = list(idautils.Entries())
        return [item[3] for item in self._exports] if only_name else self._exports

    def save(self, save_path='imports_exports.json', only_name=True):
        save_data = {
            'imports': self.get_imports(only_name),
            'exports': self.get_exports(only_name),
        }
        write_json(save_data, save_path)


if __name__ == '__main__':
    waiting_analysis()
    viewer = IEViewer()
    viewer.save(save_path=get_param(1, 'func_names.json'), only_name=True)
    quit_ida(0)