#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
-----------------File Info-----------------------
Name: gen_imports_exports.py
Description:
Author: GentleCP
Email: me@gentlecp.com
Create Date: 6/15/22
-----------------End-----------------------------
"""
import idaapi
import idautils
from utils import write_json


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

    def save(self, save_path='imports_exports.json', only_name=False):
        if only_name:
            save_data = {
                'imports': [item[2:] for item in self.get_imports()],
                'exports': [item[3] for item in self.get_exports()],
            }
        else:
            save_data = {
                'imports': self.get_imports(),
                'exports': self.get_exports(),
            }

        write_json(save_data, save_path)


if __name__ == '__main__':
    viewer = IEViewer()
    viewer.save(only_name=True)
