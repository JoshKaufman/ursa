# Build script based on examples from the NodeJS docs and
# from node-rsa

import Options
from os import unlink, symlink
from os.path import exists

srcdir = '.'
blddir = 'build'
VERSION = '0.0.1'

def set_options(opt):
    opt.tool_options('compiler_cxx')

def configure(conf):
    conf.check_tool('compiler_cxx')
    conf.check_tool('node_addon')

def build(bld):
    obj = bld.new_task_gen('cxx', 'shlib', 'node_addon')
    obj.target = 'rsabNative'
    obj.source = 'rsabNative.cc'

def shutdown():
    target = 'rsabNative.node'
    if Options.commands['clean']:
        if exists(target): unlink(target)
    if Options.commands['build']:
        if exists('build/default/' + target) and not exists(target):
            symlink('build/default/' + target, target)
        if exists('build/Release/' + target) and not exists(target):
            symlink('build/Release/' + target, target)
