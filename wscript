# Build script based on examples from the NodeJS docs and
# from node-rsa

import Options
import shutil
from os import chmod, mkdir
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
    obj.source = 'src/rsabNative.cc'

def shutdown():
    dir = 'bin'
    target = 'rsabNative.node'
    dirTarget = dir + '/' + target
    if Options.commands['clean']:
        if exists(dir): shutil.rmtree(dir)
        if exists('build'): shutil.rmtree('build')
    if Options.commands['build']:
        if not exists(dir): mkdir(dir)
        if exists('build/default/' + target):
            shutil.copyfile('build/default/' + target, dirTarget)
        if exists('build/Release/' + target):
            shutil.copyfile('build/Release/' + target, dirTarget)
        if exists(dirTarget):
            chmod(dirTarget, 0755)
