#/usr/bin/env python
"""This script transforms the structs inside the kernel ABI headers into a define
of an anonymous struct.

eg
  struct abc {int foo;};
becomes
  #define _STRUCT_abc struct {int foo;};

This allows the exact same struct to be included in the provider wrapper struct:

struct abc_resp {
   struct ibv_abc ibv_resp;
   _STRUCT_abc;
};

Which duplicates the struct layout and naming we have historically used, but
sources the data directly from the kernel headers instead of manually copying."""
import re;
import functools;
import sys;

def in_struct(ln,FO,nesting=0):
    """Copy a top level structure over to the #define output, keeping track of
    nested structures."""
    if nesting == 0:
        if re.match(r"(}.*);",ln):
            #未嵌套，遇到结构体结束标记，原样输出，并返回find_struct,继续生成其它结构体
            FO.write(ln[:-1] + "\n\n");
            return find_struct;

    #原样输出
    FO.write(ln + " \\\n");

    #层数加1
    if ln == "struct {" or ln == "union {":
        return functools.partial(in_struct,nesting=nesting+1);

    #层数减1
    if re.match(r"}.*;",ln):
        return functools.partial(in_struct,nesting=nesting-1);
    
    #原样输出
    return functools.partial(in_struct,nesting=nesting);

def find_struct(ln,FO):
    """Look for the start of a top level structure"""
    if ln.startswith("struct ") or ln.startswith("union "):
        #此行以"struct "或者"union "开头，即遇到匹配的行，
        # 针对此行，先通过group提取struct/union的id号，存在group 2中
        # 再通过define来定义宏，用于替换成匿名的结构体或者union定议的首行
        # 并返回in_struct,用于处理结构体内层。
        g = re.match(r"(struct|union)\s+(\S+)\s+{",ln);
        FO.write("#define _STRUCT_%s %s { \\\n"%(g.group(2),g.group(1)));
        #返回结构体内部处理，直接复制
        return in_struct;
    return find_struct;

#打开argv[1]文件用于读取，打开argv[2]文件用于写入
with open(sys.argv[1]) as FI:
    with open(sys.argv[2],"w") as FO:
        state = find_struct;
        #遍历输入文件的每一行
        for ln in FI:
            # Drop obvious comments
            ln = ln.strip();
            ln = re.sub(r"/\*.*\*/","",ln); #移除多行注释
            ln = re.sub(r"//.*$","",ln); #移除行注释
            #调用find_struct，并返回下一行的处理函数
            #这种处理方式为简化的语法解析处理，极简洁
            state = state(ln,FO);
