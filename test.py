import os
import shutil

def copy_files_to_root(dir_name):
    # 获取dir_name下的所有子目录
    subdirs = [name for name in os.listdir(dir_name) if os.path.isdir(os.path.join(dir_name, name))]
    # 如果没有子目录，直接返回
    if not subdirs:
        return

    # 取第一个子目录作为多出的那一层目录
    subdir = subdirs[0]

    source_dir = os.path.join(dir_name, subdir, 'UserData', 'chara', 'female')
    target_dir = dir_name

    if not os.path.exists(source_dir):
        return

    for file_name in os.listdir(source_dir):
        source_file = os.path.join(source_dir, file_name)
        target_file = os.path.join(target_dir, file_name)

        shutil.copy(source_file, target_file)
        print(f'已从 {source_file} 拷贝到 {target_file}')

# 获取当前目录下的所有文件和文件夹
for name in os.listdir('.'):
    # 如果是目录，则执行操作
    if os.path.isdir(name):
        copy_files_to_root(name)