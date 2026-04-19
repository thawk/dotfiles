#!/usr/bin/env python3

import re
import argparse
import os
import unicodedata

# --- 配置区：在此统一管理列信息 ---
# (列名, 视觉宽度, 对齐方式 'L' 或 'R')
COL_CONFIG = [
    ("#",         2,  'R'),
    ("章节标题", 30, 'L'),
    ("字数",      5,  'R'),
    ("秒数",      5,  'R'),
    ("单节用时",  8, 'R'),
    ("累计时间",  8, 'R'),
]

def get_visible_width(text):
    """计算文本在终端的视觉宽度（汉字2，英文1）"""
    width = 0
    for char in str(text):
        if unicodedata.east_asian_width(char) in ('W', 'F'):
            width += 2
        else:
            width += 1
    return width

def smart_pad(text, target_width, align='L'):
    """根据视觉宽度进行对齐填充"""
    text = str(text)
    current_w = get_visible_width(text)
    if current_w >= target_width:
        return text
    
    spaces = ' ' * (target_width - current_w)
    return text + spaces if align == 'L' else spaces + text

def format_row(data_list):
    """根据 COL_CONFIG 自动格式化一行数据"""
    formatted_parts = []
    for i, item in enumerate(data_list):
        # 如果超出配置列数则忽略
        if i >= len(COL_CONFIG): break
        name, width, align = COL_CONFIG[i]
        formatted_parts.append(smart_pad(item, width, align))
    return " | ".join(formatted_parts)

def get_separator_row():
    """生成按列分隔的横线"""
    parts = ["-" * width for _, width, _ in COL_CONFIG]
    return " | ".join(parts)

def format_time(total_seconds):
    minutes = int(total_seconds // 60)
    seconds = int(total_seconds % 60)
    return f"{minutes:02d}:{seconds:02d}"

def count_words_unicode(text):
    count = 0
    in_word = False
    for char in text:
        cat = unicodedata.category(char)
        if 'Lo' in cat and ord(char) > 0x2E80:
            count += 1
            in_word = False 
        elif cat.startswith('L') or cat.startswith('N'):
            if not in_word:
                count += 1
                in_word = True
        else:
            in_word = False
    return count

def analyze_markdown(file_path, wpm):
    if not os.path.exists(file_path):
        print(f"错误: 找不到文件 '{file_path}'")
        return

    with open(file_path, 'r', encoding='utf-8') as f:
        raw_content = f.read()

    # 1. 移除 YAML 头
    content = re.sub(r'^---\s*\n.*?\n---\s*\n', '', raw_content, flags=re.DOTALL)

    # 2. 切割标题
    # 过滤掉空字符串
    sections = [s.strip() for s in re.split(r'\n(?=#+\s+)', '\n' + content.strip()) if s.strip()]
    
    # 输出表头
    print(format_row([col[0] for col in COL_CONFIG]))
    print(get_separator_row())

    total_words = 0
    running_total_seconds = 0

    for idx, section in enumerate(sections, 1):
        lines = section.split('\n')
        first_line = lines[0]
        
        if re.match(r'^#+\s+', first_line):
            title_name = re.sub(r'^#+\s+', '', first_line).strip()
            body_text = "\n".join(lines[1:])
        else:
            title_name = "（开头正文）"
            body_text = section

        # 字数与时间计算
        word_count = count_words_unicode(body_text)
        section_seconds = (word_count / wpm) * 60
        total_words += word_count
        running_total_seconds += section_seconds
        
        # 标题长度截断处理 (根据 COL_CONFIG 中的第二列宽度)
        max_title_w = COL_CONFIG[1][1]
        if get_visible_width(title_name) > max_title_w:
            temp_title, temp_w = "", 0
            for c in title_name:
                cw = 2 if unicodedata.east_asian_width(c) in ('W', 'F') else 1
                if temp_w + cw > max_title_w - 3:
                    temp_title += "..."
                    break
                temp_title += c
                temp_w += cw
            title_name = temp_title

        # 使用封装好的函数输出行，idx 转为两位数格式
        print(format_row([
            f"{idx:02d}",
            title_name,
            word_count,
            int(section_seconds),
            format_time(section_seconds),
            format_time(running_total_seconds)
        ]))

    # 底部总计
    print(get_separator_row())
    print(format_row([
        "/",
        "总计",
        total_words,
        int(running_total_seconds),
        format_time(running_total_seconds),
        format_time(running_total_seconds)
    ]))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Markdown 章节字数统计、演讲耗时估算工具")
    parser.add_argument("file", help="Markdown 文件路径")
    parser.add_argument("-s", "--speed", type=int, default=170, help="语速 (字/分钟)")
    args = parser.parse_args()
    analyze_markdown(args.file, args.speed)
