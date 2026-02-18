#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGH 规则合并去重工具 | 高性能异步逻辑版
优化：引入层级哈希算法，处理数万条规则仅需秒级
"""

import requests
import time
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- 配置区 ---
AGH_RULE_URLS = [
    "https://adrules.top/dns.txt",
    "https://anti-ad.net/easylist.txt",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/AdGuard/Privacy/Privacy.txt",
]
AGH_RULE_NAMES = ["AdRules", "anti-ad", "Privacy"]
AGH_OUTPUT_FILE = "adguard_rules_qx.txt"
SUBSCRIBE_URL = "https://ddcm1349.github.io/AGH/adguard_rules_qx.txt"
TIMEOUT = 30

def create_retry_session():
    """创建带重试机制的请求会话"""
    session = requests.Session()
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    return session

def fetch_remote_content(url, source_name):
    """拉取远程规则"""
    try:
        print(f"📥 正在拉取【{source_name}】...")
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        resp = create_retry_session().get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        print(f"✅ 成功 | 原始行数: {len(lines)}")
        return lines
    except Exception as e:
        print(f"❌ 失败 | {source_name}: {str(e)}")
        return []

def count_rule_types(rule_list):
    """统计黑白名单数量"""
    black = sum(1 for r in rule_list if r.startswith("||"))
    white = sum(1 for r in rule_list if r.startswith("@@"))
    other = len(rule_list) - black - white
    return black, white, other

def apply_containment_dedup(rules, rule_type="规则"):
    """
    ⚡ 高性能包含去重算法
    逻辑：按域名层级排序，利用 set 记录父域，实现子域秒级剪枝
    """
    if not rules:
        return [], 0
    
    start_time = time.time()
    # 预处理：提取域名关键部分并记录原始规则
    processed = []
    for r in rules:
        # 移除修饰符，仅提取域名主体进行逻辑判断
        domain = r.split('$')[0].replace('||', '').replace('@@', '').replace('^', '').lower()
        if domain:
            processed.append((domain, r))
    
    # 核心：按域名点号数量排序（短域名/父域名排在前面）
    processed.sort(key=lambda x: x[0].count('.'))
    
    final_rules = []
    seen_domains = set() # 哈希集合，查找效率 O(1)
    
    for dom, original in processed:
        is_subdomain = False
        parts = dom.split('.')
        # 逐层向上查找父域名是否已在集合中
        # 例如: www.example.com 会查找 example.com 和 com
        for i in range(len(parts) - 1, 0, -1):
            parent = ".".join(parts[i:])
            if parent in seen_domains:
                is_subdomain = True
                break
        
        if not is_subdomain:
            final_rules.append(original)
            seen_domains.add(dom)
    
    end_time = time.time()
    removed = len(rules) - len(final_rules)
    print(f"✂️ {rule_type}包含去重完成 | 耗时: {end_time - start_time:.2f}s | 去除: {removed} 条")
    return final_rules, removed

def main():
    total_start = time.time()
    all_raw_rules = []
    source_stats = []
    
    print("="*60 + "\n🚀 开启 AGH 规则自动化合并处理\n" + "="*60)

    # 1. 分块拉取与初步清洗
    for url, name in zip(AGH_RULE_URLS, AGH_RULE_NAMES):
        raw_lines = fetch_remote_content(url, name)
        valid_rules = [line.strip() for line in raw_lines if line.strip() and not line.startswith(('!', '#'))]
        
        # 记录源信息
        b, w, o = count_rule_types(valid_rules)
        source_stats.append({
            "name": name, "total": len(valid_rules), 
            "black": b, "white": w, "other": o, "raw": len(raw_lines)
        })
        all_raw_rules.extend(valid_rules)

    # 2. 全局基础去重 (去除完全相同的行)
    unique_rules = list(dict.fromkeys(all_raw_rules))
    cross_dedup = len(all_raw_rules) - len(unique_rules)
    print(f"\n🔄 全局去重: {len(all_raw_rules)} -> {len(unique_rules)} (去除重复: {cross_dedup})")

    # 3. 分类存储
    white_list = [r for r in unique_rules if r.startswith("@@")]
    black_list = [r for r in unique_rules if r.startswith("||")]
    other_list = [r for r in unique_rules if not (r.startswith("@@") or r.startswith("||"))]

    # 4. 执行高性能包含去重
    white_final, w_rem = apply_containment_dedup(white_list, "白名单")
    black_final, b_rem = apply_containment_dedup(black_list, "黑名单")

    # 5. 合并结果
    final_output = white_final + black_final + other_list
    final_count = len(final_output)
    
    # 6. 生成 Header 并写入文件
    beijing_time = (datetime.utcnow() + timedelta(hours=8)).strftime('%Y-%m-%d %H:%M:%S')
    
    stats_lines = [f"#   {i+1}. {s['name']} | 原始:{s['total']} (黑:{s['black']} 白:{s['white']})" for i, s in enumerate(source_stats)]
    
    header = [
        "!", f"! AGH 规则合并 (高性能去重版)",
        f"! 生成时间: {beijing_time} (北京时间)",
        f"! 最终总数: {final_count} 条",
        "! " + "="*50,
        "! 各源统计:",
        *stats_lines,
        "! " + "="*50,
        f"! 去重汇总: 基础去重 {cross_dedup} | 包含去重(黑) {b_rem} | 包含去重(白) {w_rem}",
        "! " + "="*50,
        ""
    ]

    with open(AGH_OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header + final_output))

    total_end = time.time()
    print("\n" + "="*60)
    print(f"✨ 处理完成！生成文件: {AGH_OUTPUT_FILE}")
    print(f"⏱️ 总运行耗时: {total_end - total_start:.2f} 秒")
    print(f"📊 最终规模: {final_count} 条规则")
    print("="*60)

if __name__ == "__main__":
    main()
