#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGH 规则合并去重工具 | 深度追踪版
功能：高性能去重 + 自动生成过滤明细日志
"""

import requests
import time
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# --- 基础配置 ---
AGH_RULE_URLS = [
    "https://adrules.top/dns.txt",
    "https://anti-ad.net/easylist.txt",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/AdGuard/Privacy/Privacy.txt",
]
AGH_RULE_NAMES = ["AdRules", "anti-ad", "Privacy"]
AGH_OUTPUT_FILE = "adguard_rules_qx.txt"
REMOVED_LOG_FILE = "removed_details.log"  # 新增：过滤明细日志
TIMEOUT = 30

def create_retry_session():
    session = requests.Session()
    retry = Retry(total=3, backoff_factor=1, status_forcelist=[429, 500, 502, 503, 504])
    session.mount("https://", HTTPAdapter(max_retries=retry))
    return session

def fetch_remote_content(url, source_name):
    start = time.time()
    try:
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0"}
        resp = create_retry_session().get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        lines = resp.text.splitlines()
        print(f"  [✓] 同步完成: {source_name:<10} | 原始规模: {len(lines):>6} 行")
        return lines
    except Exception as e:
        print(f"  [✗] 同步失败: {source_name:<10} | 错误: {type(e).__name__}")
        return []

def apply_containment_dedup(rules, rule_type="规则"):
    """
    ⚡ 高性能包含去重算法
    """
    if not rules:
        return [], []
    
    start_time = time.time()
    initial_count = len(rules)
    
    # 预处理
    processed = []
    for r in rules:
        domain = r.split('$')[0].replace('||', '').replace('@@', '').replace('^', '').lower()
        if domain:
            processed.append((domain, r))
    
    # 按域名层级排序 (a.com 排在 b.a.com 前面)
    processed.sort(key=lambda x: x[0].count('.'))
    
    final_rules = []
    seen_domains = set()
    removed_details = [] 
    
    for dom, original in processed:
        is_subdomain = False
        parts = dom.split('.')
        
        # 逐级向上匹配父域逻辑
        for i in range(len(parts) - 1, 0, -1):
            parent = ".".join(parts[i:])
            if parent in seen_domains:
                is_subdomain = True
                removed_details.append(f"[{rule_type}] {original:<40} # 被父域 [{parent}] 覆盖")
                break
        
        if not is_subdomain:
            final_rules.append(original)
            seen_domains.add(dom)
    
    cost = time.time() - start_time
    print(f"  [✂] {rule_type}过滤: 缩减 {len(removed_details):>6} 条 | 耗时: {cost:.4f}s")
    return final_rules, removed_details

def main():
    main_start = time.time()
    all_raw_rules = []
    
    print("="*80)
    print(f"🚀 AGH 规则自动化处理 | 启动时间: {datetime.now().strftime('%H:%M:%S')}")
    print("="*80)

    # 1. 拉取资源
    for url, name in zip(AGH_RULE_URLS, AGH_RULE_NAMES):
        raw_lines = fetch_remote_content(url, name)
        valid = [l.strip() for l in raw_lines if l.strip() and not l.startswith(('!', '#'))]
        all_raw_rules.extend(valid)

    # 2. 全局基础去重
    unique_rules = list(dict.fromkeys(all_raw_rules))
    print(f"\n[阶段 2] 全局基础去重: 减少 {len(all_raw_rules) - len(unique_rules)} 条重复行")

    # 3. 分类
    white_list = [r for r in unique_rules if r.startswith("@@")]
    black_list = [r for r in unique_rules if r.startswith("||")]
    other_list = [r for r in unique_rules if not (r.startswith("@@") or r.startswith("||"))]

    # 4. 包含去重算法
    print(f"\n[阶段 3] 正在分析域名包含关系并追踪明细...")
    white_final, white_removed = apply_containment_dedup(white_list, "白名单")
    black_final, black_removed = apply_containment_dedup(black_list, "黑名单")

    # 5. 写入规则文件
    final_output = white_final + black_final + other_list
    with open(AGH_OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(final_output))

    # 6. 写入过滤明细日志
    with open(REMOVED_LOG_FILE, 'w', encoding='utf-8') as f:
        f.write(f"# AGH 过滤明细日志 - 生成于 {datetime.now()}\n")
        f.write(f"# 总计过滤: {len(white_removed) + len(black_removed)} 条\n")
        f.write("="*80 + "\n")
        f.write('\n'.join(white_removed + black_removed))

    print("\n" + "="*80)
    print(f"🏆 处理完成!")
    print(f"   - 最终文件: {AGH_OUTPUT_FILE} ({len(final_output)} 条)")
    print(f"   - 过滤日志: {REMOVED_LOG_FILE} (请去此文件查看被删规则)")
    print(f"   - 总计用时: {time.time() - main_start:.2f} 秒")
    print("="*80)

if __name__ == "__main__":
    main()
