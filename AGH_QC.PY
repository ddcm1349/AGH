#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGH规则合并去重工具 | 全功能自动化版
"""


import requests
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


AGH_RULE_URLS = [
    "https://adrules.top/dns.txt",
    "https://anti-ad.net/easylist.txt",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/AdGuard/Privacy/Privacy.txt",
]
AGH_RULE_NAMES = [
    "AdRules",
    "anti-ad",
    "Privacy",
]
AGH_OUTPUT_FILE = "adguard_rules_qx.txt"
SUBSCRIBE_URL = "https://ddcm1349.github.io/AGH/adguard_rules_qx.txt"
TIMEOUT = 30


def create_retry_session():
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
    try:
        print(f"\n📥 拉取【{source_name}】: {url}")
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"}
        resp = create_retry_session().get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        content = resp.text
        raw_line = len(content.splitlines())
        print(f"✅ 拉取成功 | 原始总行数: {raw_line}")
        return content, raw_line
    except Exception as e:
        print(f"❌ 拉取失败 | 错误: {type(e).__name__} - {str(e)}")
        return "", 0


def count_rule_types(rule_list):
    black, white, other = 0, 0, 0
    for r in rule_list:
        r = r.strip()
        if not r: continue
        if r.startswith("@@"):
            white += 1
        elif r.startswith("||"):
            black += 1
        else:
            other += 1
    return black, white, other


def process_single_rule_source(url, source_name):
    content, raw_line_count = fetch_remote_content(url, source_name)
    if not content:
        return {}, [], []
    lines, valid, skip = content.splitlines(), [], 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith(('!', '#', '!#')):
            skip += 1
            continue
        valid.append(line)
    valid_cnt = len(valid)
    black, white, other = count_rule_types(valid)
    deduped = list(dict.fromkeys(valid))
    inner_dedup = valid_cnt - len(deduped)
    stats = {
        "raw_line": raw_line_count,
        "skip": skip,
        "total_rule": valid_cnt,
        "inner_dedup": inner_dedup,
        "black": black,
        "white": white,
        "other": other
    }
    print(f"📊 【{source_name}】| 总规则: {valid_cnt}条 | 黑: {black} | 白: {white} | 其他: {other}")
    return stats, valid, deduped


# ============================================
# 新增：包含去重函数
# ============================================
def apply_containment_dedup(rules):
    """
    对规则列表应用包含去重（后缀匹配模式）
    """
    if not rules:
        return [], 0
    
    def extract_domain(rule):
        """提取域名主体（移除修饰符和AGH前缀）"""
        main_part = rule.split('$')[0] if '$' in rule else rule
        if main_part.startswith('||') or main_part.startswith('@@'):
            main_part = main_part[2:]
        if main_part.endswith('^'):
            main_part = main_part[:-1]
        return main_part.lower()
    
    # 构建规则信息列表
    rule_infos = []
    for rule in rules:
        domain = extract_domain(rule)
        rule_infos.append({
            'original': rule,
            'domain': domain
        })
    
    # 包含去重
    to_remove = set()
    n = len(rule_infos)
    
    for i in range(n):
        if i in to_remove:
            continue
        domain_i = rule_infos[i]['domain']
        for j in range(i + 1, n):
            if j in to_remove:
                continue
            domain_j = rule_infos[j]['domain']
            
            # 检查后缀关系
            if domain_j == domain_i:
                to_remove.add(j)
            elif domain_j.endswith('.' + domain_i):
                to_remove.add(j)
            elif domain_i.endswith('.' + domain_j):
                to_remove.add(i)
                break
    
    # 保留未被移除的规则，保持原始顺序
    result = [rule_infos[i]['original'] for i in range(n) if i not in to_remove]
    removed_count = len(to_remove)
    return result, removed_count


# —— 主逻辑区 ——
def main():
    source_stats_list = []
    total_stats = {
        "raw_line":0, "skip":0, "total_rule":0, "inner_dedup":0,
        "total_black":0, "total_white":0, "total_other":0
    }
    all_rules = []  # 收集所有规则（未去重）


    print("="*80 + "\n📦 开始处理【所有AGH规则源】\n" + "="*80)
    for idx, (url, name) in enumerate(zip(AGH_RULE_URLS, AGH_RULE_NAMES), 1):
        print(f"\n🔸 正在处理第{idx}个规则源: {name}")
        stats, valid, deduped = process_single_rule_source(url, name)
        source_stats_list.append({"name": name, "url": url, **stats})
        if deduped:
            total_stats["raw_line"] += stats["raw_line"]
            total_stats["skip"] += stats["skip"]
            total_stats["total_rule"] += stats["total_rule"]
            total_stats["inner_dedup"] += stats["inner_dedup"]
            total_stats["total_black"] += stats["black"]
            total_stats["total_white"] += stats["white"]
            total_stats["total_other"] += stats["other"]
            all_rules.extend(deduped)  # 使用源内去重后的规则


    # ============================================
    # 步骤1：全局去重（跨源去重）
    # ============================================
    all_rules_global_dedup = list(dict.fromkeys(all_rules))
    cross_dedup = len(all_rules) - len(all_rules_global_dedup)
    print(f"\n🔄 全局去重: {len(all_rules)} → {len(all_rules_global_dedup)} (去除 {cross_dedup} 条)")


    # ============================================
    # 步骤2：分离黑白名单
    # ============================================
    white_rules = []
    black_rules = []
    other_rules = []
    
    for r in all_rules_global_dedup:
        if r.startswith("@@"):
            white_rules.append(r)
        elif r.startswith("||"):
            black_rules.append(r)
        else:
            other_rules.append(r)
    
    print(f"📋 分离结果 - 白:{len(white_rules)} 黑:{len(black_rules)} 其他:{len(other_rules)}")


    # ============================================
    # 步骤3：各自进行包含去重（互不干扰）
    # ============================================
    white_rules_final, white_containment_dedup = apply_containment_dedup(white_rules)
    black_rules_final, black_containment_dedup = apply_containment_dedup(black_rules)
    # 其他规则不做包含去重
    
    print(f"✂️ 包含去重 - 白:{len(white_rules)}→{len(white_rules_final)}(去{white_containment_dedup}) 黑:{len(black_rules)}→{len(black_rules_final)}(去{black_containment_dedup})")


    # ============================================
    # 步骤4：合并 - 白名单在前，黑名单在后，其他规则最后
    # ============================================
    final_rules = white_rules_final + black_rules_final + other_rules
    
    # 统计
    final_total = len(final_rules)
    final_black, final_white, final_other = count_rule_types(final_rules)
    source_merged_total = total_stats["total_rule"] - total_stats["inner_dedup"]


    beijing_time = datetime.now() + timedelta(hours=8)
    
    source_stats_lines = []
    for i, stat in enumerate(source_stats_list, 1):
        source_stats_lines.append(
            f"#   {i}. {stat['name']} | 总规则数：{stat['total_rule']} 条 | "
            f"黑名单：{stat['black']} 条 | 白名单：{stat['white']} 条 | 其他规则：{stat['other']} 条"
        )
    
    header = [
        f"# AGH规则合并 (多源去重+包含去重)",
        f"# 生成时间（北京时间）: {beijing_time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# 订阅地址：{SUBSCRIBE_URL}",
        f"# ==============================================================================",
        f"# 【各规则源单独统计】",
        *source_stats_lines,
        f"# ==============================================================================",
        f"# 【全局合并统计】",
        f"# 原始总行数：{total_stats['raw_line']} 条 | 跳过无效行：{total_stats['skip']} 条",
        f"# 源内合并后总数：{source_merged_total}条 | 黑{total_stats['total_black']}条 | 白{total_stats['total_white']}条 | 其他{total_stats['total_other']}条",
        f"# 跨源重复去重数：{cross_dedup} 条 | 包含去重(白)：{white_containment_dedup} 条 | 包含去重(黑)：{black_containment_dedup} 条",
        f"# 最终全局保留总数：{final_total} 条 | 黑名单{final_black}条 | 白名单{final_white}条 | 其他规则{final_other}条",
        f"# ==============================================================================",
        f""
    ]


    with open(AGH_OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write('\n'.join(header + final_rules))


    print("\n" + "="*80)
    print(f"✅ AGH规则合并去重完成！生成文件：{AGH_OUTPUT_FILE}")
    print(f"🕒 生成时间（北京时间）：{beijing_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 规则引用链接：https://raw.githubusercontent.com/ddcm1349/AGH/main/{AGH_OUTPUT_FILE}")
    print("="*80)
    print(f"📊 【规则源汇总】 | 原始总行数：{total_stats['raw_line']} 条 | 跳过无效行：{total_stats['skip']} 条")
    print(f"📊 【有效规则统计】| 总有效规则：{total_stats['total_rule']} 条 | 源内去重：{total_stats['inner_dedup']} 条")
    print(f"📊 【黑白规则汇总】| 总黑名单：{total_stats['total_black']} 条 | 总白名单：{total_stats['total_white']} 条 | 其他规则：{total_stats['total_other']} 条")
    print(f"📊 【全局去重统计】| 跨源去重：{cross_dedup} 条")
    print(f"📊 【包含去重统计】| 白名单去重：{white_containment_dedup} 条 | 黑名单去重：{black_containment_dedup} 条")
    print(f"📊 【全局最终统计】| 最终保留总数：{final_total} 条")
    print(f"📊 【最终黑白分布】| 黑名单：{final_black} 条 | 白名单：{final_white} 条 | 其他规则：{final_other} 条")
    print("="*80)


if __name__ == "__main__":
    main()
