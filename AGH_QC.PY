#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AGH规则合并去重工具 | 全功能自动化版
📊 统计维度：黑/白/其他规则精准统计，总数完全匹配
📍 订阅配置：规则源+自有订阅地址，注释序号3专属展示
✂️ 去重逻辑：源内去重+跨源全局去重+包含去重，全程保留规则顺序
🌐 网络适配：带重试机制的网络请求，抗波动拉取更稳定
📝 注释格式：自定义规范注释，规则文件内统计信息完整
🖥️ 日志输出：GH Actions日志完整打印，关键统计一键查看
⏰ 时间同步：生成时间自动转换北京时间，无时区偏差
"""


# —— 模块导入区 ——
import requests
from datetime import datetime, timedelta
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


# —— 核心配置区 ——
AGH_RULE_URLS = [
    "https://adrules.top/dns.txt",
    "https://anti-ad.net/easylist.txt",
    "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/AdGuard/Privacy/Privacy.txt",
   # "https://raw.githubusercontent.com/blackmatrix7/ios_rule_script/master/rule/AdGuard/Advertising/Advertising.txt"
]
AGH_RULE_NAMES = [
    "AdRules",
    "anti-ad",
    "Privacy",
    #"Advertising"
]
AGH_OUTPUT_FILE = "adguard_rules_qx.txt"
SUBSCRIBE_URL = "https://ddcm1349.github.io/AGH/adguard_rules_qx.txt"
TIMEOUT = 30


# —— 工具函数区 ——
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
# 新增：包含去重函数（版本1：任意后缀匹配）
# ============================================
def apply_containment_dedup(rules):
    """
    对规则列表应用包含去重（后缀匹配模式）：
    - 如果规则A的域名是规则B的域名的后缀，则删除规则B（因为A已包含B）
    - 保留修饰符（$后面的内容不参与比较）
    - 保持原始顺序
    例如：||b.com^ 包含 ||a.b.com^，删除 ||a.b.com^
    """
    if not rules:
        return []
    
    def extract_domain(rule):
        """提取域名主体（移除修饰符和AGH前缀）"""
        # 分离修饰符
        main_part = rule.split('$')[0] if '$' in rule else rule
        # 移除AGH前缀
        if main_part.startswith('||') or main_part.startswith('@@'):
            main_part = main_part[2:]
        # 移除 ^ 结尾
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
    
    # 包含去重：如果短域名是长域名的后缀，则移除长域名
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
            
            # 检查后缀关系（版本1：任意后缀匹配）
            # domain_i 包含 domain_j：domain_j 以 .domain_i 结尾，或两者相等
            if domain_j == domain_i:
                to_remove.add(j)  # 完全重复
            elif domain_j.endswith('.' + domain_i):
                to_remove.add(j)  # j 被 i 包含（i是j的后缀）
            elif domain_i.endswith('.' + domain_j):
                to_remove.add(i)  # i 被 j 包含（j是i的后缀）
                break  # i 已被移除，无需继续比较
    
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
    all_deduped_rules = []


    print("="*80 + "\n📦 开始处理【所有AGH规则源】\n" + "="*80)
    for idx, (url, name) in enumerate(zip(AGH_RULE_URLS, AGH_RULE_NAMES), 1):
        print(f"\n🔸 正在处理第{idx}个规则源: {name}")
        stats, _, deduped = process_single_rule_source(url, name)
        source_stats_list.append({"name": name, "url": url, **stats})
        if deduped:
            total_stats["raw_line"] += stats["raw_line"]
            total_stats["skip"] += stats["skip"]
            total_stats["total_rule"] += stats["total_rule"]
            total_stats["inner_dedup"] += stats["inner_dedup"]
            total_stats["total_black"] += stats["black"]
            total_stats["total_white"] += stats["white"]
            total_stats["total_other"] += stats["other"]
            all_deduped_rules.extend(deduped)


    # ============================================
    # 新增：分离黑白名单，分别进行包含去重
    # ============================================
    # 1. 分离黑白名单和其他规则
    white_rules = [r for r in all_deduped_rules if r.startswith("@@")]
    black_rules = [r for r in all_deduped_rules if r.startswith("||")]
    other_rules = [r for r in all_deduped_rules if not r.startswith(("@@", "||"))]
    
    # 2. 黑白名单各自进行包含去重（互不干扰）
    white_rules_deduped, white_containment_dedup = apply_containment_dedup(white_rules)
    black_rules_deduped, black_containment_dedup = apply_containment_dedup(black_rules)
    # 其他规则不做包含去重（保持原样）
    
    # 3. 合并：白名单在前，黑名单在后，其他规则最后
    all_deduped_rules = white_rules_deduped + black_rules_deduped + other_rules


    # 全局跨源去重统计（基于已有逻辑）
    all_deduped_rules = [r for r in list(dict.fromkeys(all_deduped_rules)) if r.strip()]
    final_total = len(all_deduped_rules)
    final_black, final_white, final_other = count_rule_types(all_deduped_rules)
    cross_dedup = total_stats["total_rule"] - final_total
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
        f.write('\n'.join(header + all_deduped_rules))


    print("\n" + "="*80)
    print(f"✅ AGH规则合并去重完成！生成文件：{AGH_OUTPUT_FILE}")
    print(f"🕒 生成时间（北京时间）：{beijing_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 规则引用链接：https://raw.githubusercontent.com/ddcm1349/AGH/main/{AGH_OUTPUT_FILE}")
    print("="*80)
    print(f"📊 【规则源汇总】 | 原始总行数：{total_stats['raw_line']} 条 | 跳过无效行：{total_stats['skip']} 条")
    print(f"📊 【有效规则统计】| 总有效规则：{total_stats['total_rule']} 条 | 源内去重：{total_stats['inner_dedup']} 条")
    print(f"📊 【黑白规则汇总】| 总黑名单：{total_stats['total_black']} 条 | 总白名单：{total_stats['total_white']} 条 | 其他规则：{total_stats['total_other']} 条")
    print(f"📊 【包含去重统计】| 白名单去重：{white_containment_dedup} 条 | 黑名单去重：{black_containment_dedup} 条")
    print(f"📊 【全局最终统计】| 跨源去重数：{cross_dedup} 条 | 最终保留总数：{final_total} 条")
    print(f"📊 【最终黑白分布】| 黑名单：{final_black} 条 | 白名单：{final_white} 条 | 其他规则：{final_other} 条")
    print("="*80)


if __name__ == "__main__":
    main()
