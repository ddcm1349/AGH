#!/usr/bin/env python3  # Python3解释器声明
# -*- coding: utf-8 -*-  # UTF-8编码（支持中文注释/日志，避免乱码）
"""
AGH规则合并去重工具 | 全功能自动化版
📊 统计维度：黑/白/其他规则精准统计，总数完全匹配
📍 订阅配置：规则源+自有订阅地址，注释序号3专属展示
✂️ 去重逻辑：源内去重+跨源全局去重，全程保留规则顺序
🌐 网络适配：带重试机制的网络请求，抗波动拉取更稳定
📝 注释格式：自定义规范注释，规则文件内统计信息完整
🖥️ 日志输出：GH Actions日志完整打印，关键统计一键查看
⏰ 时间同步：生成时间自动转换北京时间，无时区偏差
"""


# —— 模块导入区 ——
import requests                          # 发送网络请求，拉取远程规则文件
from datetime import datetime, timedelta # 时间处理，UTC转北京时间/生成日志时间
from requests.adapters import HTTPAdapter # 配置requests请求适配器，实现重试挂载
from urllib3.util.retry import Retry     # 定义网络请求重试策略，解决临时网络波动


# —— 核心配置区 ——
# 待合并的远程AGH规则源地址（与下方名称一一对应，可按需增删）
AGH_RULE_URLS = [
     "https://adrules.top/dns.txt",
     "https://anti-ad.net/easylist.txt"
]
# 规则源名称（用于日志打印、规则文件注释展示，方便溯源）
AGH_RULE_NAMES = [
    "AdRules",
    "anti-ad"
]
AGH_OUTPUT_FILE = "adguard_rules.txt"    # 合并去重后生成的本地规则文件名
SUBSCRIBE_URL = "https://ddcm1349.github.io/AGH/adguard_rules.txt"  # 自有规则订阅地址
TIMEOUT = 30                             # 网络请求超时时间（单位：秒），超时则触发重试


# —— 工具函数区 ——
def create_retry_session():
    """创建带重试机制的requests会话
    作用：解决网络波动、服务器临时不可达问题，自动重试GET请求，提升规则拉取成功率
    返回：配置好重试策略的会话对象
    """
    session = requests.Session()
    # 重试策略配置：3次最大重试、1秒基础间隔、指定异常状态码重试
    retry = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"]
    )
    # 为HTTPS/HTTP请求挂载重试适配器，让会话拥有重试能力
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))
    return session


def fetch_remote_content(url, source_name):
    """拉取远程规则源内容并统计原始行数
    参数：
        url: 远程规则源的网络地址
        source_name: 规则源名称（用于日志打印，方便定位拉取结果）
    返回：
        成功：拉取到的规则内容（字符串）、规则文件原始总行数
        失败：空字符串、0（触发异常时返回）
    """
    try:
        print(f"\n📥 拉取【{source_name}】: {url}")
        # 模拟浏览器请求头，避免部分服务器拒绝爬虫类型请求
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36"}
        # 使用带重试的会话发送GET请求，设置超时时间
        resp = create_retry_session().get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()  # 校验HTTP请求状态，非200系列直接触发异常
        
        content = resp.text  # 获取规则文件的文本内容
        raw_line = len(content.splitlines())  # 统计原始总行数（按换行符分割）
        print(f"✅ 拉取成功 | 原始总行数: {raw_line}")
        return content, raw_line
    
    except Exception as e:
        # 捕获所有异常（网络超时、连接失败、服务器错误等），打印错误信息
        print(f"❌ 拉取失败 | 错误: {type(e).__name__} - {str(e)}")
        return "", 0


def count_rule_types(rule_list):
    """按AGH语法统计规则类型，确保 黑名单+白名单+其他规则 = 总有效规则数
    AGH语法规则：@@开头=白名单，||开头=黑名单，其余归为其他规则（正则/IP段等）
    参数：rule_list - 待统计的有效规则列表（已过滤空行/注释行）
    返回：黑名单数量、白名单数量、其他规则数量
    """
    black, white, other = 0, 0, 0
    for r in rule_list:
        r = r.strip()  # 去除规则前后空格/换行符，避免空字符影响判断
        if not r: continue  # 跳过空行，不参与统计
        
        if r.startswith("@@"):
            white += 1
        elif r.startswith("||"):
            black += 1
        else:
            other += 1  # 正则表达式、IP段、特殊语法规则等
    return black, white, other


def process_single_rule_source(url, source_name):
    """处理单个规则源全流程：拉取→过滤无效行→统计类型→源内去重
    参数：
        url: 远程规则源地址
        source_name: 规则源名称
    返回：
        成功：规则源统计信息（字典）、原始有效规则列表、源内去重后规则列表
        失败：空字典、空列表、空列表（拉取失败时返回）
    """
    # 拉取远程规则内容
    content, raw_line_count = fetch_remote_content(url, source_name)
    if not content:  # 拉取失败则直接返回空值
        return {}, [], []
    
    # 过滤无效行：空行、以!/#/!#开头的注释行（AGH注释规范为!，兼容#注释）
    lines, valid, skip = content.splitlines(), [], 0
    for line in lines:
        line = line.strip()
        if not line or line.startswith(('!', '#', '!#')):
            skip += 1  # 无效行计数器+1
            continue
        valid.append(line)  # 有效规则加入列表
    
    # 统计有效规则总数+规则类型，执行源内去重（保持规则顺序）
    valid_cnt = len(valid)
    black, white, other = count_rule_types(valid)
    deduped = list(dict.fromkeys(valid))  # 字典去重法：保留规则原始顺序
    inner_dedup = valid_cnt - len(deduped)  # 统计源内重复规则数量
    
    # 整理当前规则源的全量统计信息，方便后续全局汇总
    stats = {
        "raw_line": raw_line_count,  # 原始总行数
        "skip": skip,                # 过滤的无效行数量
        "total_rule": valid_cnt,     # 有效规则总数
        "inner_dedup": inner_dedup,  # 源内去重数量
        "black": black,              # 黑名单规则数
        "white": white,              # 白名单规则数
        "other": other               # 其他规则数
    }
    # 打印当前规则源的统计日志，方便查看单源处理结果
    print(f"📊 【{source_name}】| 总规则: {valid_cnt}条 | 黑: {black} | 白: {white} | 其他: {other}")
    return stats, valid, deduped


# —— 主逻辑区 ——
def main():
    """脚本核心执行逻辑：按流程完成多规则源的合并、去重、统计、文件生成
    执行步骤：初始化容器→处理所有规则源→全局跨源去重→生成头部注释→写入文件→打印最终日志
    """
    # 初始化数据存储容器，用于保存统计信息和规则内容
    source_stats_list = []  # 存储每个规则源的详细统计信息（用于生成规则文件注释）
    # 存储所有规则源的全局汇总统计信息
    total_stats = {
        "raw_line":0, "skip":0, "total_rule":0, "inner_dedup":0,
        "total_black":0, "total_white":0, "total_other":0
    }
    all_deduped_rules = []  # 存储所有规则源去重后的规则，用于后续全局跨源去重


    # 步骤1：遍历处理所有规则源，完成拉取、过滤、统计、源内去重，并汇总数据
    print("="*80 + "\n📦 开始处理【所有AGH规则源】\n" + "="*80)
    for idx, (url, name) in enumerate(zip(AGH_RULE_URLS, AGH_RULE_NAMES), 1):
        print(f"\n🔸 正在处理第{idx}个规则源: {name}")
        stats, _, deduped = process_single_rule_source(url, name)
        # 将当前规则源的统计信息加入列表，后续生成注释使用
        source_stats_list.append({"name": name, "url": url, **stats})
        
        # 若当前规则源处理成功（去重后规则非空），则汇总到全局统计
        if deduped:
            total_stats["raw_line"] += stats["raw_line"]
            total_stats["skip"] += stats["skip"]
            total_stats["total_rule"] += stats["total_rule"]
            total_stats["inner_dedup"] += stats["inner_dedup"]
            total_stats["total_black"] += stats["black"]
            total_stats["total_white"] += stats["white"]
            total_stats["total_other"] += stats["other"]
            all_deduped_rules.extend(deduped)  # 合并源内去重后的规则到全局列表


    # 步骤2：全局跨源去重，过滤空行，统计最终规则数量和类型
    all_deduped_rules = [r for r in list(dict.fromkeys(all_deduped_rules)) if r.strip()]
    final_total = len(all_deduped_rules)  # 全局去重后的最终规则总数
    # 统计最终规则的类型分布
    final_black, final_white, final_other = count_rule_types(all_deduped_rules)
    cross_dedup = total_stats["total_rule"] - final_total  # 统计跨源重复规则数量
    # 统计所有源内去重后的规则总数
    source_merged_total = total_stats["total_rule"] - total_stats["inner_dedup"]


    # 步骤3：生成北京时间，构建规则文件的头部注释（含统计信息/订阅地址/规则源）
    beijing_time = datetime.now() + timedelta(hours=8)  # UTC时间+8小时=北京时间
    header = [
        f"# AGH规则合并 (多源去重)",
        f"# 生成时间（北京时间）: {beijing_time.strftime('%Y-%m-%d %H:%M:%S')}",
        f"# 规则源地址：",
        f"#   1. {source_stats_list[0]['name']} 规则：{source_stats_list[0]['url']}",
        f"#   2. {source_stats_list[1]['name']} 规则：{source_stats_list[1]['url']}",
        f"#   3. 本规则订阅地址：{SUBSCRIBE_URL}",
        f"# ==============================================================================",
        f"# 【各规则源单独统计】",
        f"#   1. {source_stats_list[0]['name']} | 总规则数：{source_stats_list[0]['total_rule']} 条 | 黑名单：{source_stats_list[0]['black']} 条 | 白名单：{source_stats_list[0]['white']} 条 | 其他规则：{source_stats_list[0]['other']} 条",
        f"#   2. {source_stats_list[1]['name']} | 总规则数：{source_stats_list[1]['total_rule']} 条 | 黑名单：{source_stats_list[1]['black']} 条 | 白名单：{source_stats_list[1]['white']} 条 | 其他规则：{source_stats_list[1]['other']} 条",
        f"# ==============================================================================",
        f"# 【规则源汇总统计】",
        f"# 原始总行数：{total_stats['raw_line']} 条 | 跳过无效行：{total_stats['skip']} 条",
        f"# 过滤有效数：{total_stats['total_rule']} 条 | 源内去重数：{total_stats['inner_dedup']} 条 | 源内合并后",
        f"# 汇总规则：黑{total_stats['total_black']}条 | 白{total_stats['total_white']}条 | 其他{total_stats['total_other']}条 | 总计{total_stats['total_black']+total_stats['total_white']+total_stats['total_other']}条",
        f"# ==============================================================================",
        f"# 【全局合并统计】",
        f"# 源内合并后总数：{source_merged_total}条 | 黑{total_stats['total_black']}条 | 白{total_stats['total_white']}条 | 其他{total_stats['total_other']}条",
        f"# 跨源重复去重数：{cross_dedup} 条 | 最终全局保留总数：{final_total} 条 | 黑名单{final_black}条 | 白名单{final_white}条 | 其他规则{final_other}条",
        f"# ==============================================================================",
        f""  # 空行分隔：让头部注释和实际规则内容区分更清晰
    ]


    # 步骤4：将头部注释和全局去重后的规则写入本地文件（UTF-8编码避免中文乱码）
    with open(AGH_OUTPUT_FILE, 'w', encoding='utf-8') as f:
        # 将注释列表和规则列表合并，用换行符连接成完整字符串后写入
        f.write('\n'.join(header + all_deduped_rules))


    # 步骤5：打印最终执行结果日志，GH Actions中可查看完整统计数据
    print("\n" + "="*80)
    print(f"✅ AGH规则合并去重完成！生成文件：{AGH_OUTPUT_FILE}")
    print(f"🕒 生成时间（北京时间）：{beijing_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"🌐 规则引用链接：https://raw.githubusercontent.com/ddcm1349/AGH/main/{AGH_OUTPUT_FILE}")
    print("="*80)
    print(f"📊 【规则源汇总】 | 原始总行数：{total_stats['raw_line']} 条 | 跳过无效行：{total_stats['skip']} 条")
    print(f"📊 【有效规则统计】| 总有效规则：{total_stats['total_rule']} 条 | 源内去重：{total_stats['inner_dedup']} 条")
    print(f"📊 【黑白规则汇总】| 总黑名单：{total_stats['total_black']} 条 | 总白名单：{total_stats['total_white']} 条 | 其他规则：{total_stats['total_other']} 条")
    print(f"📊 【全局最终统计】| 跨源去重数：{cross_dedup} 条 | 最终保留总数：{final_total} 条")
    print(f"📊 【最终黑白分布】| 黑名单：{final_black} 条 | 白名单：{final_white} 条 | 其他规则：{final_other} 条")
    print("="*80)


# —— 脚本入口 ——
if __name__ == "__main__":
    # 仅当直接运行本脚本时，才执行主逻辑（避免被作为模块导入时自动执行）
    main()
