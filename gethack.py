#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
GetHack - أداة قوية لاكتشاف واستغلال الثغرات الأمنية
تم تطويرها بواسطة: SayerLinux
البريد الإلكتروني: saudiSayer@gmail.com
'''

import os
import sys
import argparse
import requests
import socket
import whois
import dns.resolver
import nmap
import colorama
from colorama import Fore, Back, Style
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse
from modules.scanner import VulnerabilityScanner
from modules.exploiter import Exploiter
from modules.reporter import Reporter
from modules.banner import display_banner

# تهيئة الألوان
colorama.init(autoreset=True)

# التحقق من نظام التشغيل
def check_os():
    if sys.platform != 'linux':
        print(f"{Fore.YELLOW}[!] تحذير: هذه الأداة مصممة للعمل على نظام لينكس، قد لا تعمل بعض الميزات بشكل صحيح على {sys.platform}{Style.RESET_ALL}")
        # تعطيل الخروج مؤقتًا للاختبار
        # sys.exit(1)

# التحقق من الصلاحيات
def check_root():
    # تعديل للتوافق مع ويندوز
    if sys.platform == 'linux':
        try:
            if os.geteuid() != 0:
                print(f"{Fore.YELLOW}[!] تحذير: يفضل تشغيل الأداة بصلاحيات الجذر (root) للحصول على أفضل النتائج{Style.RESET_ALL}")
        except AttributeError:
            pass
    else:
        print(f"{Fore.YELLOW}[!] تحذير: يفضل تشغيل الأداة بصلاحيات المسؤول للحصول على أفضل النتائج{Style.RESET_ALL}")

# التحقق من وجود الحزم المطلوبة
def check_requirements():
    # تعطيل التحقق مؤقتًا للاختبار
    return []
    
    required_packages = ['requests', 'python-whois', 'dnspython', 'python-nmap', 'colorama']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package.replace('-', '_'))
        except ImportError:
            missing_packages.append(package)
    
    if missing_packages:
        print(f"{Fore.RED}[!] الحزم المفقودة: {', '.join(missing_packages)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[+] قم بتثبيت الحزم المطلوبة باستخدام: pip install {' '.join(missing_packages)}{Style.RESET_ALL}")
        sys.exit(1)

# تحليل المعلومات الأساسية للهدف
def gather_basic_info(target):
    print(f"{Fore.BLUE}[*] جمع المعلومات الأساسية عن الهدف: {target}{Style.RESET_ALL}")
    
    parsed_url = urlparse(target)
    if not parsed_url.scheme:
        target = "http://" + target
        parsed_url = urlparse(target)
    
    domain = parsed_url.netloc
    if not domain:
        print(f"{Fore.RED}[!] خطأ: تعذر تحليل الهدف. تأكد من إدخال عنوان URL صحيح.{Style.RESET_ALL}")
        sys.exit(1)
    
    # الحصول على عنوان IP
    try:
        ip = socket.gethostbyname(domain)
        print(f"{Fore.GREEN}[+] عنوان IP: {ip}{Style.RESET_ALL}")
    except socket.gaierror:
        print(f"{Fore.RED}[!] خطأ: تعذر الحصول على عنوان IP للنطاق {domain}{Style.RESET_ALL}")
        ip = None
    
    # الحصول على معلومات WHOIS
    try:
        whois_info = whois.whois(domain)
        print(f"{Fore.GREEN}[+] معلومات التسجيل:")
        print(f"    المسجل: {whois_info.registrar}")
        print(f"    تاريخ الإنشاء: {whois_info.creation_date}")
        print(f"    تاريخ الانتهاء: {whois_info.expiration_date}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] تعذر الحصول على معلومات WHOIS: {str(e)}{Style.RESET_ALL}")
    
    # الحصول على سجلات DNS
    try:
        print(f"{Fore.GREEN}[+] سجلات DNS:{Style.RESET_ALL}")
        for qtype in ['A', 'MX', 'NS', 'TXT']:
            try:
                answers = dns.resolver.resolve(domain, qtype)
                print(f"    سجلات {qtype}:")
                for rdata in answers:
                    print(f"      {rdata}")
            except Exception:
                print(f"    لا توجد سجلات {qtype}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] تعذر الحصول على سجلات DNS: {str(e)}{Style.RESET_ALL}")
    
    return {'target': target, 'domain': domain, 'ip': ip}

# فحص المنافذ المفتوحة
def scan_ports(ip, ports=None):
    if not ip:
        return []
    
    if not ports:
        ports = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080'
    
    print(f"{Fore.BLUE}[*] فحص المنافذ المفتوحة على {ip}...{Style.RESET_ALL}")
    
    try:
        scanner = nmap.PortScanner()
        scanner.scan(ip, ports, arguments='-T4 -sV')
        
        open_ports = []
        for host in scanner.all_hosts():
            for proto in scanner[host].all_protocols():
                lport = scanner[host][proto].keys()
                for port in lport:
                    if scanner[host][proto][port]['state'] == 'open':
                        service = scanner[host][proto][port]['name']
                        version = scanner[host][proto][port]['product'] + " " + scanner[host][proto][port]['version']
                        open_ports.append({'port': port, 'service': service, 'version': version})
                        print(f"{Fore.GREEN}[+] المنفذ {port}/tcp مفتوح - {service} {version}{Style.RESET_ALL}")
        
        return open_ports
    except Exception as e:
        print(f"{Fore.RED}[!] خطأ أثناء فحص المنافذ: {str(e)}{Style.RESET_ALL}")
        return []

# الدالة الرئيسية
def main():
    # عرض الشعار
    display_banner()
    
    # التحقق من نظام التشغيل
    check_os()
    
    # التحقق من الصلاحيات
    check_root()
    
    # التحقق من المتطلبات
    check_requirements()
    
    # إعداد محلل الوسيطات
    parser = argparse.ArgumentParser(description='GetHack - أداة قوية لاكتشاف واستغلال الثغرات الأمنية')
    parser.add_argument('-t', '--target', help='الهدف (URL أو عنوان IP)', required=True)
    parser.add_argument('-o', '--output', help='ملف لحفظ التقرير')
    parser.add_argument('-p', '--ports', help='المنافذ المراد فحصها (افتراضيًا: المنافذ الشائعة)')
    parser.add_argument('-d', '--deep-scan', action='store_true', help='إجراء فحص عميق للثغرات')
    parser.add_argument('-e', '--exploit', action='store_true', help='محاولة استغلال الثغرات المكتشفة')
    parser.add_argument('-v', '--verbose', action='store_true', help='عرض معلومات تفصيلية')
    
    args = parser.parse_args()
    
    # جمع المعلومات الأساسية
    target_info = gather_basic_info(args.target)
    
    # فحص المنافذ
    open_ports = scan_ports(target_info['ip'], args.ports)
    
    # إنشاء كائن الماسح
    scanner = VulnerabilityScanner(target_info, open_ports, args.deep_scan, args.verbose)
    
    # البدء في فحص الثغرات
    print(f"{Fore.BLUE}[*] بدء فحص الثغرات...{Style.RESET_ALL}")
    vulnerabilities = scanner.scan()
    
    # عرض الثغرات المكتشفة
    if vulnerabilities:
        print(f"{Fore.GREEN}[+] تم العثور على {len(vulnerabilities)} ثغرة:{Style.RESET_ALL}")
        for i, vuln in enumerate(vulnerabilities, 1):
            severity_color = Fore.RED if vuln['severity'] == 'عالية' else Fore.YELLOW if vuln['severity'] == 'متوسطة' else Fore.BLUE
            print(f"{severity_color}[{i}] {vuln['name']} - الخطورة: {vuln['severity']}{Style.RESET_ALL}")
            print(f"    الوصف: {vuln['description']}")
            print(f"    المسار: {vuln['path']}")
    else:
        print(f"{Fore.GREEN}[+] لم يتم العثور على ثغرات!{Style.RESET_ALL}")
    
    # استغلال الثغرات إذا تم تحديد الخيار
    if args.exploit and vulnerabilities:
        print(f"{Fore.BLUE}[*] محاولة استغلال الثغرات...{Style.RESET_ALL}")
        exploiter = Exploiter(target_info, vulnerabilities, args.verbose)
        exploited = exploiter.run()
        
        if exploited:
            print(f"{Fore.GREEN}[+] تم استغلال {len(exploited)} ثغرة بنجاح!{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] لم يتم استغلال أي ثغرة بنجاح.{Style.RESET_ALL}")
    
    # إنشاء تقرير إذا تم تحديد الخيار
    if args.output:
        reporter = Reporter(target_info, open_ports, vulnerabilities)
        # استخدام اسم الملف المحدد من المستخدم
        reporter.report_file = args.output
        reporter.generate_vulnerability_report(vulnerabilities)
        print(f"{Fore.GREEN}[+] تم حفظ التقرير في: {reporter.report_file}{Style.RESET_ALL}")
    
    print(f"{Fore.BLUE}[*] اكتمل الفحص!{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] تم إيقاف العملية بواسطة المستخدم{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[!] حدث خطأ غير متوقع: {str(e)}{Style.RESET_ALL}")
        sys.exit(1)