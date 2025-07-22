#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
وحدة إنشاء التقارير
'''

import os
import time
import json
from datetime import datetime
from colorama import Fore, Style

class Reporter:
    """صنف إنشاء وإدارة التقارير الأمنية
    
    Attributes:
        target_info (dict): معلومات الهدف
        open_ports (list): قائمة المنافذ المفتوحة
        vulnerabilities (list): قائمة الثغرات المكتشفة
        output_dir (str): مجلد حفظ التقارير
        report_format (str): تنسيق التقرير ('txt', 'json', 'html')
        timestamp (str): الطابع الزمني للتقرير
        report_file (str): مسار ملف التقرير
    """
    def __init__(self, target_info, open_ports=None, vulnerabilities=None, output_dir="reports", report_format='txt'):
        """تهيئة منشئ التقارير
        Args:
            target_info (dict): معلومات الهدف
            open_ports (list, optional): قائمة المنافذ المفتوحة
            vulnerabilities (list, optional): قائمة الثغرات المكتشفة
            output_dir (str, optional): مجلد حفظ التقارير
            report_format (str, optional): تنسيق التقرير ('txt', 'json', 'html')
        """
        self.report_format = report_format.lower()
        self.target_info = target_info
        self.open_ports = open_ports or []
        self.vulnerabilities = vulnerabilities or []
        self.output_dir = output_dir
        self.timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        self.report_file = None
        
        # إنشاء مجلد التقارير إذا لم يكن موجودًا
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
    
    # إنشاء تقرير عن الثغرات المكتشفة
    def generate_vulnerability_report(self, vulnerabilities, exploited_vulnerabilities=None, report_format='txt'):
        """إنشاء تقرير بالثغرات المكتشفة
        Args:
            vulnerabilities (list): قائمة الثغرات المكتشفة
            exploited_vulnerabilities (list, optional): قائمة الثغرات المستغلة
            report_format (str, optional): تنسيق التقرير ('txt' أو 'json' أو 'html')
        Returns:
            str: مسار ملف التقرير المنشأ
        """
        print(f"{Fore.BLUE}[*] إنشاء تقرير عن الثغرات المكتشفة...{Style.RESET_ALL}")
        
        # استخدام اسم الملف المحدد أو إنشاء اسم ملف افتراضي
        if not self.report_file:
            target_name = self.target_info['domain'] if self.target_info['domain'] else self.target_info['ip']
            report_filename = f"{self.output_dir}/{target_name}_{self.timestamp}_report.txt"
            self.report_file = report_filename
        
        # تحديد تنسيق التقرير
        if report_format.lower() == 'json':
            return self.generate_json_report(vulnerabilities, exploited_vulnerabilities)
        elif report_format.lower() == 'html':
            return self.generate_html_report(vulnerabilities, exploited_vulnerabilities)
        
        # إنشاء محتوى التقرير النصي
        with open(self.report_file, 'w', encoding='utf-8-sig') as f:
            # كتابة رأس التقرير
            f.write("="*80 + "\n")
            f.write(f"تقرير GetHack للثغرات الأمنية\n")
            f.write(f"تاريخ الفحص: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"المطور: SayerLinux (saudiSayer@gmail.com)\n")
            f.write("="*80 + "\n\n")
            
            # كتابة معلومات الهدف
            f.write("معلومات الهدف:\n")
            f.write("-"*80 + "\n")
            f.write(f"الهدف: {self.target_info['target']}\n")
            f.write(f"اسم النطاق: {self.target_info['domain'] if self.target_info['domain'] else 'غير متاح'}\n")
            f.write(f"عنوان IP: {self.target_info['ip']}\n")
            
            if 'whois' in self.target_info and self.target_info['whois']:
                f.write("\nمعلومات WHOIS:\n")
                for key, value in self.target_info['whois'].items():
                    if isinstance(value, list):
                        value = ', '.join(value)
                    f.write(f"  {key}: {value}\n")
            
            if 'dns' in self.target_info and self.target_info['dns']:
                f.write("\nسجلات DNS:\n")
                for record_type, records in self.target_info['dns'].items():
                    f.write(f"  {record_type}:\n")
                    for record in records:
                        f.write(f"    {record}\n")
            
            if 'open_ports' in self.target_info and self.target_info['open_ports']:
                f.write("\nالمنافذ المفتوحة:\n")
                for port in self.target_info['open_ports']:
                    f.write(f"  {port['port']}/{port['protocol']}: {port['service']}")
                    if 'version' in port and port['version']:
                        f.write(f" ({port['version']})")
                    f.write("\n")
            
            # كتابة ملخص الثغرات
            f.write("\n")
            f.write("ملخص الثغرات المكتشفة:\n")
            f.write("-"*80 + "\n")
            f.write(f"إجمالي الثغرات المكتشفة: {len(vulnerabilities)}\n")
            
            # تصنيف الثغرات حسب مستوى الخطورة
            high_severity = [v for v in vulnerabilities if v['severity'] == 'عالي']
            medium_severity = [v for v in vulnerabilities if v['severity'] == 'متوسط']
            low_severity = [v for v in vulnerabilities if v['severity'] == 'منخفض']
            
            f.write(f"ثغرات عالية الخطورة: {len(high_severity)}\n")
            f.write(f"ثغرات متوسطة الخطورة: {len(medium_severity)}\n")
            f.write(f"ثغرات منخفضة الخطورة: {len(low_severity)}\n\n")
            
            # كتابة تفاصيل الثغرات
            f.write("تفاصيل الثغرات المكتشفة:\n")
            f.write("-"*80 + "\n")
            
            # كتابة الثغرات عالية الخطورة أولاً
            if high_severity:
                f.write("\nالثغرات عالية الخطورة:\n")
                for i, vuln in enumerate(high_severity, 1):
                    f.write(f"\n{i}. {vuln['name']}\n")
                    f.write(f"   المسار: {vuln['path']}\n")
                    f.write(f"   الوصف: {vuln['description']}\n")
                    f.write(f"   تاريخ الاكتشاف: {vuln['timestamp']}\n")
                    if 'details' in vuln and vuln['details']:
                        f.write(f"   تفاصيل إضافية: {vuln['details']}\n")
            
            # كتابة الثغرات متوسطة الخطورة
            if medium_severity:
                f.write("\nالثغرات متوسطة الخطورة:\n")
                for i, vuln in enumerate(medium_severity, 1):
                    f.write(f"\n{i}. {vuln['name']}\n")
                    f.write(f"   المسار: {vuln['path']}\n")
                    f.write(f"   الوصف: {vuln['description']}\n")
                    f.write(f"   تاريخ الاكتشاف: {vuln['timestamp']}\n")
                    if 'details' in vuln and vuln['details']:
                        f.write(f"   تفاصيل إضافية: {vuln['details']}\n")
            
            # كتابة الثغرات منخفضة الخطورة
            if low_severity:
                f.write("\nالثغرات منخفضة الخطورة:\n")
                for i, vuln in enumerate(low_severity, 1):
                    f.write(f"\n{i}. {vuln['name']}\n")
                    f.write(f"   المسار: {vuln['path']}\n")
                    f.write(f"   الوصف: {vuln['description']}\n")
                    f.write(f"   تاريخ الاكتشاف: {vuln['timestamp']}\n")
                    if 'details' in vuln and vuln['details']:
                        f.write(f"   تفاصيل إضافية: {vuln['details']}\n")
            
            # كتابة معلومات عن الثغرات المستغلة
            if exploited_vulnerabilities:
                f.write("\n\nالثغرات التي تم استغلالها:\n")
                f.write("-"*80 + "\n")
                f.write(f"إجمالي الثغرات المستغلة: {len(exploited_vulnerabilities)}\n\n")
                
                for i, exploit in enumerate(exploited_vulnerabilities, 1):
                    vuln = exploit['vulnerability']
                    result = exploit['result']
                    
                    f.write(f"{i}. {vuln['name']}\n")
                    f.write(f"   المسار: {vuln['path']}\n")
                    f.write(f"   الوصف: {vuln['description']}\n")
                    f.write(f"   نتيجة الاستغلال:\n")
                    
                    # كتابة نتيجة الاستغلال بناءً على نوع النتيجة
                    if isinstance(result, dict):
                        for key, value in result.items():
                            if isinstance(value, list):
                                f.write(f"     {key}:\n")
                                for item in value:
                                    f.write(f"       - {item}\n")
                            else:
                                f.write(f"     {key}: {value}\n")
                    elif isinstance(result, list):
                        for item in result:
                            if isinstance(item, dict):
                                for k, v in item.items():
                                    f.write(f"     {k}: {v}\n")
                            else:
                                f.write(f"     - {item}\n")
                    else:
                        f.write(f"     {result}\n")
                    
                    f.write("\n")
            
            # كتابة توصيات الأمان
            f.write("\n\nتوصيات الأمان:\n")
            f.write("-"*80 + "\n")
            
            # إنشاء توصيات مخصصة بناءً على الثغرات المكتشفة
            recommendations = self.generate_security_recommendations(vulnerabilities)
            for i, rec in enumerate(recommendations, 1):
                f.write(f"{i}. {rec}\n")
            
            # كتابة تذييل التقرير
            f.write("\n" + "="*80 + "\n")
            f.write("تم إنشاء هذا التقرير بواسطة أداة GetHack\n")
            f.write("المطور: SayerLinux (saudiSayer@gmail.com)\n")
            f.write("="*80 + "\n")
        
        print(f"{Fore.GREEN}[+] تم إنشاء التقرير بنجاح: {self.report_file}{Style.RESET_ALL}")
        return self.report_file
    
    # إنشاء تقرير بتنسيق JSON
    def generate_json_report(self, vulnerabilities, exploited_vulnerabilities=None):
        """إنشاء تقرير بتنسيق JSON
        
        Args:
            vulnerabilities (list): قائمة الثغرات المكتشفة
            exploited_vulnerabilities (list, optional): قائمة الثغرات المستغلة
            
        Returns:
            str: مسار ملف التقرير JSON
        """
        print(f"{Fore.BLUE}[*] إنشاء تقرير JSON...{Style.RESET_ALL}")
        
        # إنشاء اسم ملف التقرير
        target_name = self.target_info['domain'] if self.target_info['domain'] else self.target_info['ip']
        json_filename = f"{self.output_dir}/{target_name}_{self.timestamp}_report.json"
        
        # إنشاء بنية التقرير
        report = {
            'scan_info': {
                'tool': 'GetHack',
                'developer': 'SayerLinux',
                'email': 'saudiSayer@gmail.com',
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            },
            'target_info': self.target_info,
            'vulnerabilities': vulnerabilities,
            'exploited_vulnerabilities': exploited_vulnerabilities if exploited_vulnerabilities else [],
            'summary': {
                'total_vulnerabilities': len(vulnerabilities),
                'high_severity': len([v for v in vulnerabilities if v['severity'] == 'عالي']),
                'medium_severity': len([v for v in vulnerabilities if v['severity'] == 'متوسط']),
                'low_severity': len([v for v in vulnerabilities if v['severity'] == 'منخفض']),
                'exploited': len(exploited_vulnerabilities) if exploited_vulnerabilities else 0
            },
            'recommendations': self.generate_security_recommendations(vulnerabilities)
        }
        
        # كتابة التقرير إلى ملف JSON
        with open(json_filename, 'w', encoding='utf-8') as f:
            json.dump(report, f, ensure_ascii=False, indent=4)
        
        print(f"{Fore.GREEN}[+] تم إنشاء تقرير JSON بنجاح: {json_filename}{Style.RESET_ALL}")
        return json_filename
    
    # إنشاء توصيات أمان بناءً على الثغرات المكتشفة
    def generate_html_report(self, vulnerabilities, exploited_vulnerabilities=None):
        """إنشاء تقرير HTML تفاعلي
        Args:
            vulnerabilities (list): قائمة الثغرات المكتشفة
            exploited_vulnerabilities (list, optional): قائمة الثغرات المستغلة
        Returns:
            str: مسار ملف التقرير HTML
        """
        print(f"{Fore.BLUE}[*] إنشاء تقرير HTML...{Style.RESET_ALL}")
        
        target_name = self.target_info['domain'] if self.target_info['domain'] else self.target_info['ip']
        html_filename = f"{self.output_dir}/{target_name}_{self.timestamp}_report.html"
        
        # تصنيف الثغرات حسب مستوى الخطورة
        high_severity = [v for v in vulnerabilities if v['severity'] == 'عالي']
        medium_severity = [v for v in vulnerabilities if v['severity'] == 'متوسط']
        low_severity = [v for v in vulnerabilities if v['severity'] == 'منخفض']
        
        # إنشاء محتوى HTML
        html_content = f"""
        <!DOCTYPE html>
        <html dir="rtl" lang="ar">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>تقرير GetHack للثغرات الأمنية</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
                .container {{ max-width: 1200px; margin: 0 auto; background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
                h1, h2, h3 {{ color: #333; }}
                .severity-high {{ color: #dc3545; }}
                .severity-medium {{ color: #ffc107; }}
                .severity-low {{ color: #28a745; }}
                .vuln-details {{ margin: 10px 0; padding: 15px; border: 1px solid #ddd; border-radius: 4px; }}
                .summary-box {{ background-color: #f8f9fa; padding: 15px; border-radius: 4px; margin-bottom: 20px; }}
                .recommendations {{ background-color: #e9ecef; padding: 15px; border-radius: 4px; }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>تقرير GetHack للثغرات الأمنية</h1>
                <div class="summary-box">
                    <h2>معلومات الهدف</h2>
                    <p>الهدف: {self.target_info['target']}</p>
                    <p>اسم النطاق: {self.target_info['domain'] if self.target_info['domain'] else 'غير متاح'}</p>
                    <p>عنوان IP: {self.target_info['ip']}</p>
                    <p>تاريخ الفحص: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                
                <h2>ملخص الثغرات</h2>
                <div class="summary-box">
                    <p>إجمالي الثغرات المكتشفة: {len(vulnerabilities)}</p>
                    <p class="severity-high">ثغرات عالية الخطورة: {len(high_severity)}</p>
                    <p class="severity-medium">ثغرات متوسطة الخطورة: {len(medium_severity)}</p>
                    <p class="severity-low">ثغرات منخفضة الخطورة: {len(low_severity)}</p>
                </div>
        """
        
        # إضافة تفاصيل الثغرات
        if high_severity:
            html_content += '<h2 class="severity-high">الثغرات عالية الخطورة</h2>'
            for vuln in high_severity:
                html_content += self._generate_vuln_html(vuln)
        
        if medium_severity:
            html_content += '<h2 class="severity-medium">الثغرات متوسطة الخطورة</h2>'
            for vuln in medium_severity:
                html_content += self._generate_vuln_html(vuln)
        
        if low_severity:
            html_content += '<h2 class="severity-low">الثغرات منخفضة الخطورة</h2>'
            for vuln in low_severity:
                html_content += self._generate_vuln_html(vuln)
        
        # إضافة الثغرات المستغلة
        if exploited_vulnerabilities:
            html_content += f"""
                <h2>الثغرات المستغلة</h2>
                <div class="summary-box">
                    <p>إجمالي الثغرات المستغلة: {len(exploited_vulnerabilities)}</p>
                </div>
            """
            for exploit in exploited_vulnerabilities:
                html_content += self._generate_exploit_html(exploit)
        
        # إضافة التوصيات
        recommendations = self.generate_security_recommendations(vulnerabilities)
        html_content += f"""
            <h2>توصيات الأمان</h2>
            <div class="recommendations">
                <ul>
                    {''.join(f'<li>{rec}</li>' for rec in recommendations)}
                </ul>
            </div>
            
            <div style="margin-top: 30px; text-align: center; color: #666;">
                <p>تم إنشاء هذا التقرير بواسطة أداة GetHack</p>
                <p>المطور: SayerLinux (saudiSayer@gmail.com)</p>
            </div>
            </div>
        </body>
        </html>
        """
        
        # كتابة التقرير إلى ملف HTML
        with open(html_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"{Fore.GREEN}[+] تم إنشاء تقرير HTML بنجاح: {html_filename}{Style.RESET_ALL}")
        return html_filename
    
    def _generate_vuln_html(self, vuln):
        """إنشاء HTML لعرض تفاصيل ثغرة"""
        return f"""
            <div class="vuln-details">
                <h3>{vuln['name']}</h3>
                <p><strong>المسار:</strong> {vuln['path']}</p>
                <p><strong>الوصف:</strong> {vuln['description']}</p>
                <p><strong>تاريخ الاكتشاف:</strong> {vuln['timestamp']}</p>
                {f'<p><strong>تفاصيل إضافية:</strong> {vuln["details"]}</p>' if 'details' in vuln and vuln['details'] else ''}
            </div>
        """
    
    def _generate_exploit_html(self, exploit):
        """إنشاء HTML لعرض تفاصيل استغلال ثغرة"""
        vuln = exploit['vulnerability']
        result = exploit['result']
        
        result_html = ''
        if isinstance(result, dict):
            result_html = '<ul>'
            for key, value in result.items():
                if isinstance(value, list):
                    result_html += f'<li>{key}:<ul>'
                    result_html += ''.join(f'<li>{item}</li>' for item in value)
                    result_html += '</ul></li>'
                else:
                    result_html += f'<li>{key}: {value}</li>'
            result_html += '</ul>'
        elif isinstance(result, list):
            result_html = '<ul>'
            for item in result:
                if isinstance(item, dict):
                    result_html += '<li><ul>'
                    result_html += ''.join(f'<li>{k}: {v}</li>' for k, v in item.items())
                    result_html += '</ul></li>'
                else:
                    result_html += f'<li>{item}</li>'
            result_html += '</ul>'
        else:
            result_html = f'<p>{result}</p>'
        
        return f"""
            <div class="vuln-details">
                <h3>{vuln['name']}</h3>
                <p><strong>المسار:</strong> {vuln['path']}</p>
                <p><strong>الوصف:</strong> {vuln['description']}</p>
                <div>
                    <strong>نتيجة الاستغلال:</strong>
                    {result_html}
                </div>
            </div>
        """
    
    def generate_security_recommendations(self, vulnerabilities):
        """إنشاء توصيات أمان بناءً على الثغرات المكتشفة
        
        Args:
            vulnerabilities (list): قائمة الثغرات المكتشفة
            
        Returns:
            list: قائمة التوصيات الأمنية
        """
        recommendations = [
            "قم بتحديث جميع البرامج والأنظمة بانتظام للحصول على أحدث إصلاحات الأمان.",
            "قم بتنفيذ جدار حماية لتقييد الوصول إلى الخدمات والمنافذ غير الضرورية.",
            "استخدم كلمات مرور قوية وفريدة لجميع الحسابات وقم بتغييرها بانتظام.",
            "قم بتنفيذ سياسة الحد الأدنى من الامتيازات لجميع المستخدمين والخدمات."
        ]
        
        # إضافة توصيات مخصصة بناءً على الثغرات المكتشفة
        vuln_types = [v['name'] for v in vulnerabilities]
        
        if any('SQL' in v for v in vuln_types):
            recommendations.append("استخدم استعلامات SQL المعدة مسبقًا أو ORM لمنع هجمات حقن SQL.")
        
        if any('XSS' in v for v in vuln_types):
            recommendations.append("قم بترميز مخرجات المستخدم لمنع هجمات XSS.")
        
        if any('CSRF' in v for v in vuln_types):
            recommendations.append("استخدم رموز CSRF في جميع النماذج لمنع هجمات CSRF.")
        
        if any('تضمين الملفات' in v for v in vuln_types):
            recommendations.append("تحقق من صحة جميع مدخلات المستخدم وقيدها لمنع هجمات تضمين الملفات.")
        
        if any('تحميل الملفات' in v for v in vuln_types):
            recommendations.append("تحقق من نوع الملف وحجمه ومحتواه قبل قبول التحميلات لمنع هجمات تحميل الملفات الضارة.")
        
        if any('إعادة التوجيه المفتوح' in v for v in vuln_types):
            recommendations.append("تحقق من صحة جميع عناوين URL المستخدمة في عمليات إعادة التوجيه لمنع هجمات إعادة التوجيه المفتوح.")
        
        if any('رؤوس HTTP' in v for v in vuln_types):
            recommendations.append("قم بتنفيذ رؤوس HTTP الأمنية مثل Content-Security-Policy وX-XSS-Protection.")
        
        if any('FTP' in v for v in vuln_types):
            recommendations.append("قم بتعطيل الوصول المجهول إلى خدمة FTP وفرض المصادقة القوية.")
        
        if any('Telnet' in v for v in vuln_types):
            recommendations.append("استبدل Telnet بـ SSH للاتصالات الآمنة.")
        
        if any('RDP' in v for v in vuln_types):
            recommendations.append("قيد الوصول إلى خدمة RDP باستخدام جدار الحماية وفرض المصادقة القوية.")
        
        if any('MySQL' in v for v in vuln_types):
            recommendations.append("قم بتغيير كلمات مرور MySQL الافتراضية واستخدم كلمات مرور قوية.")
        
        return recommendations
    
    # عرض ملخص التقرير في وحدة التحكم
    def display_summary(self, vulnerabilities, exploited_vulnerabilities=None, show_recommendations=True):
        """عرض ملخص التقرير في وحدة التحكم
        Args:
            vulnerabilities (list): قائمة الثغرات المكتشفة
            exploited_vulnerabilities (list, optional): قائمة الثغرات المستغلة
            show_recommendations (bool, optional): عرض التوصيات الأمنية
        """
        print("\n" + "="*80)
        print(f"{Fore.CYAN}ملخص نتائج الفحص:{Style.RESET_ALL}")
        print("-"*80)
        
        # عرض معلومات الهدف
        print(f"{Fore.CYAN}معلومات الهدف:{Style.RESET_ALL}")
        print(f"الهدف: {self.target_info['target']}")
        print(f"اسم النطاق: {self.target_info['domain'] if self.target_info['domain'] else 'غير متاح'}")
        print(f"عنوان IP: {self.target_info['ip']}")
        
        # عرض ملخص الثغرات
        print(f"\n{Fore.CYAN}ملخص الثغرات:{Style.RESET_ALL}")
        print(f"إجمالي الثغرات المكتشفة: {len(vulnerabilities)}")
        
        # تصنيف الثغرات حسب مستوى الخطورة
        high_severity = [v for v in vulnerabilities if v['severity'] == 'عالي']
        medium_severity = [v for v in vulnerabilities if v['severity'] == 'متوسط']
        low_severity = [v for v in vulnerabilities if v['severity'] == 'منخفض']
        
        print(f"{Fore.RED}ثغرات عالية الخطورة: {len(high_severity)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}ثغرات متوسطة الخطورة: {len(medium_severity)}{Style.RESET_ALL}")
        print(f"{Fore.GREEN}ثغرات منخفضة الخطورة: {len(low_severity)}{Style.RESET_ALL}")
        
        # عرض معلومات عن الثغرات المستغلة
        if exploited_vulnerabilities:
            print(f"\n{Fore.CYAN}ملخص الاستغلال:{Style.RESET_ALL}")
            print(f"إجمالي الثغرات المستغلة: {len(exploited_vulnerabilities)}")
        
        # عرض مسار ملف التقرير
        if self.report_file:
            print(f"\n{Fore.CYAN}تم إنشاء التقرير في:{Style.RESET_ALL} {self.report_file}")
        
        print("="*80)
        
        # عرض التوصيات الأمنية
        if show_recommendations:
            print(f"\n{Fore.CYAN}التوصيات الأمنية:{Style.RESET_ALL}")
            recommendations = self.generate_security_recommendations(vulnerabilities)
            for i, rec in enumerate(recommendations, 1):
                print(f"{i}. {rec}")
        
        print("="*80)