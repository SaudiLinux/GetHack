#!/usr/bin/env python3
# -*- coding: utf-8 -*-

'''
وحدة عرض شعار GetHack
'''

import random
from colorama import Fore, Style

# تعريف الشعار
LOGO = '''
  ▄████  ▄████▄  ▄▄▄█████▓ ██░ ██  ▄▄▄       ▄████▄   ██ ▄█▀
 ██▒ ▀█▒▒██▀ ▀█  ▓  ██▒ ▓▒▓██░ ██▒▒████▄    ▒██▀ ▀█   ██▄█▒ 
▒██░▄▄▄░▒▓█    ▄ ▒ ▓██░ ▒░▒██▀▀██░▒██  ▀█▄  ▒▓█    ▄ ▓███▄░ 
░▓█  ██▓▒▓▓▄ ▄██▒░ ▓██▓ ░ ░▓█ ░██ ░██▄▄▄▄██ ▒▓▓▄ ▄██▒▓██ █▄ 
░▒▓███▀▒▒ ▓███▀ ░  ▒██▒ ░ ░▓█▒░██▓ ▓█   ▓██▒▒ ▓███▀ ░▒██▒ █▄
 ░▒   ▒ ░ ░▒ ▒  ░  ▒ ░░    ▒ ░░▒░▒ ▒▒   ▓▒█░░ ░▒ ▒  ░▒ ▒▒ ▓▒
  ░   ░   ░  ▒       ░     ▒ ░▒░ ░  ▒   ▒▒ ░  ░  ▒   ░ ░▒ ▒░
░ ░   ░ ░          ░       ░  ░░ ░  ░   ▒   ░        ░ ░░ ░ 
      ░ ░ ░                ░  ░  ░      ░  ░░ ░      ░  ░   
        ░                                   ░               
'''

# معلومات الأداة
INFO = '''
  [ أداة قوية لاكتشاف واستغلال الثغرات الأمنية ]
  [ المطور: SayerLinux | البريد: saudiSayer@gmail.com ]
  [ الإصدار: 1.0.0 | تعمل على نظام لينكس فقط ]
'''

# ألوان عشوائية للشعار
def get_random_color():
    colors = [Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN]
    return random.choice(colors)

# عرض الشعار
def display_banner():
    logo_color = get_random_color()
    info_color = Fore.CYAN
    
    print(logo_color + LOGO + Style.RESET_ALL)
    print(info_color + INFO + Style.RESET_ALL)
    print("\n" + "=" * 60 + "\n")